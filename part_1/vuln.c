#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>


void * chunks[256];
unsigned long sizes[256];
unsigned long chunk_idx;

int allocate_chunk(){
	char response[32];
	unsigned long size;
	if (chunk_idx >= 256){
		puts("You cannot allocate any more chunks!");
		return 1;
	}
	printf("Size?\n> ");
	fgets(response, sizeof(response), stdin);
	size = strtoul(response, NULL, 10);
	if (!size){
		puts("Size should be non-zero!");
		return 1;
	}
	chunks[chunk_idx] = malloc(size);
	sizes[chunk_idx++] = size;
	return 0;
}

int free_chunk(){
	char response[32];
	unsigned long idx = 0;
	printf("Index?\n> ");
	fgets(response, sizeof(response), stdin);
	idx = strtoul(response, NULL, 10);
	if (idx >= 256){
		puts("Invalid index!");
		return 1;
	}
	free(chunks[idx]);
	return 0;
}

int edit_chunk(){
	char response[32];
	unsigned long idx = 0;
	unsigned long offset = 0;
	printf("Index?\n> ");
	fgets(response, sizeof(response), stdin);
	idx = strtoul(response, NULL, 10);
	if (idx >= 256){
		puts("Invalid index!");
		return 1;
	}
	void * chunk = chunks[idx];
	printf("Offset?\n> ");
	fgets(response, sizeof(response), stdin);
	offset = strtoul(response, NULL, 10);
	if (offset >= sizes[idx]) {
		puts("Offset too large!");
		return 1;
	}
		
	read(0, chunks[idx]+offset, sizes[idx]-offset);
	return 0;
}

int main(){
	char response[32];
	unsigned long choice = 0;
	unsigned char leak = 0;
	
	setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
	
	while (1) {
		puts("+--------------------+");
		puts(" [1] Allocate Chunk");
		puts(" [2] Free Chunk");
		puts(" [3] Edit Chunk");
		puts(" [4] Get Tiny Leak");
		puts(" [5] Exit");
		printf("+--------------------+\n> ");
		fgets(response, sizeof(response), stdin);
		choice = strtoul(response, NULL, 10);
		
		switch (choice){
			case 1:
				allocate_chunk();
				break;
			case 2:
				free_chunk();
				break;
			case 3:
				edit_chunk();
				break;
			case 4:
				/*
				This option leaks 8 bits of information to the user.
				In a real exploit, you would just guess these 8 bits
				for a 1/256 chance of success.
				*/

				leak = ((size_t) &exit >> 12) & 0xf;
				printf("Least-significant ASLR-affected nibble of exit(): %hhx\n", leak);
				// heap has to be initialized to get this
				if (chunks[0]){
					leak = ((size_t) chunks[0] >> 12) & 0xf;
					printf("Least-significant ASLR-affected nibble of heap: %hhx\n", leak);
				}
				break;
			case 5:
				exit(0);
				break; // i mean hey you never know
			case 31518715:
				/*
				Heap overflows aren't an 'intended' vulnerability in this
				program, so this option lets you get overflows if you'd like.
				*/
				puts("DEBUG: Allowing all chunks to be overflowed.");
				for (int i = 0; i < 256; i++){
					// Fun fact: Setting this to LONG_MAX actually causes nothing to be read.
					// This is (seemingly) an exploitation defense in the Linux kernel:
					// https://elixir.bootlin.com/linux/v6.5-rc6/source/fs/read_write.c#L357
					sizes[i] = 0x999999; 
				}
				break;
			default:
				puts("Unknown option!");
		}
	}
}