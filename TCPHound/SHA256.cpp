#include "stdafx.h"     // Precompiled headers

#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/err.h>

void sha256_hash_string(unsigned char hash[SHA256_DIGEST_LENGTH], char outputBuffer[65])
{
	int i = 0;
	for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
	{
		sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
	}
	outputBuffer[64] = 0;
}

int HashFileSHA256(char *path, char *outputBuffer)
{
	FILE *file = fopen(path, "rb");
	if (!file) return -534;

	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	const int bufSize = 32768;
	unsigned char *buffer = new unsigned char[bufSize];
	int bytesRead = 0;
	if (!buffer) return ENOMEM;
	while ((bytesRead = fread(buffer, 1, bufSize, file)))
	{
		SHA256_Update(&sha256, buffer, bytesRead);
	}
	SHA256_Final(hash, &sha256);

	sha256_hash_string(hash, outputBuffer);
	fclose(file);
	free(buffer);
	return 0;
}