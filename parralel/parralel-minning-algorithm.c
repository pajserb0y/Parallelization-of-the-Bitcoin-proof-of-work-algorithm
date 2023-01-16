#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <omp.h>
#include <time.h>

#define TARGET_BITS 16
#define NUM_THREADS 4

char target[SHA256_DIGEST_LENGTH] = {0};

void calculate_hash(char *block_header, int header_length, char hash[SHA256_DIGEST_LENGTH]) {
    // Step 1: SHA-256 hash
    unsigned char sha256_1[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, block_header, header_length);
    SHA256_Final(sha256_1, &sha256);	

    // Step 2: SHA-256 hash of the result of the first hash
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, sha256_1, SHA256_DIGEST_LENGTH);
    SHA256_Final(hash, &sha256);
}

void mine_block(char *block_header, int header_length) {
    char hash[SHA256_DIGEST_LENGTH];
    unsigned int nonce = 0;
    double start_time = omp_get_wtime();
    #pragma omp parallel for num_threads(NUM_THREADS) private(hash, nonce)
    for (nonce = 0; nonce < UINT32_MAX; nonce++) {
        // Append the nonce to the block header
        char *block_header_with_nonce = (char *)malloc(header_length + sizeof(unsigned int));
        memcpy(block_header_with_nonce, block_header, header_length);
        memcpy(block_header_with_nonce + header_length, &nonce, sizeof(unsigned int));

        // Calculate the hash of the block header + nonce
        calculate_hash(block_header_with_nonce, header_length + sizeof(unsigned int), hash);
        free(block_header_with_nonce);

        // Check if the hash is less than the target
        if(memcmp(hash, target, SHA256_DIGEST_LENGTH) < 0 ){
            #pragma omp critical
            {
                double time_elapsed = (omp_get_wtime() - start_time)* 1000.0;
                printf("Block mined by thread %d: %x\n", omp_get_thread_num(), hash);
                printf("Time taken: %f milliseconds\n", time_elapsed);
                exit(0);
            }
        }
    }
}

int main(void) {
    // Set the target for mining
	// Set the most significant TARGET_BITS / 8 bytes to 0x00
	// using big-endian format because SHA256_Final(hash, &sha256) function returns hash value in that format
	for (int i = 0; i < TARGET_BITS / 8; i++) {
		target[i] = (unsigned char)0x00;
	}

	// Set the remaining bytes to 0xff
	for (int i = TARGET_BITS / 8; i < SHA256_DIGEST_LENGTH; i++) {
		target[i] = (unsigned char)0xff;
	}

    // Mine the block
    char *block_header = "This is the block header.";
    int header_length = strlen(block_header);
    mine_block(block_header, header_length);

    return 0;
}

