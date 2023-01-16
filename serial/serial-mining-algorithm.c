#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <time.h>

#define TARGET_BITS 16 // determines the difficulty of mining the block

//unsigned int target;
char target[SHA256_DIGEST_LENGTH] = {0};

void calculate_hash(char *block_header, int header_length, char hash[SHA256_DIGEST_LENGTH]) {
    // Step 1: SHA-256 hash
    unsigned char sha256_1[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, block_header, header_length);
    SHA256_Final(sha256_1, &sha256);

    // Step 2: SHA-256 hash of the result of the first hash, because we use double SHA-256 hash
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, sha256_1, SHA256_DIGEST_LENGTH);
    SHA256_Final(hash, &sha256);
    // hash is 32 bytes(elements) long, set by SHA256_DIGEST_LENGTH, each element of this array represent a byte of the hash. eg. hash[0] = 0x7f
} 

void mine_block(char *block_header, int header_length) {
    char hash[SHA256_DIGEST_LENGTH];
    unsigned int nonce = 0;
    while (1) {
        // Append the nonce to the block header
        char *block_header_with_nonce = (char *)malloc(header_length + sizeof(unsigned int));
        memcpy(block_header_with_nonce, block_header, header_length);
        memcpy(block_header_with_nonce + header_length, &nonce, sizeof(unsigned int));

        // Calculate the hash of the block header + nonce
        calculate_hash(block_header_with_nonce, header_length + sizeof(unsigned int), hash);
        free(block_header_with_nonce);

        // Check if the hash is less than the target    
        if(memcmp(hash, target, SHA256_DIGEST_LENGTH) < 0 ){ // Compare hash and target, If the return value is less than zero, it means that the first byte that does not match in both memory blocks has a lower value in hash than in target
        	printf("Block mined: %x\n", hash);
        	break;
    	}
        // Increment the nonce and try again
        nonce++;
    }
}

int main() {
    	// Set the target for mining, target value is a 256-bit number, represented by 32 byte-sized array of characters, that is used as a threshold for mining a block in the Bitcoin network
	// Set the most significant TARGET_BITS / 8 bytes to 0x00 
	for (int i = 0; i < TARGET_BITS / 8; i++) {
		target[i] = (unsigned char)0x00;
	}

	// Set the remaining bytes to 0xff
	for (int i = TARGET_BITS / 8; i < SHA256_DIGEST_LENGTH; i++) {
		target[i] = (unsigned char)0xff;
	}

     // Start timer
    clock_t start = clock();

    // Mine the block
    char *block_header = "This is the block header.";
    int header_length = strlen(block_header);
    mine_block(block_header, header_length);

    // End timer
    clock_t end = clock();

    // Calculate and print the elapsed time in milliseconds
    double elapsed_time = (end - start) * 1000.0 / CLOCKS_PER_SEC;
    printf("Time taken: %f milliseconds", elapsed_time);

    return 0;
}
