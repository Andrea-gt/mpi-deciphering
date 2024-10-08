// bruteforce_secuencial.c
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <unistd.h>
#include <openssl/des.h>

// Function to append time result on file
void appendTimeResult(double cpu_time_used, long key) {
    FILE *file = fopen("time_result.csv", "a");
    if (!file) {
        perror("File opening failed");
        return;
    }

    fprintf(file, "%f,%li\n", cpu_time_used, key);
    fclose(file);
}



void decrypt(long key, char *ciph, int len) {
    DES_key_schedule schedule;
    DES_cblock des_key;
    
    // Convert long key to DES_cblock
    for (int i = 0; i < 8; ++i) {
        des_key[i] = (key >> (56 - (i * 8))) & 0xFF;
    }

    // Suppress deprecated warnings for OpenSSL DES functions
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wdeprecated-declarations"

    // Set parity
    DES_set_odd_parity(&des_key);

    // Set the key schedule
    DES_set_key_checked(&des_key, &schedule);

    // Decrypt the ciphertext
    DES_ecb_encrypt((DES_cblock *)ciph, (DES_cblock *)ciph, &schedule, DES_DECRYPT);
}

void encrypt(long key, char *ciph, int len) {
    DES_key_schedule schedule;
    DES_cblock des_key;
    
    // Convert long key to DES_cblock
    for (int i = 0; i < 8; ++i) {
        des_key[i] = (key >> (56 - (i * 8))) & 0xFF;
    }

    // Set parity
    DES_set_odd_parity(&des_key);

    // Set the key schedule
    DES_set_key_checked(&des_key, &schedule);

    // Encrypt the plaintext
    DES_ecb_encrypt((DES_cblock *)ciph, (DES_cblock *)ciph, &schedule, DES_ENCRYPT);
}

char search[] = "es una prueba de";
bool tryKey(long key, char *ciph, int len) {
    char temp[len + 1];
    memcpy(temp, ciph, len);
    temp[len] = 0;
    decrypt(key, temp, len);

    return strstr((char *)temp, search) != NULL;
}

int main(int argc, char *argv[]) {
    clock_t start, end;
    double cpu_time_used;
    start = clock();

    if (argc < 3) {
        printf("Usage: %s <key> <file>\n", argv[0]);
        return 1;
    }

    // Parse the key and file name from command line arguments
    long key = atol(argv[1]);
    char *filename = argv[2];

    // Open the file for reading
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("File opening failed");
        return EXIT_FAILURE;
    }

    // Read the contents of the file (assuming the file contains one sentence)
    char buffer[256];
    fgets(buffer, sizeof(buffer), file);
    fclose(file);

    // Calculate the length of the buffer
    int len = strlen(buffer);

    // Encrypt the sentence
    printf("Original text: %s\n", buffer);
    encrypt(key, buffer, len);
    printf("Encrypted text: ");
    for (int i = 0; i < len; ++i) {
        printf("%02x", (unsigned char)buffer[i]);
    }
    printf("\n");

    long upper = (1L << 56); // upper bound for DES keys (2^56)

    printf("Searching for the key...\n");

    long found = -1; // Initialize to -1 to indicate not found
    for (long i = 0; i < upper; ++i) {
        if (tryKey(i, buffer, len)) {
            found = i;
            printf("Found key: %li\n", found);
            break; // Stop searching if the key is found
        }

        // Debug message every large number of iterations
        if (i % 100000000000 == 0) {
            printf("Progress: %li\n", i);
        }
    }

    // Decrypt the ciphertext with the found key
    if (found != -1) {
        decrypt(found, buffer, len);
        printf("Decrypted text: %s\n", buffer);
    } else {
        printf("No key found\n");
    }

    end = clock();
    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    printf("Time: %f seconds\n", cpu_time_used);

    // Append time result to file
    appendTimeResult(cpu_time_used, key);

    return 0;
}
