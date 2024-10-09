/**
 * @file bruteforce_sequential.c
 * 
 * @brief       This program demonstrates a brute-force attack to find the key
 *              used for DES encryption. It encrypts and then tries to decrypt
 *              a given ciphertext by attempting every possible key combination
 *              up to the maximum 56-bit DES keyspace.
 *              
 *              The program prints the progress of the brute-force search and
 *              logs the time taken to perform the operation in a CSV file.
 *
 * @author      Valdez D., Flores A., Ramirez A. 
 * @date        October 8, 2024
 *
*  @usage:
 * Compile the program with gcc -o bruteforce_sequential bruteforce_sequential.c -lssl -lcrypto
 * Run the program with the command:     
 *      ./bruteforce_sequential <key> <file>
 *
 * where <key> is the initial encryption key and <file> is the 
 * file containing the text to encrypt and then attack.
 *
 **/


#include <stdio.h>      // For input and output functions
#include <stdlib.h>     // For memory allocation and conversion functions
#include <string.h>     // For string manipulation functions
#include <stdbool.h>    // For using boolean data types
#include <time.h>       // For measuring time
#include <unistd.h>     // For POSIX operating system API
#include <openssl/des.h> // For DES encryption and decryption functions

/**
 * @brief Appends the CPU time used and the found key to a CSV file.
 * 
 * @param cpu_time_used The time taken to perform the decryption in seconds.
 * @param key The key that was found (or attempted).
 */
void appendTimeResult(double cpu_time_used, long key) {
    FILE *file = fopen("data/time_result.csv", "a");
    if (!file) {
        perror("File opening failed");
        return;
    }

    fprintf(file, "%f,%li\n", cpu_time_used, key);
    fclose(file);
}

/**
 * @brief Decrypts the given ciphertext using the specified DES key.
 * 
 * @param key The DES key used for decryption.
 * @param ciph Pointer to the ciphertext to be decrypted.
 * @param len Length of the ciphertext.
 */
void decrypt(long key, char *ciph, int len) {
    DES_key_schedule schedule;
    DES_cblock des_key;
    
    // Convert long key to DES_cblock (56 bits represented in 8 bytes)
    for (int i = 0; i < 8; ++i) {
        des_key[i] = (key >> (56 - (i * 8))) & 0xFF;
    }

    // Suppress deprecated warnings for OpenSSL DES functions
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wdeprecated-declarations"

    // Set parity for the DES key (required by DES)
    DES_set_odd_parity(&des_key);

    // Initialize the DES key schedule
    int result = DES_set_key_checked(&des_key, &schedule);

    // Decrypt the ciphertext (DES ECB mode)
    DES_ecb_encrypt((DES_cblock *)ciph, (DES_cblock *)ciph, &schedule, DES_DECRYPT);
}

/**
 * @brief Encrypts the given plaintext using the specified DES key.
 * 
 * @param key The DES key used for encryption.
 * @param ciph Pointer to the plaintext to be encrypted.
 * @param len Length of the plaintext.
 */
void encrypt(long key, char *ciph, int len) {
    DES_key_schedule schedule;
    DES_cblock des_key;
    
    // Convert long key to DES_cblock (56 bits represented in 8 bytes)
    for (int i = 0; i < 8; ++i) {
        des_key[i] = (key >> (56 - (i * 8))) & 0xFF;
    }

    // Set parity for the DES key (required by DES)
    DES_set_odd_parity(&des_key);

    // Initialize the DES key schedule
    DES_set_key_checked(&des_key, &schedule);

    // Encrypt the plaintext (DES ECB mode)
    DES_ecb_encrypt((DES_cblock *)ciph, (DES_cblock *)ciph, &schedule, DES_ENCRYPT);
}


/**
 * @brief Tries a given key to decrypt the ciphertext and checks for the presence of a specific substring.
 * 
 * @param key The DES key to try.
 * @param ciph Pointer to the ciphertext.
 * @param len Length of the ciphertext.
 * @return true If the substring is found in the decrypted text.
 * @return false If the substring is not found.
 */

char search[] = "es una prueba de";
bool tryKey(long key, char *ciph, int len) {
    char temp[len + 1]; // Create a temporary buffer
    memcpy(temp, ciph, len); // Copy the ciphertext
    temp[len] = '\0'; // Ensure null-termination

    decrypt(key, temp, len); // Decrypt the ciphertext

    // Debugging: Print the decrypted string
    //printf("Decrypted: %s\n", temp);
    
    // Check if the search string is found
    return strstr(temp, search) != NULL;
}

/**
 * @brief Main function to perform the DES brute-force attack.
 * 
 * @param argc Number of command-line arguments.
 * @param argv Array of command-line arguments. Expects two arguments:
 *             1. Key (as a long integer).
 *             2. Filename containing the encrypted message.
 * 
 * @return int Exit status of the program. Returns 0 on success, 1 on error.
 */
int main(int argc, char *argv[]) {
    clock_t start, end;
    double cpu_time_used;
    start = clock();

    // Check for correct usage
    if (argc < 3) {
        printf("Usage: %s <key> <file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    // Parse the key and file name from command line arguments
    char *endptr;
    long key = strtol(argv[1], &endptr, 10); 

    // Check for conversion errors
    if (endptr == argv[1]) {
        fprintf(stderr, "Error: No digits were found in input '%s'.\n", argv[1]);
        return EXIT_FAILURE;
    }

    char *filename = argv[2];

    // Open the file for reading the plaintext
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

    // Encrypt the plaintext
    printf("\nOriginal text: %s\n", buffer);
    encrypt(key, buffer, len);

    printf("\nEncrypted text: ");
    for (int i = 0; i < len; ++i) {
        printf("%02x", (unsigned char)buffer[i]);
    }

    // Neatly print the filename, key, and search string
    printf("\nFilename: %s\n", filename);
    printf("Key: %ldL\n", key);
    printf("Search string: '%s'\n", search);
    printf("\n");

    long upper = (1L << 56); // upper bound for DES keys (2^56)

    printf("Searching for the key...\n");

    long found = -1; // Initialize to -1 to indicate not found
    for (long i = 0; i < upper; ++i) {
        if (tryKey(i, buffer, len)) {
            found = i;
            printf("\nFound key: %li\n", found);
            break; // Stop searching if the key is found
        }

        // Debug message every large number of iterations
        if (i % 10000000000 == 0) {
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

    // Calculate the time taken for the brute-force search
    end = clock();
    cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("\nTime: %f seconds\n", cpu_time_used);

    // Append time result to file
    appendTimeResult(cpu_time_used, key);

    return 0;
}