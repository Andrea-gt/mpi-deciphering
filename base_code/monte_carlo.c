#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <mpi.h>
#include <stdbool.h>
#include <time.h>
#include <unistd.h>
#include <openssl/des.h>
#include <omp.h>

// Function to append time result on file
void appendTimeResult(double cpu_time_used, uint64_t key) {
    FILE *file = fopen("time_result_parallel.csv", "a");
    if (!file) {
        perror("File opening failed");
        return;
    }
    fprintf(file, "%f,%lu\n", cpu_time_used, key);
    fclose(file);
}

void decrypt(uint64_t key, char *ciph, int len) {
    DES_key_schedule schedule;
    DES_cblock des_key;

    // Convert uint64_t key to DES_cblock
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

void encrypt(uint64_t key, char *ciph, int len) {
    DES_key_schedule schedule;
    DES_cblock des_key;

    // Convert uint64_t key to DES_cblock
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
bool tryKey(uint64_t key, char *ciph, int len) {
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
    uint64_t key = atol(argv[1]);
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

    int N, id;
    uint64_t upper = (1L << 56); // upper bound DES keys 2^56
    MPI_Status st;
    MPI_Comm comm = MPI_COMM_WORLD;

    MPI_Init(&argc, &argv);
    MPI_Comm_size(comm, &N);
    MPI_Comm_rank(comm, &id);
    printf("Process %d of %d\n", id, N);

    uint64_t found = -1; // Initialize to -1 to indicate not found
    int stop_signal = 0; // Signal to stop all processes

    // Seed the random number generator for each process
    srand(time(NULL) + id);

    #pragma omp parallel
    {
        uint64_t local_found = -1;
        while (local_found == -1 && !stop_signal) {
            uint64_t random_key = ((uint64_t)rand() << 32) | rand(); // Generate a random 56-bit key

            if (tryKey(random_key, buffer, len)) {
                local_found = random_key;
                #pragma omp critical
                {  
                    stop_signal = 1; // Send the stop signal to all threads
                }

                // Send the stop signal to all processes
                MPI_Request req;
                for (int node = 0; node < N; node++) {
                    #pragma omp critical
                    MPI_Isend(&stop_signal, 1, MPI_INT, node, 0, comm, &req);
                }
            }

            // Check for stop signal from other processes
            int flag;
            #pragma omp critical
            MPI_Iprobe(MPI_ANY_SOURCE, 0, comm, &flag, &st);
            if (flag) {
                #pragma omp critical
                
                MPI_Recv(&stop_signal, 1, MPI_INT, MPI_ANY_SOURCE, 0, comm, &st);
            }
        }

        #pragma omp critical
        if (local_found != -1) {
            found = local_found; // Store the found key
        }
    }

    // Send the found key to the root process
    MPI_Send(&found, 1, MPI_UNSIGNED_LONG_LONG, 0, 0, comm);

    if (id == 0) {
        // Gather results from all processes
        uint64_t best_key = found;
        for (int node = 0; node < N; node++) {
            uint64_t received_key;
            MPI_Recv(&received_key, 1, MPI_UNSIGNED_LONG_LONG, node, 0, comm, MPI_STATUS_IGNORE);
            if (received_key != -1) {
                best_key = received_key; // Update the best key found
            }
        }

        // Decrypt the ciphertext with the found key
        if (best_key != -1) {
            printf("Found key: %lu\n", best_key);
            decrypt(best_key, buffer, len);
            printf("Decrypted text: %s\n", buffer);
            end = clock();
            cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
            printf("Time: %f\n", cpu_time_used);

            // Append time result to file
            appendTimeResult(cpu_time_used, best_key);
        } else {
            printf("No key found\n");
        }
    }

    MPI_Finalize();
    return 0;
}
