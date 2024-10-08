// bruteforce.c
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
    fprintf(file, "%f,%li\n", cpu_time_used, key);
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
    uint64_t mylower, myupper;
    MPI_Status st;
    MPI_Request req;
    MPI_Comm comm = MPI_COMM_WORLD;

    MPI_Init(&argc, &argv);
    MPI_Comm_size(comm, &N);
    MPI_Comm_rank(comm, &id);
    printf("Process %d of %d\n", id, N);

    
    // Calc the range for each process
    uint64_t range_per_node = (upper + N - 1) / N; // Ajust the range to the number of nodes
    mylower = range_per_node * id; 
    myupper = (id == N - 1) ? upper : mylower + range_per_node; // Asegurarse de que el último proceso maneje el resto

    
    printf("The key to be searched is between %li and %li\n, process %d", mylower, myupper, id);

    uint64_t found = UINT64_MAX; // Found key
    int stop_signal = 0; // Signal to stop all processes

    
    for (uint64_t i = mylower; i < myupper; ++i) {
        // Verify if the stop signal is received
        MPI_Iprobe(MPI_ANY_SOURCE, 0, comm, &stop_signal, &st);
        if (stop_signal) {
            printf("Process %d: Stop signal received\n", id);
            break;
        }

        if (tryKey(i, buffer, len)) {
            found = i; // Store the found key
            printf("### Process %d: Found key %li\n", id, found);
            stop_signal = 1; // Send the stop signal to all processes
            // Send the stop signal to all processes
            for (int node = 0; node < N; node++) {
                MPI_Send(&stop_signal, 1, MPI_INT, node, 0, comm);
            }

            printf("Process %d: Stop signal sent\n", id);
            break; // Stop searching if the key is found
        }

    }

    // Enviar la llave encontrada al proceso root
    MPI_Send(&found, 1, MPI_UNSIGNED_LONG_LONG, 0, id, comm); // Utiliza 'id' como tag para diferenciar los mensajes

    if (id == 0) {
        uint64_t best_key = found;
        for (int node = 0; node < N; node++) {
            uint64_t received_key;
            MPI_Recv(&received_key, 1, MPI_UNSIGNED_LONG_LONG, node, node, comm, &st); // Usamos el 'tag' correspondiente
            if (received_key != UINT64_MAX) {
                printf("### Received key: %lu from process %d\n", received_key, node);
                best_key = received_key; // Actualiza la mejor llave encontrada
            }
        }

        if (best_key != UINT64_MAX) {
            printf("Found key: %lu\n", best_key);
            decrypt(best_key, buffer, len);
            printf("Decrypted text: %s\n", buffer);
            end = clock();
            cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
            printf("Time: %f\n", cpu_time_used);
            appendTimeResult(cpu_time_used, best_key);
        } else {
            printf("No key found\n");
        }
    }

    MPI_Finalize();
    return 0;
}
