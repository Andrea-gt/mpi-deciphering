#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mpi.h>
#include <time.h>
#include <ctype.h>
#include <mpi.h>
#include <stdbool.h>
#include <unistd.h>
#include <openssl/des.h>
#include <omp.h>

#define POPULATION_SIZE 100
#define MAX_GENERATIONS 1000
#define MUTATION_RATE 0.2
#define TEXT_SIZE 1024
#define KEY_MIN 0x0000000000000001L  // Minimum possible numeric key
#define KEY_MAX 0xFFFFFFFFFFFFFFFFL  // Maximum possible numeric key (64-bit)

// Function to encrypt the text using a numeric key
void encrypt(unsigned long long key, char *ciph, int len) {
    DES_key_schedule schedule;
    DES_cblock des_key;

    // Convert unsigned long long key to DES_cblock
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

    // Encrypt the plaintext
    DES_ecb_encrypt((DES_cblock *)ciph, (DES_cblock *)ciph, &schedule, DES_ENCRYPT);
}

// Function to decrypt the text using a numeric key
void decrypt(unsigned long long key, char *ciph, int len) {
    DES_key_schedule schedule;
    DES_cblock des_key;

    // Convert unsigned long long key to DES_cblock
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

// Fitness function: simple letter frequency analysis
double fitness(const char* decrypted_text, const char* hint) {
    const double letter_freq[26] = {11.525, 2.215, 4.019, 5.010, 12.181, 0.692, 1.768, 0.703,
                                6.247, 0.493, 0.011, 4.967, 3.157, 6.712, 8.683, 2.510,
                                0.877, 6.871, 7.977, 4.632, 3.930, 1.138, 0.017, 0.215,
                                1.008, 0.467};

    double score = 0.0;
    int count[26] = {0};
    int total = 0;

    // Check for the presence of the hint in the decrypted text
    if (strstr(decrypted_text, hint) != NULL) {
        score += 1000.0;  // Large bonus for having the hint
    }

    // Letter frequency analysis
    for (int i = 0; decrypted_text[i] != '\0'; i++) {
        if (isalpha(decrypted_text[i])) {
            count[decrypted_text[i] - 'A']++;
            total++;
        }
    }

    for (int i = 0; i < 26; i++) {
        score += (count[i] / (double)total) * letter_freq[i];
    }

    return score;
}

// Randomly mutates a numeric key
unsigned long long mutate(unsigned long long key) {
    // Randomly mutate individual bits in the key
    for (int i = 0; i < sizeof(unsigned long long) * 8; i++) {
        if ((double)rand() / RAND_MAX < MUTATION_RATE) {
            key ^= (1L << i);  // Flip the ith bit
        }
    }
    return key;
}

// Crossover between two parent keys to create a child key
unsigned long long crossover(unsigned long long parent1, unsigned long long parent2) {
    unsigned long long child = 0;
    for (int i = 0; i < sizeof(unsigned long long) * 8; i++) {
        if (rand() % 2) {
            child |= (parent1 & (1L << i));
        } else {
            child |= (parent2 & (1L << i));
        }
    }
    return child;
}

// Generate a random key within the numeric range
unsigned long long random_key() {
    return (rand() % (KEY_MAX - KEY_MIN + 1)) + KEY_MIN;
}

// Main program
int main(int argc, char** argv) {

    clock_t start, end;
    double cpu_time_used;
    start = clock();

    if (argc < 3) {
        printf("Usage: %s <key> <file>\n", argv[0]);
        return 1;
    }

    // Parse the key and file name from command line arguments
    unsigned long long key = atol(argv[1]);
    char *filename = argv[2];

    // Open the file for reading
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("File opening failed");
        return EXIT_FAILURE;
    }

    // Read the contents of the file
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

    int rank, size;
    MPI_Init(&argc, &argv);
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);

    srand(time(NULL) + rank);

    const char* encrypted_text = argv[1];
    unsigned long long population[POPULATION_SIZE];
    unsigned long long new_population[POPULATION_SIZE];
    double fitness_scores[POPULATION_SIZE];
    unsigned long long best_key;
    double best_fitness = -1.0;

    // Generate initial population
    for (int i = 0; i < POPULATION_SIZE; i++) {
        population[i] = random_key();
    }

    // Evolve population
    for (int generation = 0; generation < MAX_GENERATIONS; generation++) {
        // Evaluate fitness in parallel
        for (int i = rank; i < POPULATION_SIZE; i += size) {
            decrypt(population[i], buffer, len);
            fitness_scores[i] = fitness(buffer, "es una prueba de");

            if (fitness_scores[i] > best_fitness) {
                best_fitness = fitness_scores[i];
                best_key = population[i];
            }
        }

        // Gather best results from all processes
        double global_best_fitness;
        unsigned long long global_best_key;
        MPI_Reduce(&best_fitness, &global_best_fitness, 1, MPI_DOUBLE, MPI_MAX, 0, MPI_COMM_WORLD);
        MPI_Reduce(&best_key, &global_best_key, 1, MPI_LONG, MPI_MAX, 0, MPI_COMM_WORLD);

        if (rank == 0 && global_best_fitness > best_fitness) {
            printf("Generation %d, Best Key: %lld, Fitness: %f\n", generation, global_best_key, global_best_fitness);
        }

        // Selection and reproduction (only rank 0 handles this)
        if (rank == 0) {
            for (int i = 0; i < POPULATION_SIZE; i++) {
                int parent1_idx = rand() % POPULATION_SIZE;
                int parent2_idx = rand() % POPULATION_SIZE;

                new_population[i] = crossover(population[parent1_idx], population[parent2_idx]);
                new_population[i] = mutate(new_population[i]);
            }

            // Copy new population
            memcpy(population, new_population, sizeof(new_population));
        }

        // Broadcast the new population to all processes
        MPI_Bcast(population, POPULATION_SIZE, MPI_LONG, 0, MPI_COMM_WORLD);
    }

    if (rank == 0) {
        end = clock();
        cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
        printf("Best key found: %lli with fitness %f (%.6f)\n", best_key, best_fitness, cpu_time_used);
        // Decrypt the message using the found key
        decrypt(best_key, buffer, len);
        printf("Decrypted text: %s\n", buffer);
    }

    MPI_Finalize();
    return 0;
}
