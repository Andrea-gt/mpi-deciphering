/**
 * @file monte_carlo.cpp
 * 
 * @brief This program implements a brute-force attack on DES encryption using 
 *        multiple parallel techniques including OpenMP and MPI. It searches 
 *        for a specified key in a given range and decrypts the ciphertext 
 *        if the key is found. The program also measures and logs the time 
 *        taken for the key search process.
 * 
 * @authors Valdez D., Flores A., Ramirez A.
 * @date October 8, 2024
 * 
 * @usage 
 * Compile the program with:
 *    mpic++ -o monte_carlo monte_carlo.cpp -lssl -lcrypto -fopenmp -lmpi
 * 
 * Run the program with the command:
 *     mpirun -np <number_of_processes> ./monte_carlo <key> <file>
 * 
 * where <key> is the initial encryption key and <file> is the 
 * file containing the text to encrypt and then attack.
 * 
 * This program supports multiple threads and processes for improved performance 
 * during the brute-force search. It uses the DES encryption algorithm and applies 
 * PKCS#7 padding to the plaintext before encryption and decryption. 
 * The found key and the time taken for the search are logged to a CSV file 
 * for further analysis.
 * 
 * @note Make sure to have OpenSSL and MPI installed on your system to compile 
 *       and run the program.
 */

#include <iostream>     // For input and output streams
#include <fstream>      // For file handling
#include <sstream>      // For string streams
#include <string>       // For string manipulation
#include <cstring>      // For string manipulation functions
#include <chrono>       // For measuring time
#include <memory>       // For smart pointers
#include <openssl/des.h> // For DES encryption and decryption functions
#include <cstdint>
#include <iomanip>
#include <vector>       // For holding multiple ciphertexts
#include <algorithm>    // For min function
#include <mpi.h>        // For MPI functions
#include <omp.h>        // For OpenMP functions

/**
 * @brief Adds PKCS#7 padding to the plaintext.
 * 
 * @param input The plaintext to pad.
 * @return std::string The padded plaintext.
 */
std::string addPadding(const std::string &input) {
    int block_size = 8;
    int pad_len = block_size - (input.length() % block_size); // Calculate the padding length
    std::string padded = input;
    padded.append(pad_len, static_cast<char>(pad_len)); // Append 'pad_len' bytes, each of value 'pad_len'
    return padded;
}

/**
 * @brief Removes PKCS#7 padding from the decrypted plaintext.
 * 
 * @param input The decrypted text to unpad.
 * @return std::string The unpadded plaintext.
 */
std::string removePadding(const std::string &input) {
    int pad_len = static_cast<unsigned char>(input[input.length() - 1]); // Get the value of the last byte (padding length)
    return input.substr(0, input.length() - pad_len); // Remove padding
}

/**
 * @brief Appends the CPU time used and the found key to a CSV file.
 * 
 * @param cpu_time_used The time taken to perform the decryption in seconds.
 * @param key The key that was found (or attempted).
 */
void appendTimeResult(double cpu_time_used, uint64_t key) {
    std::ofstream file("data/time_result.csv", std::ios::app);
    if (!file) {
        std::cerr << "File opening failed" << std::endl;
        return;
    }

    file << cpu_time_used << "," << key << std::endl;
}

/**
 * @brief Decrypts the given ciphertext using the specified DES key.
 * 
 * @param key The DES key used for decryption.
 * @param ciph Pointer to the ciphertext to be decrypted.
 * @param len Length of the ciphertext.
 */
void decrypt(uint64_t key, char *ciph, int len) {
    DES_key_schedule schedule;
    DES_cblock des_key;

    // Suppress deprecated warnings for OpenSSL DES functions
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wdeprecated-declarations"

    // Convert long key to DES_cblock (56 bits represented in 8 bytes)
    for (int i = 0; i < 8; ++i) {
        des_key[i] = (key >> (56 - (i * 8))) & 0xFF;
    }

    // Set parity for the DES key (required by DES)
    DES_set_odd_parity(&des_key);

    // Initialize the DES key schedule
    int result = DES_set_key_checked(&des_key, &schedule);

    // Decrypt the ciphertext (DES ECB mode)
    for (int i = 0; i < len; i += 8) {
        DES_ecb_encrypt((DES_cblock *)(ciph + i), (DES_cblock *)(ciph + i), &schedule, DES_DECRYPT);
    }

    #pragma GCC diagnostic pop
}

/**
 * @brief Encrypts the given plaintext using the specified DES key.
 * 
 * @param key The DES key used for encryption.
 * @param ciph Pointer to the plaintext to be encrypted.
 * @param len Length of the plaintext.
 */
void encrypt(uint64_t key, char *ciph, int len) {
    DES_key_schedule schedule;
    DES_cblock des_key;

    // Suppress deprecated warnings for OpenSSL DES functions
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wdeprecated-declarations"

    // Convert long key to DES_cblock (56 bits represented in 8 bytes)
    for (int i = 0; i < 8; ++i) {
        des_key[i] = (key >> (56 - (i * 8))) & 0xFF;
    }

    // Set parity for the DES key (required by DES)
    DES_set_odd_parity(&des_key);

    // Initialize the DES key schedule
    int result = DES_set_key_checked(&des_key, &schedule);

    // Encrypt the plaintext (DES ECB mode)
    for (int i = 0; i < len; i += 8) {
        DES_ecb_encrypt((DES_cblock *)(ciph + i), (DES_cblock *)(ciph + i), &schedule, DES_ENCRYPT);
    }

    #pragma GCC diagnostic pop
}

/**
 * @brief Tries a given key to decrypt the ciphertext and checks for the presence of a specific substring.
 * 
 * @param key The DES key to try.
 * @param ciph Pointer to the ciphertext.
 * @param len Length of the ciphertext.
 * @param search_str The substring to search for in the decrypted text.
 * @return true If the substring is found in the decrypted text.
 * @return false If the substring is not found.
 */
bool tryKey(uint64_t key, char *ciph, int len, const std::string& search_str) {
    std::unique_ptr<char[]> temp(new char[len + 1]); // Allocate a buffer using smart pointer
    if (!temp) {
        std::cerr << "Memory allocation failed" << std::endl;
        return false; // Handle memory allocation failure
    }

    memcpy(temp.get(), ciph, len); // Copy the ciphertext
    temp[len] = '\0'; // Ensure null-termination

    decrypt(key, temp.get(), len); // Decrypt the ciphertext

    // Check if the search string is found
    bool found = strstr(temp.get(), search_str.c_str()) != nullptr;

    return found;
}

void searchOnOrder(uint64_t start, uint64_t end, uint64_t key, char *ciph, int len, const std::string &search_str, uint64_t &found_key, bool &key_found, int world_rank, int world_size, std::string &padded_buffer) {
    for (uint64_t k = start; k < end; ++k) {
        // Verifica si la llave ya ha sido encontrada
        #pragma omp flush(key_found) // Actualiza el valor de key_found en todos los hilos
        if (key_found) {
            break; // Si se encontró la llave, salir del bucle
        }

        // Verificar si se recibe la llave desde otro proceso
        int flag;
        #pragma omp critical
        {
            MPI_Iprobe(MPI_ANY_SOURCE, 0, MPI_COMM_WORLD, &flag, MPI_STATUS_IGNORE);
        }
        if (flag) {
            uint64_t received_key;
            #pragma omp critical
            {
                MPI_Recv(&received_key, 1, MPI_UNSIGNED_LONG_LONG, MPI_ANY_SOURCE, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
            }
            if (received_key != 0) {
                //std::cout << "Key found: " << received_key << "L" << std::endl;
                found_key = received_key; // Update the best key found
                key_found = true;
                #pragma omp flush(key_found) // Asegurar que todos los hilos vean el cambio
                return;
            }
        }

        if (tryKey(k, &padded_buffer[0], len, "es una prueba de")) {
            found_key = k;
            key_found = true;
            //std::cout << "Key found: " << k << "L" << std::endl;
            #pragma omp flush(key_found) // Asegurar que todos los hilos vean el cambio
            // Enviar la llave encontrada a todos los procesos
            for (int node = 0; node < world_size; node++) {
                if (node != world_rank) {
                    #pragma omp critical
                    {
                        MPI_Send(&found_key, 1, MPI_UNSIGNED_LONG_LONG, node, 0, MPI_COMM_WORLD);
                    }
                }
            }
            return;
        }
    }
}


void searchReversed( uint64_t start, uint64_t end, uint64_t key, char *ciph, int len, const std::string& search_str, uint64_t &found_key, bool &key_found, int world_rank, int world_size, std::string &padded_buffer) {
    for (uint64_t k = end - 1; k >= start && !key_found; --k) {
        // Verify if not recieving the key from another process
        int flag;
        #pragma omp critical
        {
            MPI_Iprobe(MPI_ANY_SOURCE, 0, MPI_COMM_WORLD, &flag, MPI_STATUS_IGNORE);
        }
        if (flag) {
            uint64_t received_key;
            #pragma omp critical
            {
                MPI_Recv(&received_key, 1, MPI_UNSIGNED_LONG_LONG, MPI_ANY_SOURCE, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
            }
            if (received_key != 0) {
                //std::cout << "Key found: " << received_key << "L" << std::endl;
                found_key = received_key; // Update the best key found
                key_found = true;
                return;
            }
        }

        if (tryKey(k, &padded_buffer[0], len, "es una prueba de")) {
            found_key = k;
            key_found = true;
            //std::cout << "Key found: " << k << "L" << std::endl;
            // Send the found key to all processes
            for (int node = 0; node < world_size; node++) {
                if (node != world_rank) {
                    #pragma omp critical
                    {
                        MPI_Send(&found_key, 1, MPI_UNSIGNED_LONG_LONG, node, 0, MPI_COMM_WORLD);
                    }
                }
            }

            return;
        }

    }
}

void searchByMonteCarlo( uint64_t start, uint64_t end, uint64_t key, char *ciph, int len, const std::string& search_str, uint64_t &found_key, bool &key_found, int world_rank, int world_size, std::string &padded_buffer) {
    for (uint64_t k = start; k < end && !key_found; ++k) {
        // Verify if not recieving the key from another process
        int flag;
        #pragma omp critical
        {
            MPI_Iprobe(MPI_ANY_SOURCE, 0, MPI_COMM_WORLD, &flag, MPI_STATUS_IGNORE);
        }

        if (flag) {
            uint64_t received_key;
            #pragma omp critical
            {
                MPI_Recv(&received_key, 1, MPI_UNSIGNED_LONG_LONG, MPI_ANY_SOURCE, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
            }
            if (received_key != 0) {
                //std::cout << "Key found: " << received_key << "L" << std::endl;
                found_key = received_key; // Update the best key found
                key_found = true;
                return;
            }
        }
        u_int64_t random_key = ((uint64_t)rand() << 32) | rand(); // Generate a random 56-bit key 


        if (tryKey(random_key, &padded_buffer[0], len, "es una prueba de")) {
            found_key = random_key;
            key_found = true;
            //std::cout << "Key found: " << random_key << "L" << std::endl;
            // Send the found key to all processes
            for (int node = 0; node < world_size; node++) {
                if (node != world_rank) {
                    #pragma omp critical
                    {
                        MPI_Send(&found_key, 1, MPI_UNSIGNED_LONG_LONG, node, 0, MPI_COMM_WORLD);
                    }
                }
            }

            return;
        }
    }
}

/**
 * @brief Main function to perform the DES brute-force attack using MPI.
 * 
 * @param argc Number of command-line arguments.
 * @param argv Array of command-line arguments. Expects two arguments:
 *             1. Key (as a long integer).
 *             2. Filename containing the encrypted message.
 * 
 * @return int Exit status of the program. Returns 0 on success, 1 on error.
 */
int main(int argc, char *argv[]) {
    // Initialize MPI environment
    MPI_Init(&argc, &argv);

    int world_size, world_rank;
    MPI_Comm_size(MPI_COMM_WORLD, &world_size); // Get the number of processes
    MPI_Comm_rank(MPI_COMM_WORLD, &world_rank); // Get the rank of the process
    std::cout << "Process " << world_rank << " of " << world_size << std::endl;

    auto start = std::chrono::high_resolution_clock::now(); // Start time measurement

    // Check for correct usage
    if (argc < 3) {
        if (world_rank == 0) {
            std::cout << "Usage: " << argv[0] << " <key> <file>" << std::endl;
        }
        MPI_Finalize();
        return EXIT_FAILURE;
    }

    // Parse the key and file name from command line arguments
    char *endptr;
    uint64_t key = strtoull(argv[1], &endptr, 10); 

    // Check for conversion errors
    if (endptr == argv[1]) {
        if (world_rank == 0) {
            std::cerr << "Error: No digits were found in input '" << argv[1] << "'." << std::endl;
        }
        MPI_Finalize();
        return EXIT_FAILURE;
    }

    std::string filename = argv[2];

    // Read the contents of the file (assuming the file contains one sentence)
    std::string buffer;
    if (world_rank == 0) {
        // Open the file for reading the plaintext
        std::ifstream file(filename);
        if (!file) {
            std::cerr << "File opening failed" << std::endl;
            MPI_Abort(MPI_COMM_WORLD, EXIT_FAILURE);
            return EXIT_FAILURE;
        }
        std::getline(file, buffer);
        file.close();
    }

    // Broadcast the buffer to all processes
    int buffer_length = buffer.size();
    MPI_Bcast(&buffer_length, 1, MPI_INT, 0, MPI_COMM_WORLD);

    buffer.resize(buffer_length);
    MPI_Bcast(&buffer[0], buffer_length, MPI_CHAR, 0, MPI_COMM_WORLD);

    // Calculate the length of the buffer
    std::string padded_buffer = addPadding(buffer);
    int len = padded_buffer.length();

    // Encrypt the plaintext
    if (world_rank == 0) {
        std::cout << "\nOriginal text: " << buffer << std::endl;
    }

    // Encrypt the padded plaintext
    encrypt(key, &padded_buffer[0], len);

    if (world_rank == 0) {
        std::cout << "\nEncrypted text: ";
        for (int i = 0; i < len; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (static_cast<unsigned int>(padded_buffer[i]) & 0xFF) << std::dec;
        }
        std::cout << "\nKey: " << key << "L" << std::endl;
        std::cout << "Search string: 'es una prueba de'" << std::endl;
    }

    // Initialize variables for the brute-force attack
    uint64_t max_key = (1ULL << 56); // Limiting to 24 bits for demonstration (adjust as needed)
    uint64_t keys_per_process = max_key / world_size;
    uint64_t key_start = keys_per_process * world_rank;
    uint64_t key_end = (world_rank == world_size - 1) ? max_key : keys_per_process * (world_rank + 1);

    std::cout << "Process " << world_rank << " searching keys " << key_start << " to " << key_end << std::endl;

    bool key_found = false;
    uint64_t found_key = 0;
    int num_threads = omp_get_max_threads();
    std::cout << "Number of threads: " << num_threads << std::endl;

    // Brute-force key search
    omp_set_num_threads(4);
    #pragma omp parallel
    {
        #pragma omp single
        {
            #pragma omp task
            {
                //std::cout << "Searching on order" << std::endl;
                searchOnOrder(key_start, key_end, key, &padded_buffer[0], len, "es una prueba de", found_key, key_found, world_rank, world_size, padded_buffer);
            }

            #pragma omp task
            {
                //std::cout << "Searching reversed" << std::endl;
                searchReversed(key_start, key_end, key, &padded_buffer[0], len, "es una prueba de", found_key, key_found, world_rank, world_size, padded_buffer);
            }

            #pragma omp task
            {
                //std::cout << "Searching by Monte Carlo" << std::endl;
                searchByMonteCarlo(key_start, key_end, key, &padded_buffer[0], len, "es una prueba de", found_key, key_found, world_rank, world_size, padded_buffer);
            }

            #pragma omp task
            {
                //std::cout << "Searching by Monte Carlo" << std::endl;
                searchByMonteCarlo(key_start, key_end, key, &padded_buffer[0], len, "es una prueba de", found_key, key_found, world_rank, world_size, padded_buffer);
            }

        }
    }

    // Gather the found key from all processes
    uint64_t global_found_key = 0;
    MPI_Allreduce(&found_key, &global_found_key, 1, MPI_UNSIGNED_LONG_LONG, MPI_MAX, MPI_COMM_WORLD);

    // Only the root process will output the result
    if (world_rank == 0) {
        if (global_found_key != 0) {
            if (world_rank == 0) {
                std::cout << "\nKey found: " << global_found_key << "L" << std::endl;
            }
            // Decrypt and display the message
            decrypt(global_found_key, &padded_buffer[0], len);
            std::string decrypted_message = removePadding(std::string(&padded_buffer[0], len));
            std::cout << "\nDecrypted message: " << decrypted_message << std::endl;
        } else {
            std::cout << "No key found in the tested range." << std::endl;
        }

        // End time measurement
        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> elapsed_seconds = end - start;

        // Log time result and key to CSV
        appendTimeResult(elapsed_seconds.count(), global_found_key);

        std::cout << "Time taken: " << elapsed_seconds.count() << " seconds\n";
    }

    // Finalize MPI environment
    MPI_Finalize();

    return EXIT_SUCCESS;
}
