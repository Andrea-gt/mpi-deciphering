// bruteforce.c
// nota: el key usado es bastante pequenio, cuando sea random speedup variara

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <mpi.h>
#include <unistd.h>
#include <openssl/des.h>

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

char search[] = " the ";
int tryKey(long key, char *ciph, int len) {
    char temp[len + 1];
    memcpy(temp, ciph, len);
    temp[len] = 0;
    decrypt(key, temp, len);
    return strstr((char *)temp, search) != NULL;
}

unsigned char cipher[] = {108, 245, 65, 63, 125, 200, 150, 66, 17, 170, 207, 170, 34, 31, 70, 215, 0};

int main(int argc, char *argv[]) { // char **argv
    int N, id;
    long upper = (1L << 56); // upper bound DES keys 2^56
    long mylower, myupper;
    MPI_Status st;
    MPI_Request req;
    int flag;
    int ciphlen = sizeof(cipher); // Updated to use sizeof for the cipher length
    MPI_Comm comm = MPI_COMM_WORLD;

    MPI_Init(NULL, NULL);
    MPI_Comm_size(comm, &N);
    MPI_Comm_rank(comm, &id);

    int range_per_node = upper / N;
    mylower = range_per_node * id;
    myupper = range_per_node * (id + 1) - 1;
    if (id == N - 1) {
        // compensate for remainder
        myupper = upper;
    }

    long found = 0;

    MPI_Irecv(&found, 1, MPI_LONG, MPI_ANY_SOURCE, MPI_ANY_TAG, comm, &req);

    for (int i = mylower; i < myupper && (found == 0); ++i) {
        if (tryKey(i, (char *)cipher, ciphlen)) {
            found = i;
            for (int node = 0; node < N; node++) {
                MPI_Send(&found, 1, MPI_LONG, node, 0, MPI_COMM_WORLD);
            }
            break;
        }
    }

    if (id == 0) {
        MPI_Wait(&req, &st);
        decrypt(found, (char *)cipher, ciphlen);
        printf("%li %s\n", found, cipher);
    }

    MPI_Finalize();
}