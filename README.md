# DES Encryption Project

Welcome to the DES Encryption Project! This repository contains several implementations of the Data Encryption Standard (DES) using various approaches to encrypt and decrypt text. We explore the capabilities of DES through brute force, parallel processing, and advanced techniques, aiming to find the most efficient method for cracking the encryption.

## Table of Contents

- [Project Overview](#project-overview)
- [Getting Started](#getting-started)
- [Implementation Approaches](#implementation-approaches)
- [Testing and Analysis](#testing-and-analysis)

## Project Overview

In this project, we focus on encrypting text loaded from a `.txt` file using an arbitrary private key. The goal is to showcase the encryption and decryption process and analyze the efficiency of different approaches. 

We specifically target the string **“This is a project test 2”** for encryption, with a keyword for search being **“it is proof of.”**

## Getting Started

To get started with the project, ensure you have the necessary dependencies installed, including OpenMP and OpenMPI. 

### Prerequisites

- C++ Compiler (g++, clang++, etc.)
- OpenMP
- OpenMPI

### Installation

Clone the repository:

```bash
git clone https://github.com/Andrea-gt/mpi-deciphering.git
cd mpi-deciphering.git
```

## Implementation Approaches

This project consists of four different implementations of the DES algorithm:

1. **Brute Force Approach**:
   - A straightforward implementation that tries every possible key until it finds the right one.
  
2. **OpenMPI Approach**:
   - Utilizes the Message Passing Interface (MPI) to distribute the key search across multiple processes.

3. **Monte Carlo Approach with OpenMP and OpenMPI**:
   - Combines random key generation with parallel processing to increase efficiency.
   
4. **Genetic Algorithm Approach with OpenMP and OpenMPI**:
   - Employs genetic algorithms to evolve potential keys, optimizing the search for the correct key.

### Example Usage

To encrypt the text with a simple key (e.g., `42`), run the program as follows:

```bash
mpirun -np 4 ./your_program 42 cipher.txt
```

Replace `your_program` with the name of the compiled approach and `cipher.txt` with the name of your text file.

## Testing and Analysis

For the tests, we will analyze the encryption and decryption performance using four processes:

1. **Encrypting/Decrypting**: 
   - Text: "This is a project test 2"
   - Keyword to search: "it is proof of."
   
2. **Key Complexity**:
   - We will evaluate performance for keys categorized as “easy”, “medium easy”, and “difficult”.

### Flowcharts and Pseudocode

To visualize the proposed approaches, flowcharts and pseudocode will be provided in the report to describe the algorithms clearly.

## Results

The results section will include detailed comparisons of speedup and parallel times based on different key complexities, highlighting the effectiveness of each approach against the naive brute force method.