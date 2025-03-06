// gcc benchmark2.c -o benchmark2 -lt81 -lgmp -lmpfr -O2
// ./benchmark2
//
// OpenAI Inspired

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <gmp.h>
#include <mpfr.h>
#include "t81.h"

#define ITERATIONS 100000
#define BAR_SCALE 50  // Scale factor for ASCII bar graph

// Function to print an ASCII bar graph
void print_bar_graph(const char* label, double time, double max_time) {
    int bar_length = (int)((time / max_time) * BAR_SCALE);
    printf("%-30s | ", label);
    for (int i = 0; i < bar_length; i++) {
        printf("#");
    }
    printf(" (%.6f sec)\n", time);
}

// Benchmark function for addition
void benchmark_addition(double* t81_time, double* gmp_time) {
    T81BigIntHandle a = t81bigint_from_string("123456789012345678901234567890");
    T81BigIntHandle b = t81bigint_from_string("987654321098765432109876543210");
    T81BigIntHandle sum;
    
    mpz_t gmp_a, gmp_b, gmp_sum;
    mpz_init_set_str(gmp_a, "123456789012345678901234567890", 10);
    mpz_init_set_str(gmp_b, "987654321098765432109876543210", 10);
    mpz_init(gmp_sum);
    
    clock_t start, end;
    
    start = clock();
    for (int i = 0; i < ITERATIONS; i++) {
        t81bigint_add(a, b, &sum);
        t81bigint_free(sum);
    }
    end = clock();
    *t81_time = ((double)(end - start)) / CLOCKS_PER_SEC;
    
    start = clock();
    for (int i = 0; i < ITERATIONS; i++) {
        mpz_add(gmp_sum, gmp_a, gmp_b);
    }
    end = clock();
    *gmp_time = ((double)(end - start)) / CLOCKS_PER_SEC;
    
    // Cleanup
    t81bigint_free(a);
    t81bigint_free(b);
    mpz_clears(gmp_a, gmp_b, gmp_sum, NULL);
}

// Benchmark function for multiplication
void benchmark_multiplication(double* t81_time, double* gmp_time) {
    T81BigIntHandle a = t81bigint_from_string("123456789012345678901234567890");
    T81BigIntHandle b = t81bigint_from_string("987654321098765432109876543210");
    T81BigIntHandle product;
    
    mpz_t gmp_a, gmp_b, gmp_product;
    mpz_init_set_str(gmp_a, "123456789012345678901234567890", 10);
    mpz_init_set_str(gmp_b, "987654321098765432109876543210", 10);
    mpz_init(gmp_product);
    
    clock_t start, end;
    
    start = clock();
    for (int i = 0; i < ITERATIONS; i++) {
        t81bigint_multiply(a, b, &product);
        t81bigint_free(product);
    }
    end = clock();
    *t81_time = ((double)(end - start)) / CLOCKS_PER_SEC;
    
    start = clock();
    for (int i = 0; i < ITERATIONS; i++) {
        mpz_mul(gmp_product, gmp_a, gmp_b);
    }
    end = clock();
    *gmp_time = ((double)(end - start)) / CLOCKS_PER_SEC;
    
    // Cleanup
    t81bigint_free(a);
    t81bigint_free(b);
    mpz_clears(gmp_a, gmp_b, gmp_product, NULL);
}

int main(int argc, char* argv[]) {
    printf("T81 Benchmark Tool - Command Line Mode\n");
    printf("Usage: %s [iterations]\n", argv[0]);
    if (argc > 1) {
        ITERATIONS = atoi(argv[1]);
        if (ITERATIONS <= 0) {
            fprintf(stderr, "Invalid iteration count. Using default %d.\n", ITERATIONS);
            ITERATIONS = 100000;
        }
    }
    
    double t81_add, gmp_add, t81_mul, gmp_mul;
    benchmark_addition(&t81_add, &gmp_add);
    benchmark_multiplication(&t81_mul, &gmp_mul);
    
    double max_time = t81_add;
    if (gmp_add > max_time) max_time = gmp_add;
    if (t81_mul > max_time) max_time = t81_mul;
    if (gmp_mul > max_time) max_time = gmp_mul;
    
    printf("\nPerformance Results (ASCII Bar Graph)\n");
    printf("--------------------------------------------------------\n");
    print_bar_graph("T81 Addition", t81_add, max_time);
    print_bar_graph("GMP Addition", gmp_add, max_time);
    print_bar_graph("T81 Multiplication", t81_mul, max_time);
    print_bar_graph("GMP Multiplication", gmp_mul, max_time);
    printf("--------------------------------------------------------\n");
    
    return 0;
}
