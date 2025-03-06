// gcc t81benchmark.c -o t81benchmark -lt81 -lgmp -O2
// ./t81benchmark
//
// Enabled by OpenAI

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <gmp.h>
#include "t81.h"

#define ITERATIONS 100000

// Benchmark function for addition
void benchmark_addition() {
    T81BigIntHandle a = t81bigint_from_string("123456789012345678901234567890");
    T81BigIntHandle b = t81bigint_from_string("987654321098765432109876543210");
    T81BigIntHandle sum;
    
    mpz_t gmp_a, gmp_b, gmp_sum;
    mpz_init_set_str(gmp_a, "123456789012345678901234567890", 10);
    mpz_init_set_str(gmp_b, "987654321098765432109876543210", 10);
    mpz_init(gmp_sum);
    
    clock_t start, end;
    double t81_time, gmp_time;
    
    // Benchmark T81
    start = clock();
    for (int i = 0; i < ITERATIONS; i++) {
        t81bigint_add(a, b, &sum);
        t81bigint_free(sum);
    }
    end = clock();
    t81_time = ((double)(end - start)) / CLOCKS_PER_SEC;
    
    // Benchmark GMP
    start = clock();
    for (int i = 0; i < ITERATIONS; i++) {
        mpz_add(gmp_sum, gmp_a, gmp_b);
    }
    end = clock();
    gmp_time = ((double)(end - start)) / CLOCKS_PER_SEC;
    
    printf("T81 Addition Time: %f seconds\n", t81_time);
    printf("GMP Addition Time: %f seconds\n", gmp_time);
    
    // Cleanup
    t81bigint_free(a);
    t81bigint_free(b);
    mpz_clears(gmp_a, gmp_b, gmp_sum, NULL);
}

// Benchmark function for multiplication
void benchmark_multiplication() {
    T81BigIntHandle a = t81bigint_from_string("123456789012345678901234567890");
    T81BigIntHandle b = t81bigint_from_string("987654321098765432109876543210");
    T81BigIntHandle product;
    
    mpz_t gmp_a, gmp_b, gmp_product;
    mpz_init_set_str(gmp_a, "123456789012345678901234567890", 10);
    mpz_init_set_str(gmp_b, "987654321098765432109876543210", 10);
    mpz_init(gmp_product);
    
    clock_t start, end;
    double t81_time, gmp_time;
    
    // Benchmark T81
    start = clock();
    for (int i = 0; i < ITERATIONS; i++) {
        t81bigint_multiply(a, b, &product);
        t81bigint_free(product);
    }
    end = clock();
    t81_time = ((double)(end - start)) / CLOCKS_PER_SEC;
    
    // Benchmark GMP
    start = clock();
    for (int i = 0; i < ITERATIONS; i++) {
        mpz_mul(gmp_product, gmp_a, gmp_b);
    }
    end = clock();
    gmp_time = ((double)(end - start)) / CLOCKS_PER_SEC;
    
    printf("T81 Multiplication Time: %f seconds\n", t81_time);
    printf("GMP Multiplication Time: %f seconds\n", gmp_time);
    
    // Cleanup
    t81bigint_free(a);
    t81bigint_free(b);
    mpz_clears(gmp_a, gmp_b, gmp_product, NULL);
}

int main() {
    printf("Running benchmarks...\n");
    benchmark_addition();
    benchmark_multiplication();
    return 0;
}
