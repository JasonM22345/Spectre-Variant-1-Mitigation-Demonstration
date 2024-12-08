# Spectre-Variant-1-Mitigation-Demonstration
Spectre Variant 1 Mitigation Demonstration


This repository contains a demonstration and mitigation of the Spectre Variant 1 vulnerability, which exploits speculative execution in modern CPUs to infer sensitive data via side-channel attacks. The code is based on the [Spectre-Attack](https://github.com/Markus-MS/Spectre-Attack.git) project and extends it by implementing robust mitigations rooted in computer architecture principles.

## Overview

Speculative execution, a key performance optimization in modern processors, can lead to security vulnerabilities when branch mispredictions cause out-of-bounds memory accesses. These accesses leave measurable traces in the CPU cache, creating a covert channel for attackers. This repository illustrates both the vulnerability and its mitigation, focusing on techniques such as:

- **Bounds Checking**: Validating array indices to prevent unauthorized memory access.
- **Instruction Fencing**: Using CPU-specific instructions (e.g., `_mm_lfence`) to serialize execution and prevent speculative paths.
- **Cache Flushing**: Clearing sensitive data from the CPU cache to mitigate side-channel attacks.
- **Branch Predictor Reset**: Flushing branch predictors to reduce speculative mispredictions.

## Files

- `main.c`: The main implementation file containing the vulnerable code, mitigations, and demonstration logic.
- `Makefile`: A build script to compile the code easily.
- `README.md`: This documentation file.

## Build Instructions

To compile the code, ensure you have GCC installed. Then run the following command:

```bash
make
```
