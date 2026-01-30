# README

## Prerequisites
- OpenFHE libraries installed and on the default include/library paths.
- OpenSSL development headers.
- Gramine + SGX driver (only if running enclave benchmarks).

## Build
```
make all          # native binaries
make sgx          # adds SGX manifests/signed binaries
```

## End-to-end benchmark
```
./run_benchmark.sh           # all modes
./run_benchmark.sh TERSE-SGX # single mode
```
Results accumulate in `benchmark_results.txt`.

## Manual TERSE flow
1. `./setup <n_clients> <n_timestamps> [vector_dim]`
2. `./client <n_clients> <n_timestamps> [vector_dim]`
3. For each timestamp `i`: `./server i`
4. `./trusted <n_timestamps>`
5. Replace any of the above with `gramine-sgx ./…` to run inside SGX.

## Manual AES flow
1. `./aes_client <n_clients> <n_timestamps> <vector_dim>`
2. `./aes_trusted <n_timestamps>`
3. Use `gramine-sgx ./aes_trusted …` for the enclave variant.