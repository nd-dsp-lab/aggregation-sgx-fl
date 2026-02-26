#!/usr/bin/env bash
set -euo pipefail

mkdir -p data/results

# Edit these
N_CLIENTS=10000
N_ROUNDS=5
N_CHUNKS=1
VECTOR_DIM=1000000
FRACTION_FIT=0.3

# TERSE pipeline
gramine-sgx sgx/setup_trusted "$N_CLIENTS" "$N_ROUNDS" "$VECTOR_DIM"
./setup_clients              "$N_CLIENTS" "$N_ROUNDS" "$VECTOR_DIM"
./client                     "$N_CLIENTS" "$N_ROUNDS" "$VECTOR_DIM"
# ./server                     "$N_CLIENTS" "$N_ROUNDS" "$VECTOR_DIM"
# gramine-sgx sgx/trusted      "$N_ROUNDS"

# gramine-sgx sgx/setup_trusted "$N_CLIENTS" "$N_ROUNDS" "$N_CHUNKS" "$VECTOR_DIM" "$FRACTION_FIT"

# AES pipeline
# ./aes_client \
#   --n_clients "$N_CLIENTS" \
#   --n_rounds "$N_ROUNDS" \
#   --vector_dim "$VECTOR_DIM"

# gramine-sgx sgx/aes_trusted \
#   --n_clients "$N_CLIENTS" \
#   --n_rounds "$N_ROUNDS" \
#   --vector_dim "$VECTOR_DIM"