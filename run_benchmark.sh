#!/bin/bash

set -e
 
N_CLIENTS=1000
N_TIMESTAMPS=5
VECTOR_DIM=1000000

echo ""
echo "=== TERSE Native ==="
./setup $N_CLIENTS $N_TIMESTAMPS $VECTOR_DIM
./client $N_CLIENTS $N_TIMESTAMPS $VECTOR_DIM
./server $N_CLIENTS $N_TIMESTAMPS $VECTOR_DIM
./trusted $N_TIMESTAMPS

echo ""
echo "=== TERSE SGX ==="
gramine-sgx ./trusted $N_TIMESTAMPS

echo ""
echo "=== AES Native ==="
rm -rf data
./aes_client $N_CLIENTS $N_TIMESTAMPS $VECTOR_DIM
./aes_trusted $N_TIMESTAMPS

echo ""
echo "=== AES SGX ==="
gramine-sgx ./aes_trusted $N_TIMESTAMPS

echo ""
echo "Done"
