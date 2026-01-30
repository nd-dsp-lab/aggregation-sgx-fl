#!/bin/bash

set -e

VECTOR_DIM=${VECTOR_DIM:-100}
CLIENT_COUNTS=(100 1000)
N_TIMESTAMPS=20
PROGRESS_INTERVAL=10

RESULTS_FILE="benchmark_results.txt"

if [ $# -eq 1 ]; then
    SINGLE_MODE=$1
else
    SINGLE_MODE=""
fi

VALID_MODES=("TERSE-Native" "TERSE-SGX" "AES-Native" "AES-SGX" "all")

if [ -n "$SINGLE_MODE" ] && [[ ! " ${VALID_MODES[@]} " =~ " ${SINGLE_MODE} " ]]; then
    echo "Invalid mode: $SINGLE_MODE"
    echo "Valid modes: ${VALID_MODES[@]}"
    exit 1
fi

if [ ! -f "$RESULTS_FILE" ]; then
    echo "Type               Number of Clients  Vector Dim   Number of Vectors  KeyGen per Client (ms)   KeyGen Total (ms)    Precomp per client (ms)      Precomp Trusted (ms)     Encrypt per vector (ms)  Addition (ms)    Decrypt (ms)   Total Aggregation (ms)" > "$RESULTS_FILE"
fi

extract_ms() {
    awk '{print $(NF-1)}'
}

run_terse_native() {
    for n_clients in "${CLIENT_COUNTS[@]}"; do
        echo "Testing TERSE with $n_clients clients (Native)"

        rm -rf data
        mkdir -p data

        if ! setup_output=$(./setup $n_clients $N_TIMESTAMPS $VECTOR_DIM 2>&1); then
            echo "ERROR: Setup failed"
            echo "$setup_output"
            exit 1
        fi

        keygen_per_client=$(echo "$setup_output" | grep "Client key generation time (per user, averaged)" | extract_ms)
        keygen_total=$(echo "$setup_output" | grep "Key generation time (total)" | extract_ms)
        precomp_per_client=$(echo "$setup_output" | grep "Client precomputation time (per client):" | extract_ms)
        precomp_trusted=$(echo "$setup_output" | grep "Server precomputation time (total):" | extract_ms)
        encrypt_per_vector="0"

        if ! client_output=$(./client $n_clients $N_TIMESTAMPS $VECTOR_DIM 2>&1); then
            echo "ERROR: Client encryption failed"
            echo "$client_output"
            exit 1
        fi

        encrypt_per_vector=$(echo "$client_output" | grep "Encryption time (per vector, averaged):" | extract_ms)

        echo "Running server aggregation..."
        total_agg_time=0
        for ((i=0; i<$N_TIMESTAMPS; i++)); do
            if [ $((i % PROGRESS_INTERVAL)) -eq 0 ]; then
                echo "  Progress: $i/$N_TIMESTAMPS"
            fi

            if ! server_output=$(./server $i 2>&1); then
                echo "ERROR: Server failed at timestamp $i"
                exit 1
            fi

            agg_time=$(echo "$server_output" | grep "Aggregation time:" | extract_ms)
            total_agg_time=$(echo "$total_agg_time + $agg_time" | bc -l)

            if [ ! -f "data/encrypted_aggregate_$i.bin" ]; then
                echo "ERROR: Aggregated file not created for timestamp $i"
                exit 1
            fi
        done
        avg_agg_time=$(echo "scale=6; $total_agg_time / $N_TIMESTAMPS" | bc -l)

        echo "Running trusted decryption..."
        if ! trusted_output=$(./trusted $N_TIMESTAMPS 2>&1); then
            echo "ERROR: Trusted decryption failed"
            echo "$trusted_output"
            exit 1
        fi

        total_decrypt_time=$(echo "$trusted_output" | grep "Trusted decryption:" | extract_ms)
        avg_decrypt_time=$(echo "scale=8; $total_decrypt_time / $N_TIMESTAMPS" | bc -l)
        total_aggregation=$(echo "$avg_agg_time + $avg_decrypt_time" | bc -l)

        printf "TERSE-Native       %-18s %-12s %-18s %-24s %-22s %-32s %-24s %-24s %-16s %-12s %s\n" \
            "$n_clients" "$VECTOR_DIM" "$N_TIMESTAMPS" "$keygen_per_client" "$keygen_total" \
            "$precomp_per_client" "$precomp_trusted" "$encrypt_per_vector" "$avg_agg_time" \
            "$avg_decrypt_time" "$total_aggregation" >> "$RESULTS_FILE"

        echo "✓ Native TERSE complete"
        echo ""
    done
}

run_terse_sgx() {
    for n_clients in "${CLIENT_COUNTS[@]}"; do
        echo "Testing TERSE with $n_clients clients (SGX)"

        rm -rf data
        mkdir -p data

        if ! setup_output=$(gramine-sgx ./setup $n_clients $N_TIMESTAMPS $VECTOR_DIM 2>&1); then
            echo "ERROR: Setup (SGX) failed"
            echo "$setup_output"
            exit 1
        fi

        keygen_per_client=$(echo "$setup_output" | grep "Client key generation time (per user, averaged)" | extract_ms)
        keygen_total=$(echo "$setup_output" | grep "Key generation time (total)" | extract_ms)
        precomp_per_client=$(echo "$setup_output" | grep "Client precomputation time (per client):" | extract_ms)
        precomp_trusted=$(echo "$setup_output" | grep "Server precomputation time (total):" | extract_ms)

        if ! client_output=$(./client $n_clients $N_TIMESTAMPS $VECTOR_DIM 2>&1); then
            echo "ERROR: Client encryption failed"
            exit 1
        fi
        encrypt_per_vector=$(echo "$client_output" | grep "Encryption time (per vector, averaged):" | extract_ms)

        echo "Running server aggregation..."
        total_agg_time=0
        for ((i=0; i<$N_TIMESTAMPS; i++)); do
            if [ $((i % PROGRESS_INTERVAL)) -eq 0 ]; then
                echo "  Progress: $i/$N_TIMESTAMPS"
            fi

            if ! server_output=$(./server $i 2>&1); then
                echo "ERROR: Server failed at timestamp $i"
                exit 1
            fi
            agg_time=$(echo "$server_output" | grep "Aggregation time:" | extract_ms)
            total_agg_time=$(echo "$total_agg_time + $agg_time" | bc -l)
        done
        avg_agg_time=$(echo "scale=6; $total_agg_time / $N_TIMESTAMPS" | bc -l)

        echo "Running trusted decryption (SGX)..."
        if ! trusted_output=$(gramine-sgx ./trusted $N_TIMESTAMPS 2>&1); then
            echo "ERROR: Trusted decryption (SGX) failed"
            exit 1
        fi

        total_decrypt_time=$(echo "$trusted_output" | grep "Trusted decryption:" | extract_ms)
        avg_decrypt_time=$(echo "scale=8; $total_decrypt_time / $N_TIMESTAMPS" | bc -l)
        total_aggregation=$(echo "$avg_agg_time + $avg_decrypt_time" | bc -l)

        printf "TERSE-SGX          %-18s %-12s %-18s %-24s %-22s %-32s %-24s %-24s %-16s %-12s %s\n" \
            "$n_clients" "$VECTOR_DIM" "$N_TIMESTAMPS" "$keygen_per_client" "$keygen_total" \
            "$precomp_per_client" "$precomp_trusted" "$encrypt_per_vector" "$avg_agg_time" \
            "$avg_decrypt_time" "$total_aggregation" >> "$RESULTS_FILE"

        echo "✓ SGX TERSE complete"
        echo ""
    done
}

run_aes_native() {
    for n_clients in "${CLIENT_COUNTS[@]}"; do
        echo "Testing AES with $n_clients clients (Native)"

        rm -rf data
        mkdir -p data

        if ! aes_client_output=$(./aes_client $n_clients $N_TIMESTAMPS $VECTOR_DIM 2>&1); then
            echo "ERROR: AES client failed"
            exit 1
        fi

        aes_keygen_per_client=$(echo "$aes_client_output" | grep "AES key generation time (per user, averaged):" | extract_ms)
        aes_encrypt_per_vector=$(echo "$aes_client_output" | grep "AES encryption time (per vector, averaged):" | extract_ms)

        if ! aes_trusted_output=$(./aes_trusted $N_TIMESTAMPS 2>&1); then
            echo "ERROR: AES trusted failed"
            exit 1
        fi

        aes_decrypt_time=$(echo "$aes_trusted_output" | grep "Trusted decrypt+aggregate (avg):" | extract_ms)

        printf "AES-Native         %-18s %-12s %-18s %-24s %-22s %-32s %-24s %-24s %-16s %-12s %s\n" \
            "$n_clients" "$VECTOR_DIM" "$N_TIMESTAMPS" "$aes_keygen_per_client" "0" \
            "0" "0" "$aes_encrypt_per_vector" "0" "$aes_decrypt_time" "$aes_decrypt_time" >> "$RESULTS_FILE"

        echo "✓ Native AES complete"
        echo ""
    done
}

run_aes_sgx() {
    for n_clients in "${CLIENT_COUNTS[@]}"; do
        echo "Testing AES with $n_clients clients (SGX)"

        rm -rf data
        mkdir -p data

        if ! aes_client_output=$(./aes_client $n_clients $N_TIMESTAMPS $VECTOR_DIM 2>&1); then
            echo "ERROR: AES client failed"
            exit 1
        fi

        aes_keygen_per_client=$(echo "$aes_client_output" | grep "AES key generation time (per user, averaged):" | extract_ms)
        aes_encrypt_per_vector=$(echo "$aes_client_output" | grep "AES encryption time (per vector, averaged):" | extract_ms)

        if ! aes_trusted_output=$(gramine-sgx ./aes_trusted $N_TIMESTAMPS 2>&1); then
            echo "ERROR: AES trusted (SGX) failed"
            exit 1
        fi

        aes_decrypt_time=$(echo "$aes_trusted_output" | grep "Trusted decrypt+aggregate (avg):" | extract_ms)

        printf "AES-SGX            %-18s %-12s %-18s %-24s %-22s %-32s %-24s %-24s %-16s %-12s %s\n" \
            "$n_clients" "$VECTOR_DIM" "$N_TIMESTAMPS" "$aes_keygen_per_client" "0" \
            "0" "0" "$aes_encrypt_per_vector" "0" "$aes_decrypt_time" "$aes_decrypt_time" >> "$RESULTS_FILE"

        echo "✓ SGX AES complete"
        echo ""
    done
}

if [ -z "$SINGLE_MODE" ] || [ "$SINGLE_MODE" == "all" ]; then
    echo "Building all binaries..."
    make clean > /dev/null 2>&1
    make all > /dev/null 2>&1
    make sgx > /dev/null 2>&1
elif [[ "$SINGLE_MODE" == *"SGX"* ]]; then
    echo "Building native and SGX binaries..."
    make clean > /dev/null 2>&1
    make all > /dev/null 2>&1
    make sgx > /dev/null 2>&1
else
    echo "Building native binaries..."
    make clean > /dev/null 2>&1
    make all > /dev/null 2>&1
fi

echo ""
echo "=== Starting Benchmarks ==="
echo ""

case "$SINGLE_MODE" in
    "TERSE-Native")
        run_terse_native
        ;;
    "TERSE-SGX")
        run_terse_sgx
        ;;
    "AES-Native")
        run_aes_native
        ;;
    "AES-SGX")
        run_aes_sgx
        ;;
    "all"|"")
        run_terse_native
        run_aes_native
        run_terse_sgx
        run_aes_sgx
        ;;
esac

echo "=== Benchmarks Complete ==="
echo "Results: $RESULTS_FILE"
