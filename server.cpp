// server.cpp
#include "terse.h"
#include <iostream>
#include <chrono>

using namespace std;
using namespace std::chrono;

static size_t load_size(const string& filename) {
    ifstream in(filename);
    if (!in) {
        throw runtime_error("Failed to open " + filename);
    }
    size_t value;
    in >> value;
    return value;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        cerr << "Usage: " << argv[0] << " <timestamp_idx>" << endl;
        return 1;
    }

    size_t timestamp_idx = stoull(argv[1]);

    TERSEParams params = TERSEParams::load("data/params.bin");
    TERSESystem system(params);

    NativeInteger q_mod = system.get_context()->GetCryptoParameters()
                          ->GetElementParams()->GetParams()[0]->GetModulus();
    uint64_t q_val = q_mod.ConvertToInt();

    size_t vector_dim = load_size("data/vector_dim.txt");

    string ct_file = "data/ciphertexts_" + to_string(timestamp_idx) + ".bin";
    vector<vector<NativeInteger>> ciphertext_matrix = system.load_ciphertext_matrix(ct_file);
    if (ciphertext_matrix.empty()) {
        throw runtime_error("Ciphertext matrix is empty");
    }
    if (ciphertext_matrix[0].size() != vector_dim) {
        throw runtime_error("Vector dimension mismatch");
    }

    size_t n_clients = ciphertext_matrix.size();

    auto start = high_resolution_clock::now();

    // PUBLIC AGGREGATION: Just sum the ciphertexts (no p_prime)
    // This matches Algorithm 2 (Server in round ρ): ŷ_ρ,j ← Σᵢ cᵢ,ρ,j
    vector<NativeInteger> aggregate(vector_dim);

    for (size_t coord = 0; coord < vector_dim; coord++) {
        __uint128_t sum = 0;

        for (size_t client_idx = 0; client_idx < n_clients; client_idx++) {
            sum += ciphertext_matrix[client_idx][coord].ConvertToInt();
        }

        uint64_t reduced = static_cast<uint64_t>(sum % q_val);
        aggregate[coord] = NativeInteger(reduced);
    }

    auto end = high_resolution_clock::now();
    double agg_ms = duration_cast<nanoseconds>(end - start).count() / 1e6;

    string agg_file = "data/encrypted_aggregate_" + to_string(timestamp_idx) + ".bin";
    system.save_aggregate_vector(aggregate, agg_file);

    cout << "Aggregation time: " << agg_ms << " ms" << endl;

    return 0;
}
