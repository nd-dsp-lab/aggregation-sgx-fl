// client.cpp - Encryption phase (uses setup artifacts)
#include "terse.h"
#include <iostream>
#include <random>
#include <chrono>
#include <limits>
#include <numeric>

using namespace std;
using namespace std::chrono;

static size_t load_size_from_file(const string& filename) {
    ifstream in(filename);
    if (!in) {
        throw runtime_error("Failed to open " + filename);
    }
    size_t value = 0;
    in >> value;
    return value;
}

static vector<NativeInteger> load_client_precompute(const string& filename,
                                                    size_t expected_entries) {
    ifstream in(filename, ios::binary);
    if (!in) {
        throw runtime_error("Failed to open " + filename);
    }

    size_t stored_entries = 0;
    in.read(reinterpret_cast<char*>(&stored_entries), sizeof(stored_entries));
    if (stored_entries != expected_entries) {
        throw runtime_error("Precompute size mismatch in " + filename);
    }

    vector<uint64_t> buffer(stored_entries);
    in.read(reinterpret_cast<char*>(buffer.data()),
            buffer.size() * sizeof(uint64_t));
    if (!in) {
        throw runtime_error("Failed to read precompute data from " + filename);
    }

    vector<NativeInteger> result(stored_entries);
    for (size_t i = 0; i < stored_entries; i++) {
        result[i] = NativeInteger(buffer[i]);
    }
    return result;
}

int main(int argc, char* argv[]) {
    if (argc < 3 || argc > 4) {
        cerr << "Usage: " << argv[0] << " <n_clients> <n_timestamps> [vector_dim]" << endl;
        return 1;
    }

    size_t n_clients = stoull(argv[1]);
    size_t n_timestamps = stoull(argv[2]);
    size_t vector_dim = (argc == 4) ? stoull(argv[3]) : 1;

    if (n_clients == 0 || n_timestamps == 0 || vector_dim == 0) {
        cerr << "All arguments must be positive" << endl;
        return 1;
    }

    size_t recorded_clients = load_size_from_file("data/n_clients.txt");
    size_t recorded_timestamps = load_size_from_file("data/n_timestamps.txt");
    size_t recorded_vector_dim = load_size_from_file("data/vector_dim.txt");

    if (recorded_clients != n_clients ||
        recorded_timestamps != n_timestamps ||
        recorded_vector_dim != vector_dim) {
        throw runtime_error("Input arguments do not match setup metadata");
    }

    TERSEParams params = TERSEParams::load("data/params.bin");
    TERSESystem system(params);

    size_t total_streams = n_timestamps * vector_dim;
    vector<TERSEClient> clients(n_clients);

    for (size_t i = 0; i < n_clients; i++) {
        string filename = "data/client_precompute_" + to_string(i) + ".bin";
        clients[i].precomputed_p = load_client_precompute(filename, total_streams);
    }

    mt19937_64 rng(random_device{}());
    uniform_int_distribution<uint32_t> plaintext_dist(0, params.plain_modulus - 1);

    vector<vector<uint64_t>> all_expected_sums(
        n_timestamps, vector<uint64_t>(vector_dim, 0));

    vector<double> per_client_encrypt_times(n_clients, 0.0);

    for (size_t ts_idx = 0; ts_idx < n_timestamps; ts_idx++) {
        vector<vector<NativeInteger>> timestamp_ciphertexts(
            n_clients, vector<NativeInteger>(vector_dim));

        for (size_t client_idx = 0; client_idx < n_clients; client_idx++) {
            auto enc_start = high_resolution_clock::now();

            for (size_t coord = 0; coord < vector_dim; coord++) {
                size_t stream_idx = ts_idx * vector_dim + coord;
                uint32_t plaintext = plaintext_dist(rng);

                timestamp_ciphertexts[client_idx][coord] =
                    system.encrypt(clients[client_idx], plaintext, stream_idx);

                uint64_t new_sum = (all_expected_sums[ts_idx][coord] + plaintext) %
                                   params.plain_modulus;
                all_expected_sums[ts_idx][coord] = new_sum;
            }

            auto enc_end = high_resolution_clock::now();
            per_client_encrypt_times[client_idx] +=
                duration_cast<nanoseconds>(enc_end - enc_start).count() / 1e6;
        }

        string ct_file = "data/ciphertexts_" + to_string(ts_idx) + ".bin";
        system.save_ciphertext_matrix(timestamp_ciphertexts, ct_file);
    }

    double total_encrypt_ms = accumulate(per_client_encrypt_times.begin(),
                                         per_client_encrypt_times.end(), 0.0);
    double avg_per_client_encrypt_ms = total_encrypt_ms / n_clients;
    double encrypt_per_vector_ms = avg_per_client_encrypt_ms / n_timestamps;

    for (size_t ts_idx = 0; ts_idx < n_timestamps; ts_idx++) {
        string sum_file = "data/expected_sum_" + to_string(ts_idx) + ".txt";
        ofstream out(sum_file);
        if (!out) {
            throw runtime_error("Failed to open " + sum_file);
        }
        for (size_t coord = 0; coord < vector_dim; coord++) {
            out << all_expected_sums[ts_idx][coord];
            if (coord + 1 < vector_dim) {
                out << ' ';
            }
        }
        out << endl;
    }

    cout << "Encryption time (per vector, averaged): "
         << encrypt_per_vector_ms << " ms" << endl;

    return 0;
}
