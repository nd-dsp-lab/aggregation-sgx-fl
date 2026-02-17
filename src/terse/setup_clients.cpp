// setup_clients.cpp (updated; backward compatible)
//
// Old mode:
//   setup_clients <n_clients> <n_timestamps> [vector_dim]
//
// New mode (mirrors trusted setup; sampling does NOT change pad math):
//   setup_clients <n_clients> <n_rounds> <n_chunks> <vector_dim>
//
// Internally, we still precompute pads for the requested (n_timestamps, vector_dim).

#include "terse/terse.h"
#include <omp.h>

#include <chrono>
#include <filesystem>
#include <iostream>
#include <numeric>
#include <stdexcept>
#include <vector>
#include <fstream>
#include <string>

using namespace std;
using namespace std::chrono;

static void ensure_data_dir() {
    filesystem::create_directories("data");
}

static size_t load_size_from_file(const string& filename) {
    ifstream in(filename);
    if (!in) {
        throw runtime_error("Failed to open " + filename);
    }
    size_t value = 0;
    in >> value;
    return value;
}

static bool file_exists(const string& filename) {
    return filesystem::exists(filename);
}

static void save_client_precomputes(const vector<TERSEClient>& clients,
                                    size_t expected_streams) {
    for (size_t idx = 0; idx < clients.size(); idx++) {
        if (clients[idx].precomputed_p.size() != expected_streams) {
            throw runtime_error("Client " + to_string(idx) + " precomputation size mismatch");
        }

        string filename = "data/client_precompute_" + to_string(idx) + ".bin";
        ofstream out(filename, ios::binary);
        if (!out) {
            throw runtime_error("Failed to open " + filename);
        }

        size_t n_entries = clients[idx].precomputed_p.size();
        out.write(reinterpret_cast<const char*>(&n_entries), sizeof(n_entries));

        vector<uint64_t> buffer(n_entries);
        for (size_t i = 0; i < n_entries; i++) {
            buffer[i] = clients[idx].precomputed_p[i].ConvertToInt();
        }
        out.write(reinterpret_cast<const char*>(buffer.data()), buffer.size() * sizeof(uint64_t));

        if (!out) {
            throw runtime_error("Failed to write " + filename);
        }
    }
}

int main(int argc, char* argv[]) {
    omp_set_num_threads(1);
    ensure_data_dir();

    const bool old_mode = (argc == 3 || argc == 4);
    const bool new_mode = (argc == 5);

    if (!old_mode && !new_mode) {
        cerr << "Usage (old): " << argv[0] << " <n_clients> <n_timestamps> [vector_dim]\n";
        cerr << "Usage (new): " << argv[0] << " <n_clients> <n_rounds> <n_chunks> <vector_dim>\n";
        return 1;
    }

    size_t requested_clients = 0;
    size_t requested_timestamps = 0;
    size_t requested_vector_dim = 1;

    if (old_mode) {
        requested_clients = stoull(argv[1]);
        requested_timestamps = stoull(argv[2]);
        requested_vector_dim = (argc == 4) ? stoull(argv[3]) : 1;
    } else {
        // New mode: derive requested_timestamps = n_rounds * n_chunks
        requested_clients = stoull(argv[1]);
        size_t n_rounds = stoull(argv[2]);
        size_t n_chunks = stoull(argv[3]);
        requested_vector_dim = stoull(argv[4]);
        requested_timestamps = n_rounds * n_chunks;
    }

    if (requested_clients == 0 || requested_timestamps == 0 || requested_vector_dim == 0) {
        cerr << "All arguments must be positive\n";
        return 1;
    }

    cout << "=== TERSE Client Setup (Precompute Only) ===\n";

    // Trusted setup must have run first.
    TERSEParams params = TERSEParams::load("data/params.bin");
    TERSESystem system(params);

    size_t configured_clients = load_size_from_file("data/n_clients.txt");
    size_t configured_timestamps = load_size_from_file("data/n_timestamps.txt");
    size_t configured_vector_dim = load_size_from_file("data/vector_dim.txt");

    // Optional (new trusted setup writes these)
    if (file_exists("data/n_rounds.txt") && file_exists("data/n_chunks.txt")) {
        size_t configured_rounds = load_size_from_file("data/n_rounds.txt");
        size_t configured_chunks = load_size_from_file("data/n_chunks.txt");
        cout << "Configured rounds/chunks: n_rounds=" << configured_rounds
             << ", n_chunks=" << configured_chunks << "\n";
    }

    if (requested_clients > configured_clients ||
        requested_timestamps > configured_timestamps ||
        requested_vector_dim > configured_vector_dim) {
        cerr << "Requested dimensions exceed trusted-setup artifacts\n";
        cerr << "Configured: n_clients=" << configured_clients
             << ", n_timestamps=" << configured_timestamps
             << ", vector_dim=" << configured_vector_dim << "\n";
        cerr << "Requested:  n_clients=" << requested_clients
             << ", n_timestamps=" << requested_timestamps
             << ", vector_dim=" << requested_vector_dim << "\n";
        return 1;
    }

    cout << "Configured: n_clients=" << configured_clients
         << ", n_timestamps=" << configured_timestamps
         << ", vector_dim=" << configured_vector_dim << "\n";

    cout << "Requested:  n_clients=" << requested_clients
         << ", n_timestamps=" << requested_timestamps
         << ", vector_dim=" << requested_vector_dim << "\n";

    cout << "\nLoading client keys from data/client_keys.bin...\n";
    vector<TERSEClient> clients = system.load_client_keys("data/client_keys.bin");
    if (clients.size() != configured_clients) {
        throw runtime_error("Client key count mismatch: expected " +
                            to_string(configured_clients) + ", got " +
                            to_string(clients.size()));
    }

    // Only precompute for the requested subset of clients.
    clients.resize(requested_clients);

    size_t total_streams = requested_timestamps * requested_vector_dim;
    size_t n_theta = (total_streams + params.poly_modulus_degree - 1) / params.poly_modulus_degree;

    cout << "\n=== Client Precomputation Phase ===\n";
    cout << "Total streams: " << total_streams << "\n";
    cout << "Poly modulus degree: " << params.poly_modulus_degree << "\n";
    cout << "Number of theta values: " << n_theta << "\n";

    double a_theta_loading_ms = 0.0;
    double single_client_precompute_ms = 0.0;

    auto precomp_total_start = high_resolution_clock::now();

    for (uint64_t theta = 0; theta < n_theta; theta++) {
        auto theta_start = high_resolution_clock::now();
        string a_theta_file = "data/A_theta_" + to_string(theta) + ".bin";
        DCRTPoly A_theta = system.load_A_theta(a_theta_file);
        auto theta_end = high_resolution_clock::now();

        double theta_ms = duration_cast<nanoseconds>(theta_end - theta_start).count() / 1e6;
        a_theta_loading_ms += theta_ms;

        if (theta < 5 || theta == n_theta - 1) {
            cout << "Theta " << theta << " (A_theta loaded in " << theta_ms << " ms)\n";
        }

        auto one_client_start = high_resolution_clock::now();
        system.precompute_client_batch(clients[0], A_theta);
        auto one_client_end = high_resolution_clock::now();
        single_client_precompute_ms +=
            duration_cast<nanoseconds>(one_client_end - one_client_start).count() / 1e6;

        for (size_t i = 1; i < clients.size(); i++) {
            system.precompute_client_batch(clients[i], A_theta);
        }
    }

    for (auto& client : clients) {
        client.precomputed_p.resize(total_streams);
    }

    auto precomp_total_end = high_resolution_clock::now();
    double precompute_total_ms =
        duration_cast<nanoseconds>(precomp_total_end - precomp_total_start).count() / 1e6;

    cout << "\nA_theta loading time (total): " << a_theta_loading_ms << " ms\n";
    cout << "Client precomputation time (per client for one theta batch): "
         << single_client_precompute_ms << " ms\n";
    cout << "Client precomputation wall clock time: " << precompute_total_ms << " ms\n";

    save_client_precomputes(clients, total_streams);

    cout << "\nClient precompute artifacts saved to ./data\n";
    cout << "You can now run Python tests / FL runtime.\n";
    return 0;
}
