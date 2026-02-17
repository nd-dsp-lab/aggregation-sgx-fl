// setup_trusted.cpp (updated for per-round sampling schedule generated in trusted setup)
//
// Backward-compatible modes:
//
//   1) Old mode (no sampling; all clients participate in every timestamp):
//        setup_trusted <n_clients> <n_timestamps> [vector_dim]
//
//      Internally sets:
//        n_rounds   = n_timestamps
//        n_chunks   = 1
//        fraction   = 1.0
//
//   2) New mode (sampling per server_round):
//        setup_trusted <n_clients> <n_rounds> <n_chunks> <vector_dim> <fraction_fit> [schedule_seed]
//
//      Here:
//        n_timestamps = n_rounds * n_chunks
//        total_streams = n_timestamps * vector_dim
//
// Output (public params / artifacts):
//   data/params.bin
//   data/client_keys.bin
//   data/server_key.bin          (actually stores only precomputed_p_prime as before)
//   data/A_theta_<theta>.bin
//   data/schedule.bin            (participant IDs per round; omitted body if fraction_fit==1.0)
//   data/n_clients.txt, data/n_rounds.txt, data/n_chunks.txt, data/n_timestamps.txt, data/vector_dim.txt
//   data/fraction_fit.txt, data/k_per_round.txt, data/schedule_seed.txt

#include "terse/terse.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <numeric>
#include <random>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

using namespace std;
using namespace std::chrono;

static void ensure_data_dir() {
    filesystem::create_directories("data");
}

static void save_size_to_file(const string& filename, size_t value) {
    ofstream out(filename);
    if (!out) {
        throw runtime_error("Failed to open " + filename);
    }
    out << value << endl;
}

static void save_double_to_file(const string& filename, double value) {
    ofstream out(filename);
    if (!out) {
        throw runtime_error("Failed to open " + filename);
    }
    out << value << endl;
}

static uint64_t mix64(uint64_t x) {
    // Simple 64-bit mix (similar spirit to splitmix64 finalizer)
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ULL;
    x ^= x >> 33;
    return x;
}

static vector<vector<uint32_t>> make_schedule(
    uint32_t n_clients,
    uint32_t n_rounds,
    uint32_t k_per_round,
    uint64_t schedule_seed
) {
    vector<uint32_t> base(n_clients);
    iota(base.begin(), base.end(), 0);

    vector<vector<uint32_t>> participants;
    participants.resize(n_rounds);

    for (uint32_t r = 0; r < n_rounds; r++) {
        vector<uint32_t> ids = base;

        uint64_t seed_r = mix64(schedule_seed ^ (uint64_t)r * 0x9e3779b97f4a7c15ULL);
        std::mt19937_64 rng(seed_r);
        shuffle(ids.begin(), ids.end(), rng);

        ids.resize(k_per_round);
        participants[r] = std::move(ids);
    }
    return participants;
}

static void save_schedule_bin(
    const string& filename,
    uint32_t n_rounds,
    uint32_t k_per_round,
    uint64_t schedule_seed,
    bool all_clients_every_round,
    const vector<vector<uint32_t>>& participants
) {
    ofstream out(filename, ios::binary);
    if (!out) {
        throw runtime_error("Failed to open " + filename + " for writing");
    }

    // Header
    uint32_t magic = 0x53455254;   // 'TRES' (arbitrary)
    uint32_t version = 1;
    uint32_t flags = all_clients_every_round ? 1u : 0u;

    out.write(reinterpret_cast<const char*>(&magic), sizeof(magic));
    out.write(reinterpret_cast<const char*>(&version), sizeof(version));
    out.write(reinterpret_cast<const char*>(&flags), sizeof(flags));
    out.write(reinterpret_cast<const char*>(&n_rounds), sizeof(n_rounds));
    out.write(reinterpret_cast<const char*>(&k_per_round), sizeof(k_per_round));
    out.write(reinterpret_cast<const char*>(&schedule_seed), sizeof(schedule_seed));

    if (!all_clients_every_round) {
        for (uint32_t r = 0; r < n_rounds; r++) {
            if (participants[r].size() != k_per_round) {
                throw runtime_error("participants[r].size() != k_per_round at r=" + to_string(r));
            }
            out.write(reinterpret_cast<const char*>(participants[r].data()),
                      sizeof(uint32_t) * (size_t)k_per_round);
        }
    }

    if (!out) {
        throw runtime_error("Failed to write " + filename);
    }
    out.close();
}

int main(int argc, char* argv[]) {
    // Old mode: argc == 3 or 4
    // New mode: argc == 6 or 7
    const bool old_mode = (argc == 3 || argc == 4);
    const bool new_mode = (argc == 6 || argc == 7);

    if (!old_mode && !new_mode) {
        cerr << "Usage (old): " << argv[0] << " <n_clients> <n_timestamps> [vector_dim]\n";
        cerr << "Usage (new): " << argv[0] << " <n_clients> <n_rounds> <n_chunks> <vector_dim> <fraction_fit> [schedule_seed]\n";
        return 1;
    }

    size_t n_clients = 0;
    size_t n_rounds = 0;
    size_t n_chunks = 0;
    size_t n_timestamps = 0;
    size_t vector_dim = 1;
    double fraction_fit = 1.0;
    uint64_t schedule_seed = 0x123456789abcdef0ULL;

    if (old_mode) {
        n_clients = stoull(argv[1]);
        n_timestamps = stoull(argv[2]);
        vector_dim = (argc == 4) ? stoull(argv[3]) : 1;

        // Interpret as "rounds = timestamps, chunks = 1" for indexing compatibility.
        n_rounds = n_timestamps;
        n_chunks = 1;
        fraction_fit = 1.0;
    } else {
        n_clients = stoull(argv[1]);
        n_rounds = stoull(argv[2]);
        n_chunks = stoull(argv[3]);
        vector_dim = stoull(argv[4]);
        fraction_fit = stod(argv[5]);
        if (argc == 7) {
            schedule_seed = stoull(argv[6]);
        } else {
            // Derive a seed from time if not supplied (still written out).
            schedule_seed = mix64((uint64_t)high_resolution_clock::now().time_since_epoch().count());
        }

        n_timestamps = n_rounds * n_chunks;
    }

    if (n_clients == 0 || n_rounds == 0 || n_chunks == 0 || n_timestamps == 0 || vector_dim == 0) {
        cerr << "All size arguments must be positive.\n";
        return 1;
    }
    if (!(fraction_fit > 0.0 && fraction_fit <= 1.0)) {
        cerr << "fraction_fit must satisfy 0 < fraction_fit <= 1.\n";
        return 1;
    }

    ensure_data_dir();

    cout << "=== TERSE Trusted Setup (TEE) ===\n";
    cout << "Config:\n";
    cout << "  n_clients=" << n_clients << "\n";
    cout << "  n_rounds=" << n_rounds << "\n";
    cout << "  n_chunks=" << n_chunks << "\n";
    cout << "  n_timestamps=" << n_timestamps << "\n";
    cout << "  vector_dim=" << vector_dim << "\n";
    cout << "  fraction_fit=" << fraction_fit << "\n";
    cout << "  schedule_seed=" << schedule_seed << "\n";

    // Public parameters are chosen/instantiated by the TEE.
    TERSEParams params(4096, 65537, 0, HEStd_128_classic, 3.2);
    TERSESystem system(params);

    // Persist configuration metadata for later tools.
    save_size_to_file("data/n_clients.txt", n_clients);
    save_size_to_file("data/n_rounds.txt", n_rounds);
    save_size_to_file("data/n_chunks.txt", n_chunks);
    save_size_to_file("data/n_timestamps.txt", n_timestamps);
    save_size_to_file("data/vector_dim.txt", vector_dim);
    save_double_to_file("data/fraction_fit.txt", fraction_fit);
    save_size_to_file("data/schedule_seed.txt", (size_t)schedule_seed);

    // Compute k_per_round
    const bool all_clients_every_round = (fraction_fit >= 1.0);
    size_t k_per_round = all_clients_every_round
        ? n_clients
        : (size_t)std::ceil(fraction_fit * (double)n_clients);
    if (k_per_round < 1) k_per_round = 1;
    if (k_per_round > n_clients) k_per_round = n_clients;
    save_size_to_file("data/k_per_round.txt", k_per_round);

    cout << "\nGenerating client secret keys inside TEE...\n";
    auto client_keygen_start = high_resolution_clock::now();
    vector<TERSEClient> clients = system.generate_client_keys(n_clients);
    auto client_keygen_end = high_resolution_clock::now();

    double client_keygen_ms =
        duration_cast<nanoseconds>(client_keygen_end - client_keygen_start).count() / 1e6;
    cout << "Client key generation time (total): " << client_keygen_ms << " ms\n";

    // Save params.bin AFTER the system is instantiated (and after generate_client_keys sets
    // params.cipher_modulus based on the OpenFHE context modulus used by the protocol).
    {
        TERSEParams params_to_save = system.get_params();
        params_to_save.save("data/params.bin");
    }

    // Save bulk client keys file.
    system.save_client_keys(clients, "data/client_keys.bin");
    cout << "Wrote data/client_keys.bin\n";

    // Build schedule in trusted setup + publish it.
    vector<vector<uint32_t>> participants;
    if (!all_clients_every_round) {
        cout << "\nGenerating per-round participant schedule inside TEE...\n";
        auto sched_start = high_resolution_clock::now();
        participants = make_schedule((uint32_t)n_clients, (uint32_t)n_rounds, (uint32_t)k_per_round, schedule_seed);
        auto sched_end = high_resolution_clock::now();
        double sched_ms = duration_cast<nanoseconds>(sched_end - sched_start).count() / 1e6;
        cout << "Schedule generation time: " << sched_ms << " ms\n";
    } else {
        cout << "\nSampling disabled (fraction_fit=1.0): all clients participate every round.\n";
    }

    save_schedule_bin(
        "data/schedule.bin",
        (uint32_t)n_rounds,
        (uint32_t)k_per_round,
        schedule_seed,
        all_clients_every_round,
        participants
    );
    cout << "Wrote data/schedule.bin\n";

    // Compute per-round server canceling keys s'_r = -sum_{i in S_r} s_i
    cout << "\nComputing server-side round keys inside TEE...\n";
    auto round_keys_start = high_resolution_clock::now();

    auto ZeroLike = [&](const DCRTPoly& ref) {
        DCRTPoly z = ref;
        z -= ref; // produce an all-zeros poly with identical params/format
        return z;
    };

    DCRTPoly s_global;                // used when all_clients_every_round
    vector<DCRTPoly> s_round;          // used when sampling

    if (all_clients_every_round) {
        DCRTPoly sum = ZeroLike(clients[0].secret_key);
        for (size_t i = 0; i < n_clients; i++) {
            sum += clients[i].secret_key;
        }
        s_global = sum.Negate();
    } else {
        s_round.resize(n_rounds);
        for (uint32_t r = 0; r < (uint32_t)n_rounds; r++) {
            DCRTPoly sum = ZeroLike(clients[0].secret_key);
            for (uint32_t cid : participants[r]) {
                sum += clients[(size_t)cid].secret_key;
            }
            s_round[r] = sum.Negate();
        }
    }

    auto round_keys_end = high_resolution_clock::now();
    double round_keys_ms =
        duration_cast<nanoseconds>(round_keys_end - round_keys_start).count() / 1e6;
    cout << "Round key computation time: " << round_keys_ms << " ms\n";

    size_t total_streams = n_timestamps * vector_dim;
    size_t N = system.get_params().poly_modulus_degree;
    size_t n_theta = (total_streams + N - 1) / N;

    cout << "\n=== Public Parameter Material + Server Precomputation ===\n";
    cout << "Total streams: " << total_streams << "\n";
    cout << "Poly modulus degree: " << N << "\n";
    cout << "Number of theta values: " << n_theta << "\n";

    TERSEServer server;
    server.precomputed_p_prime.clear();
    server.precomputed_p_prime.reserve(total_streams);

    double a_theta_generation_ms = 0.0;
    double server_precompute_ms = 0.0;

    auto precomp_total_start = high_resolution_clock::now();

    for (uint64_t theta = 0; theta < (uint64_t)n_theta; theta++) {
        auto theta_gen_start = high_resolution_clock::now();
        DCRTPoly A_theta = system.generate_A_theta(theta);
        auto theta_gen_end = high_resolution_clock::now();

        double theta_ms = duration_cast<nanoseconds>(theta_gen_end - theta_gen_start).count() / 1e6;
        a_theta_generation_ms += theta_ms;

        string a_theta_file = "data/A_theta_" + to_string(theta) + ".bin";
        system.save_A_theta(A_theta, a_theta_file);

        if (theta < 5 || theta == (uint64_t)n_theta - 1) {
            cout << "Theta " << theta << " (A_theta generated in " << theta_ms << " ms)\n";
        }

        auto server_start = high_resolution_clock::now();

        // Cache: for this theta, we might need coeff vectors for 1 (typical) or more rounds.
        // Map round -> coeffs vector (length N), stored as std::vector<NativeInteger>.
        std::unordered_map<uint32_t, std::vector<NativeInteger>> coeff_cache;
        coeff_cache.reserve(2);

        uint64_t base = theta * (uint64_t)N;

        for (uint32_t tau = 0; tau < (uint32_t)N; tau++) {
            uint64_t stream_idx = base + (uint64_t)tau;
            if (stream_idx >= (uint64_t)total_streams) {
                break;
            }

            uint64_t timestamp = stream_idx / (uint64_t)vector_dim;
            uint32_t round = (uint32_t)(timestamp / (uint64_t)n_chunks);

            auto it = coeff_cache.find(round);
            if (it == coeff_cache.end()) {
                const DCRTPoly& s_use = all_clients_every_round ? s_global : s_round[round];

                DCRTPoly product = A_theta * s_use;
                product.SetFormat(Format::COEFFICIENT);

                const auto& first_tower = product.GetElementAtIndex(0);
                const auto& values = first_tower.GetValues(); // length N

                std::vector<NativeInteger> coeffs;
                coeffs.resize(values.GetLength());
                for (size_t i = 0; i < values.GetLength(); i++) {
                    coeffs[i] = values[i];
                }

                auto ins = coeff_cache.emplace(round, std::move(coeffs));
                it = ins.first;
            }

            server.precomputed_p_prime.push_back(it->second[(size_t)tau]);
        }

        auto server_end = high_resolution_clock::now();
        server_precompute_ms += duration_cast<nanoseconds>(server_end - server_start).count() / 1e6;
    }

    auto precomp_total_end = high_resolution_clock::now();
    double precompute_total_ms =
        duration_cast<nanoseconds>(precomp_total_end - precomp_total_start).count() / 1e6;

    if (server.precomputed_p_prime.size() != total_streams) {
        cerr << "ERROR: precomputed_p_prime size mismatch: got "
             << server.precomputed_p_prime.size() << " expected " << total_streams << "\n";
        return 1;
    }

    cout << "\nA_theta generation time (total): " << a_theta_generation_ms << " ms\n";
    cout << "Server precompute time (total): " << server_precompute_ms << " ms\n";
    cout << "Server precompute wall clock time: " << precompute_total_ms << " ms\n";

    system.save_server_key(server, "data/server_key.bin");
    cout << "\nServer key saved to data/server_key.bin\n";

    cout << "\nTrusted setup complete.\n";
    cout << "Run setup_clients next to build client precompute pads.\n";
    return 0;
}
