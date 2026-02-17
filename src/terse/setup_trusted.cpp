// setup_trusted.cpp (CSV timings added)
//
// Writes buffered CSV timing events to: data/results/timings.setup_trusted.csv
//
// CSV columns (same as other tools):
//   unix_ns,component,phase,client_idx,ts,vector_dim,n_clients,n_timestamps,duration_us
//
// Notes:
// - Here `ts` is reused as a generic index:
//   - for per-theta events: ts = theta
//   - for per-round events: ts = round
//
// Optional env vars (granularity controls):
// - TERSE_LOG_PER_THETA=1   -> emit per-theta events (generate/save A_theta + server precompute per theta)
// - TERSE_LOG_PER_ROUND=1   -> emit per-round round-key computation events (sampling mode)

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

#include <sstream>
#include <mutex>
#include <cstdlib>
#include <ctime>

using namespace std;

// ---------------------- CSV timing utilities ----------------------

static uint64_t unix_time_ns() {
    timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

class CsvTimings {
public:
    explicit CsvTimings(string path) : path_(std::move(path)) {}

    void log_event(uint64_t unix_ns,
                   const string& component,
                   const string& phase,
                   int64_t client_idx,
                   int64_t ts,
                   int64_t vector_dim,
                   int64_t n_clients,
                   int64_t n_timestamps,
                   uint64_t duration_us) {
        ostringstream oss;
        oss << unix_ns << ","
            << component << ","
            << phase << ","
            << client_idx << ","
            << ts << ","
            << vector_dim << ","
            << n_clients << ","
            << n_timestamps << ","
            << duration_us
            << "\n";

        lock_guard<mutex> lk(mu_);
        buf_.push_back(oss.str());
    }

    void flush() {
        lock_guard<mutex> lk(mu_);

        filesystem::create_directories(filesystem::path(path_).parent_path());

        const bool need_header = !file_exists_nonempty_();
        ofstream out(path_, ios::app);
        if (!out) throw runtime_error("Failed to open timings file: " + path_);

        if (need_header) {
            out << "unix_ns,component,phase,client_idx,ts,vector_dim,n_clients,n_timestamps,duration_us\n";
        }
        for (const auto& line : buf_) out << line;
        buf_.clear();
    }

    ~CsvTimings() {
        try { flush(); } catch (...) {}
    }

private:
    bool file_exists_nonempty_() const {
        ifstream in(path_, ios::binary);
        return in.good() && in.peek() != ifstream::traits_type::eof();
    }

    string path_;
    mutex mu_;
    vector<string> buf_;
};

class ScopeTimer {
public:
    using Clock = std::chrono::steady_clock;

    ScopeTimer(CsvTimings& timings,
               string component,
               string phase,
               int64_t client_idx,
               int64_t ts,
               int64_t vector_dim,
               int64_t n_clients,
               int64_t n_timestamps)
        : timings_(timings),
          component_(std::move(component)),
          phase_(std::move(phase)),
          client_idx_(client_idx),
          ts_(ts),
          vector_dim_(vector_dim),
          n_clients_(n_clients),
          n_timestamps_(n_timestamps),
          unix_ns_(unix_time_ns()),
          start_(Clock::now()) {}

    ~ScopeTimer() {
        auto end = Clock::now();
        uint64_t us = (uint64_t)std::chrono::duration_cast<std::chrono::microseconds>(end - start_).count();
        timings_.log_event(unix_ns_, component_, phase_, client_idx_, ts_, vector_dim_, n_clients_, n_timestamps_, us);
    }

private:
    CsvTimings& timings_;
    string component_;
    string phase_;
    int64_t client_idx_;
    int64_t ts_;
    int64_t vector_dim_;
    int64_t n_clients_;
    int64_t n_timestamps_;
    uint64_t unix_ns_;
    Clock::time_point start_;
};

// ---------------------- original helpers ----------------------

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

// ---------------------- main ----------------------

int main(int argc, char* argv[]) {
    CsvTimings timings("data/results/timings.setup_trusted.csv");
    const bool log_per_theta = (std::getenv("TERSE_LOG_PER_THETA") != nullptr);
    const bool log_per_round = (std::getenv("TERSE_LOG_PER_ROUND") != nullptr);

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
            schedule_seed = mix64((uint64_t)std::chrono::steady_clock::now().time_since_epoch().count());
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

    cout << "=== TERSE Trusted Setup (TEE; CSV -> data/results/timings.setup_trusted.csv) ===\n";
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

    // Persist metadata
    {
        ScopeTimer t(timings, "setup_trusted", "save_metadata",
                     -1, -1, (int64_t)vector_dim, (int64_t)n_clients, (int64_t)n_timestamps);

        save_size_to_file("data/n_clients.txt", n_clients);
        save_size_to_file("data/n_rounds.txt", n_rounds);
        save_size_to_file("data/n_chunks.txt", n_chunks);
        save_size_to_file("data/n_timestamps.txt", n_timestamps);
        save_size_to_file("data/vector_dim.txt", vector_dim);
        save_double_to_file("data/fraction_fit.txt", fraction_fit);
        save_size_to_file("data/schedule_seed.txt", (size_t)schedule_seed);
    }

    const bool all_clients_every_round = (fraction_fit >= 1.0);
    size_t k_per_round = all_clients_every_round
        ? n_clients
        : (size_t)std::ceil(fraction_fit * (double)n_clients);
    if (k_per_round < 1) k_per_round = 1;
    if (k_per_round > n_clients) k_per_round = n_clients;

    {
        ScopeTimer t(timings, "setup_trusted", "save_k_per_round",
                     -1, -1, (int64_t)vector_dim, (int64_t)n_clients, (int64_t)n_timestamps);
        save_size_to_file("data/k_per_round.txt", k_per_round);
    }

    vector<TERSEClient> clients;
    {
        ScopeTimer t(timings, "setup_trusted", "client_keygen_total",
                     -1, -1, (int64_t)vector_dim, (int64_t)n_clients, (int64_t)n_timestamps);

        cout << "\nGenerating client secret keys inside TEE...\n";
        clients = system.generate_client_keys(n_clients);
    }

    // Save params.bin AFTER generate_client_keys updates params.cipher_modulus via context
    {
        ScopeTimer t(timings, "setup_trusted", "save_params_bin",
                     -1, -1, (int64_t)vector_dim, (int64_t)n_clients, (int64_t)n_timestamps);

        TERSEParams params_to_save = system.get_params();
        params_to_save.save("data/params.bin");
    }

    {
        ScopeTimer t(timings, "setup_trusted", "save_client_keys_bin",
                     -1, -1, (int64_t)vector_dim, (int64_t)n_clients, (int64_t)n_timestamps);

        system.save_client_keys(clients, "data/client_keys.bin");
    }
    cout << "Wrote data/client_keys.bin\n";

    // Schedule generation + save
    vector<vector<uint32_t>> participants;
    if (!all_clients_every_round) {
        cout << "\nGenerating per-round participant schedule inside TEE...\n";
        {
            ScopeTimer t(timings, "setup_trusted", "schedule_generate",
                         -1, -1, (int64_t)vector_dim, (int64_t)n_clients, (int64_t)n_timestamps);
            participants = make_schedule((uint32_t)n_clients, (uint32_t)n_rounds, (uint32_t)k_per_round, schedule_seed);
        }
    } else {
        cout << "\nSampling disabled (fraction_fit=1.0): all clients participate every round.\n";
    }

    {
        ScopeTimer t(timings, "setup_trusted", "schedule_save_bin",
                     -1, -1, (int64_t)vector_dim, (int64_t)n_clients, (int64_t)n_timestamps);

        save_schedule_bin(
            "data/schedule.bin",
            (uint32_t)n_rounds,
            (uint32_t)k_per_round,
            schedule_seed,
            all_clients_every_round,
            participants
        );
    }
    cout << "Wrote data/schedule.bin\n";

    // Round keys s'_r computation
    cout << "\nComputing server-side round keys inside TEE...\n";

    auto ZeroLike = [&](const DCRTPoly& ref) {
        DCRTPoly z = ref;
        z -= ref;
        return z;
    };

    DCRTPoly s_global;
    vector<DCRTPoly> s_round;

    {
        ScopeTimer t_total(timings, "setup_trusted", "round_keys_total",
                           -1, -1, (int64_t)vector_dim, (int64_t)n_clients, (int64_t)n_timestamps);

        if (all_clients_every_round) {
            DCRTPoly sum = ZeroLike(clients[0].secret_key);
            for (size_t i = 0; i < n_clients; i++) {
                sum += clients[i].secret_key;
            }
            s_global = sum.Negate();
        } else {
            s_round.resize(n_rounds);
            for (uint32_t r = 0; r < (uint32_t)n_rounds; r++) {
                std::unique_ptr<ScopeTimer> t_r;
                if (log_per_round) {
                    t_r = std::make_unique<ScopeTimer>(
                        timings, "setup_trusted", "round_key_compute",
                        -1, (int64_t)r, (int64_t)vector_dim, (int64_t)n_clients, (int64_t)n_timestamps
                    );
                }

                DCRTPoly sum = ZeroLike(clients[0].secret_key);
                for (uint32_t cid : participants[r]) {
                    sum += clients[(size_t)cid].secret_key;
                }
                s_round[r] = sum.Negate();
            }
        }
    }

    // Theta generation + server p' precompute
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

    {
        ScopeTimer t_total(timings, "setup_trusted", "theta_total",
                           -1, -1, (int64_t)vector_dim, (int64_t)n_clients, (int64_t)n_timestamps);

        for (uint64_t theta = 0; theta < (uint64_t)n_theta; theta++) {
            // generate A_theta
            DCRTPoly A_theta;
            {
                std::unique_ptr<ScopeTimer> t_theta;
                if (log_per_theta) {
                    t_theta = std::make_unique<ScopeTimer>(
                        timings, "setup_trusted", "generate_A_theta",
                        -1, (int64_t)theta, (int64_t)vector_dim, (int64_t)n_clients, (int64_t)n_timestamps
                    );
                }
                A_theta = system.generate_A_theta(theta);
            }

            // save A_theta
            {
                std::unique_ptr<ScopeTimer> t_theta;
                if (log_per_theta) {
                    t_theta = std::make_unique<ScopeTimer>(
                        timings, "setup_trusted", "save_A_theta",
                        -1, (int64_t)theta, (int64_t)vector_dim, (int64_t)n_clients, (int64_t)n_timestamps
                    );
                }
                string a_theta_file = "data/A_theta_" + to_string(theta) + ".bin";
                system.save_A_theta(A_theta, a_theta_file);
            }

            if (theta < 5 || theta == (uint64_t)n_theta - 1) {
                cout << "Theta " << theta << " (A_theta generated/saved)\n";
            }

            // server p' precompute for this theta
            {
                std::unique_ptr<ScopeTimer> t_theta;
                if (log_per_theta) {
                    t_theta = std::make_unique<ScopeTimer>(
                        timings, "setup_trusted", "server_precompute_theta",
                        -1, (int64_t)theta, (int64_t)vector_dim, (int64_t)n_clients, (int64_t)n_timestamps
                    );
                }

                unordered_map<uint32_t, std::vector<NativeInteger>> coeff_cache;
                coeff_cache.reserve(2);

                uint64_t base = theta * (uint64_t)N;

                for (uint32_t tau = 0; tau < (uint32_t)N; tau++) {
                    uint64_t stream_idx = base + (uint64_t)tau;
                    if (stream_idx >= (uint64_t)total_streams) break;

                    uint64_t timestamp = stream_idx / (uint64_t)vector_dim;
                    uint32_t round = (uint32_t)(timestamp / (uint64_t)n_chunks);

                    auto it = coeff_cache.find(round);
                    if (it == coeff_cache.end()) {
                        const DCRTPoly& s_use = all_clients_every_round ? s_global : s_round[round];

                        DCRTPoly product = A_theta * s_use;
                        product.SetFormat(Format::COEFFICIENT);

                        const auto& first_tower = product.GetElementAtIndex(0);
                        const auto& values = first_tower.GetValues();

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
            }
        }
    }

    if (server.precomputed_p_prime.size() != total_streams) {
        cerr << "ERROR: precomputed_p_prime size mismatch: got "
             << server.precomputed_p_prime.size() << " expected " << total_streams << "\n";
        return 1;
    }

    {
        ScopeTimer t(timings, "setup_trusted", "save_server_key_bin",
                     -1, -1, (int64_t)vector_dim, (int64_t)n_clients, (int64_t)n_timestamps);
        system.save_server_key(server, "data/server_key.bin");
    }
    cout << "\nServer key saved to data/server_key.bin\n";

    timings.flush();

    cout << "\nTrusted setup complete.\n";
    cout << "Timings: data/results/timings.setup_trusted.csv\n";
    cout << "Run setup_clients next to build client precompute pads.\n";
    return 0;
}
