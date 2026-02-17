// setup_clients.cpp (updated; backward compatible) + CSV timings
//
// Writes buffered CSV timing events to: data/results/timings.setup_clients.csv
//
// Optional env vars to control granularity:
// - TERSE_LOG_PER_THETA=1        -> emit per-theta events (A_theta load + precompute)
// - TERSE_LOG_PER_CLIENT=1       -> emit per-client events inside each theta (can be large)

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

#include <sstream>
#include <mutex>
#include <cstdlib>
#include <ctime>

using namespace std;

// ---------------------- existing helpers ----------------------

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

// ---------------------- main ----------------------

int main(int argc, char* argv[]) {
    omp_set_num_threads(1);
    ensure_data_dir();

    CsvTimings timings("data/results/timings.setup_clients.csv");
    const bool log_per_theta = (std::getenv("TERSE_LOG_PER_THETA") != nullptr);
    const bool log_per_client = (std::getenv("TERSE_LOG_PER_CLIENT") != nullptr);

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

    cout << "=== TERSE Client Setup (Precompute Only; CSV -> data/results/timings.setup_clients.csv) ===\n";

    // Trusted setup must have run first.
    TERSEParams params = TERSEParams::load("data/params.bin");
    TERSESystem system(params);

    size_t configured_clients = load_size_from_file("data/n_clients.txt");
    size_t configured_timestamps = load_size_from_file("data/n_timestamps.txt");
    size_t configured_vector_dim = load_size_from_file("data/vector_dim.txt");

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

    vector<TERSEClient> clients;
    {
        ScopeTimer t(timings, "setup_clients", "load_client_keys",
                     -1, -1, (int64_t)requested_vector_dim,
                     (int64_t)requested_clients, (int64_t)requested_timestamps);

        cout << "\nLoading client keys from data/client_keys.bin...\n";
        clients = system.load_client_keys("data/client_keys.bin");
    }

    if (clients.size() != configured_clients) {
        throw runtime_error("Client key count mismatch: expected " +
                            to_string(configured_clients) + ", got " +
                            to_string(clients.size()));
    }

    clients.resize(requested_clients);

    size_t total_streams = requested_timestamps * requested_vector_dim;
    size_t n_theta = (total_streams + params.poly_modulus_degree - 1) / params.poly_modulus_degree;

    cout << "\n=== Client Precomputation Phase ===\n";
    cout << "Total streams: " << total_streams << "\n";
    cout << "Poly modulus degree: " << params.poly_modulus_degree << "\n";
    cout << "Number of theta values: " << n_theta << "\n";

    {
        ScopeTimer t_total(timings, "setup_clients", "precompute_total",
                           -1, -1, (int64_t)requested_vector_dim,
                           (int64_t)requested_clients, (int64_t)requested_timestamps);

        for (uint64_t theta = 0; theta < n_theta; theta++) {
            // A_theta load timing
            std::unique_ptr<ScopeTimer> t_theta_load;
            if (log_per_theta) {
                t_theta_load = std::make_unique<ScopeTimer>(
                    timings, "setup_clients", "load_A_theta",
                    -1, (int64_t)theta, (int64_t)requested_vector_dim,
                    (int64_t)requested_clients, (int64_t)requested_timestamps
                );
            }

            string a_theta_file = "data/A_theta_" + to_string(theta) + ".bin";
            DCRTPoly A_theta = system.load_A_theta(a_theta_file);
            t_theta_load.reset();

            if (theta < 5 || theta == n_theta - 1) {
                cout << "Theta " << theta << " (A_theta loaded)\n";
            }

            // Precompute timing (batch)
            std::unique_ptr<ScopeTimer> t_theta_pre;
            if (log_per_theta) {
                t_theta_pre = std::make_unique<ScopeTimer>(
                    timings, "setup_clients", "precompute_theta_batch",
                    -1, (int64_t)theta, (int64_t)requested_vector_dim,
                    (int64_t)requested_clients, (int64_t)requested_timestamps
                );
            }

            if (log_per_client) {
                for (size_t i = 0; i < clients.size(); i++) {
                    ScopeTimer t_cli(timings, "setup_clients", "precompute_client_batch",
                                     (int64_t)i, (int64_t)theta, (int64_t)requested_vector_dim,
                                     (int64_t)requested_clients, (int64_t)requested_timestamps);
                    system.precompute_client_batch(clients[i], A_theta);
                }
            } else {
                // Keep overhead low: do not emit per-client events by default
                for (size_t i = 0; i < clients.size(); i++) {
                    system.precompute_client_batch(clients[i], A_theta);
                }
            }
        }
    }

    // Resize to requested streams (as in your original)
    for (auto& client : clients) {
        client.precomputed_p.resize(total_streams);
    }

    // Save precomputes
    {
        ScopeTimer t_save_total(timings, "setup_clients", "save_client_precomputes_total",
                                -1, -1, (int64_t)requested_vector_dim,
                                (int64_t)requested_clients, (int64_t)requested_timestamps);

        if (log_per_client) {
            for (size_t idx = 0; idx < clients.size(); idx++) {
                ScopeTimer t_one(timings, "setup_clients", "save_client_precomputes_client",
                                (int64_t)idx, -1, (int64_t)requested_vector_dim,
                                (int64_t)requested_clients, (int64_t)requested_timestamps);

                // Save exactly one client (reuse existing logic safely)
                vector<TERSEClient> one(1);
                one[0] = clients[idx];
                save_client_precomputes(one, total_streams);
            }
        } else {
            save_client_precomputes(clients, total_streams);
        }
    }

    timings.flush();

    cout << "\nClient precompute artifacts saved to ./data\n";
    cout << "Timings: data/results/timings.setup_clients.csv\n";
    cout << "You can now run Python tests / FL runtime.\n";
    return 0;
}
