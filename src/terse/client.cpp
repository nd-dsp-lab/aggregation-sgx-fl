// client.cpp
#include "terse/terse.h"
#include <iostream>
#include <iomanip>
#include <filesystem>
#include <chrono>
#include <numeric>
#include <random>
#include <omp.h>

#include <fstream>
#include <sstream>
#include <mutex>
#include <vector>
#include <cstdlib>
#include <ctime>

using namespace std;

static TERSEParams load_params() {
    return TERSEParams::load("data/params.bin");
}

static size_t load_size_from_file(const string& filename) {
    ifstream in(filename);
    if (!in) throw runtime_error("Failed to open " + filename);
    size_t value;
    in >> value;
    return value;
}

static vector<vector<NativeInteger>> load_client_precomputes(size_t n_clients, size_t expected_streams) {
    vector<vector<NativeInteger>> precomputes(n_clients);

    for (size_t idx = 0; idx < n_clients; idx++) {
        string filename = "data/client_precompute_" + to_string(idx) + ".bin";
        ifstream in(filename, ios::binary);
        if (!in) throw runtime_error("Failed to open " + filename);

        size_t n_entries;
        in.read(reinterpret_cast<char*>(&n_entries), sizeof(n_entries));

        if (n_entries != expected_streams) {
            throw runtime_error("Client " + to_string(idx) + " precompute size mismatch");
        }

        vector<uint64_t> buffer(n_entries);
        in.read(reinterpret_cast<char*>(buffer.data()), buffer.size() * sizeof(uint64_t));

        precomputes[idx].resize(n_entries);
        for (size_t i = 0; i < n_entries; i++) {
            precomputes[idx][i] = NativeInteger(buffer[i]);
        }
    }

    return precomputes;
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
        // Buffer in memory; flush at end (or you can add periodic flushing if needed).
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

    if (argc != 4) {
        cerr << "Usage: " << argv[0] << " <n_clients> <n_timestamps> <vector_dim>" << endl;
        return 1;
    }

    size_t n_clients = stoull(argv[1]);
    size_t n_timestamps = stoull(argv[2]);
    size_t vector_dim = stoull(argv[3]);

    // CSV timings: buffered, minimal console output
    CsvTimings timings("data/results/timings.client.csv");
    const bool log_per_vector = (std::getenv("TERSE_LOG_PER_VECTOR") != nullptr);

    TERSEParams params = load_params();
    TERSESystem system(params);

    size_t expected_n_clients = load_size_from_file("data/n_clients.txt");
    size_t expected_n_timestamps = load_size_from_file("data/n_timestamps.txt");
    size_t expected_vector_dim = load_size_from_file("data/vector_dim.txt");

    if (n_clients > expected_n_clients) {
        cerr << "Error: Requested " << n_clients << " clients, but only "
             << expected_n_clients << " were set up" << endl;
        return 1;
    }

    size_t total_streams = n_timestamps * vector_dim;
    size_t expected_streams = expected_n_timestamps * expected_vector_dim;

    if (total_streams > expected_streams) {
        cerr << "Error: Requested " << total_streams << " streams, but only "
             << expected_streams << " were precomputed" << endl;
        return 1;
    }

    cout << "=== TERSE Client Encryption (CSV timings -> data/results/timings.client.csv) ===" << endl;

    vector<vector<NativeInteger>> client_precomputes;
    {
        ScopeTimer t(timings, "client", "load_precomputes", -1, -1,
                     (int64_t)vector_dim, (int64_t)n_clients, (int64_t)n_timestamps);
        client_precomputes = load_client_precomputes(n_clients, expected_streams);
    }

    random_device rd;
    mt19937_64 gen(rd());
    uniform_int_distribution<uint32_t> plaintext_dist(0, params.plain_modulus - 1);

    vector<vector<vector<NativeInteger>>> all_ciphertexts(n_clients);
    for (size_t i = 0; i < n_clients; i++) {
        all_ciphertexts[i].resize(n_timestamps, vector<NativeInteger>(vector_dim));
    }

    vector<vector<uint64_t>> expected_sums(n_timestamps, vector<uint64_t>(vector_dim, 0));

    {
        ScopeTimer total_t(timings, "client", "encrypt_total", -1, -1,
                           (int64_t)vector_dim, (int64_t)n_clients, (int64_t)n_timestamps);

        for (size_t client_idx = 0; client_idx < n_clients; client_idx++) {
            TERSEClient client;
            client.precomputed_p = client_precomputes[client_idx];

            // Optional: total per client
            ScopeTimer client_t(timings, "client", "encrypt_client_total",
                                (int64_t)client_idx, -1, (int64_t)vector_dim,
                                (int64_t)n_clients, (int64_t)n_timestamps);

            for (size_t ts = 0; ts < n_timestamps; ts++) {
                // Optional: per vector (can be large; gated by env var)
                std::unique_ptr<ScopeTimer> vec_t;
                if (log_per_vector) {
                    vec_t = std::make_unique<ScopeTimer>(
                        timings, "client", "encrypt_vector",
                        (int64_t)client_idx, (int64_t)ts, (int64_t)vector_dim,
                        (int64_t)n_clients, (int64_t)n_timestamps
                    );
                }

                for (size_t dim = 0; dim < vector_dim; dim++) {
                    uint32_t plaintext = plaintext_dist(gen);
                    size_t stream_idx = ts * vector_dim + dim;

                    NativeInteger ct = system.encrypt(client, plaintext, stream_idx);
                    all_ciphertexts[client_idx][ts][dim] = ct;

                    expected_sums[ts][dim] =
                        (expected_sums[ts][dim] + plaintext) % params.plain_modulus;
                }
            }
        }
    }

    {
        ScopeTimer t(timings, "client", "save_ciphertexts_total", -1, -1,
                     (int64_t)vector_dim, (int64_t)n_clients, (int64_t)n_timestamps);

        for (size_t client_idx = 0; client_idx < n_clients; client_idx++) {
            // Optional per-client save timing (small number of events)
            ScopeTimer t_client(timings, "client", "save_ciphertexts_client",
                                (int64_t)client_idx, -1, (int64_t)vector_dim,
                                (int64_t)n_clients, (int64_t)n_timestamps);

            string filename = "data/ciphertexts_client_" + to_string(client_idx) + ".bin";
            system.save_ciphertext_matrix(all_ciphertexts[client_idx], filename);
        }
    }

    {
        ScopeTimer t(timings, "client", "save_expected_sums_total", -1, -1,
                     (int64_t)vector_dim, (int64_t)n_clients, (int64_t)n_timestamps);

        for (size_t ts = 0; ts < n_timestamps; ts++) {
            string sum_file = "data/expected_sum_" + to_string(ts) + ".txt";
            ofstream sum_out(sum_file);
            if (!sum_out) throw runtime_error("Failed to open " + sum_file);

            for (size_t dim = 0; dim < vector_dim; dim++) {
                sum_out << expected_sums[ts][dim];
                if (dim + 1 < vector_dim) sum_out << ' ';
            }
            sum_out << endl;
        }
    }

    // Flush once at the end to minimize overhead
    timings.flush();

    cout << "Done. Timings: data/results/timings.client.csv" << endl;
    if (log_per_vector) {
        cout << "Per-vector timing was ENABLED (TERSE_LOG_PER_VECTOR set)." << endl;
    } else {
        cout << "Per-vector timing is DISABLED. Set TERSE_LOG_PER_VECTOR=1 to enable." << endl;
    }

    return 0;
}
