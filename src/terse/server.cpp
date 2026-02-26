// server.cpp (SUMMARY CSV timings)
//
// Writes aggregated summary timing stats to:
//   data/results/timings.server.summary.csv
//
// CSV columns:
//   component,phase,count,mean_us,stddev_us,min_us,max_us,range_us
//
// Optional env vars:
// - TERSE_LOG_PER_TIMESTAMP=1  -> include per-timestamp phases in the summary

#include "terse/terse.h"
#include "common/terse_timings_summary.h"

#include <iostream>
#include <iomanip>
#include <filesystem>
#include <chrono>
#include <numeric>

#include <fstream>
#include <vector>
#include <cstdlib>

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

static vector<vector<vector<NativeInteger>>> load_all_ciphertexts(
    TERSESystem& system, size_t n_clients) {

    vector<vector<vector<NativeInteger>>> all_cts(n_clients);

    for (size_t i = 0; i < n_clients; i++) {
        string filename = "data/ciphertexts_client_" + to_string(i) + ".bin";
        all_cts[i] = system.load_ciphertext_matrix(filename);
    }

    return all_cts;
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        cerr << "Usage: " << argv[0] << " <n_clients> <n_timestamps> <vector_dim>" << endl;
        return 1;
    }

    size_t n_clients = stoull(argv[1]);
    size_t n_timestamps = stoull(argv[2]);
    size_t vector_dim = stoull(argv[3]);

    CsvTimings timings("data/results/timings.server.summary.csv");
    const bool log_per_timestamp = (std::getenv("TERSE_LOG_PER_TIMESTAMP") != nullptr);

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

    if (n_timestamps > expected_n_timestamps || vector_dim > expected_vector_dim) {
        cerr << "Error: Requested dimensions exceed setup parameters" << endl;
        return 1;
    }

    NativeInteger q_mod = system.get_context()->GetCryptoParameters()
                          ->GetElementParams()->GetParams()[0]->GetModulus();
    uint64_t q_val = q_mod.ConvertToInt();

    cout << "=== TERSE Server Aggregation (summary CSV -> data/results/timings.server.summary.csv) ===" << endl;

    vector<vector<vector<NativeInteger>>> all_ciphertexts;
    {
        ScopeTimer t(timings, "server", "load_ciphertexts_total",
                     -1, -1, (int64_t)vector_dim, (int64_t)n_clients, (int64_t)n_timestamps);
        all_ciphertexts = load_all_ciphertexts(system, n_clients);
    }

    cout << "Aggregating ciphertexts (untrusted - no decryption)..." << endl;

    {
        ScopeTimer t_total(timings, "server", "aggregate_total",
                           -1, -1, (int64_t)vector_dim, (int64_t)n_clients, (int64_t)n_timestamps);

        for (size_t ts = 0; ts < n_timestamps; ts++) {
            if (n_timestamps >= 1000) {
                size_t progress_interval = max<size_t>(1, n_timestamps / 100);
                if (ts % progress_interval == 0 || ts == n_timestamps - 1) {
                    double percent = (100.0 * ts) / n_timestamps;
                    cout << "\r  Progress: " << fixed << setprecision(1)
                         << percent << "% (" << ts << "/" << n_timestamps << " timestamps)" << flush;
                }
            }

            std::unique_ptr<ScopeTimer> t_ts;
            if (log_per_timestamp) {
                t_ts = std::make_unique<ScopeTimer>(
                    timings, "server", "aggregate_timestamp",
                    -1, (int64_t)ts, (int64_t)vector_dim, (int64_t)n_clients, (int64_t)n_timestamps
                );
            }

            vector<NativeInteger> aggregate(vector_dim);

            for (size_t coord = 0; coord < vector_dim; coord++) {
                __uint128_t sum = 0;
                for (size_t client_idx = 0; client_idx < n_clients; client_idx++) {
                    sum += all_ciphertexts[client_idx][ts][coord].ConvertToInt();
                }
                uint64_t reduced = static_cast<uint64_t>(sum % q_val);
                aggregate[coord] = NativeInteger(reduced);
            }

            {
                ScopeTimer t_save(timings, "server", "save_encrypted_aggregate",
                                  -1, (int64_t)ts, (int64_t)vector_dim, (int64_t)n_clients, (int64_t)n_timestamps);

                string agg_file = "data/encrypted_aggregate_" + to_string(ts) + ".bin";
                system.save_aggregate_vector(aggregate, agg_file);
            }
        }
    }

    cout << "\r" << string(80, ' ') << "\r";

    timings.flush();

    cout << "Done. Timings: data/results/timings.server.summary.csv" << endl;
    if (log_per_timestamp) {
        cout << "Per-timestamp timing was ENABLED (TERSE_LOG_PER_TIMESTAMP set)." << endl;
    } else {
        cout << "Per-timestamp timing is DISABLED. Set TERSE_LOG_PER_TIMESTAMP=1 to enable." << endl;
    }

    return 0;
}
