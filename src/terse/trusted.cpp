// trusted.cpp (SUMMARY CSV timings)
//
// Writes aggregated summary timing stats to:
//   data/results/timings.trusted.summary.csv
//
// CSV columns:
//   component,phase,count,mean_us,stddev_us,min_us,max_us,range_us
//
// Optional env vars:
// - TERSE_LOG_PER_TIMESTAMP=1  -> include per-timestamp phases in the summary

#include "terse/terse.h"
#include "common/dp_mechanisms.h"
#include "common/terse_timings_summary.h"

#include <iostream>
#include <fstream>
#include <chrono>
#include <filesystem>
#include <sstream>
#include <vector>
#include <cstdlib>

using namespace std;

// ---------------------- app code ----------------------

struct AggregatedCiphertext {
    vector<NativeInteger> ciphertext;
};

AggregatedCiphertext load_aggregated_ciphertext_untrusted(size_t ts_idx) {
    string agg_file = "data/encrypted_aggregate_" + to_string(ts_idx) + ".bin";
    ifstream agg_in(agg_file, ios::binary);
    if (!agg_in) {
        throw runtime_error("Failed to open " + agg_file);
    }

    size_t vector_dim;
    agg_in.read(reinterpret_cast<char*>(&vector_dim), sizeof(vector_dim));

    AggregatedCiphertext agg_ct;
    agg_ct.ciphertext.resize(vector_dim);

    vector<uint64_t> buffer(vector_dim);
    agg_in.read(reinterpret_cast<char*>(buffer.data()), vector_dim * sizeof(uint64_t));

    for (size_t i = 0; i < vector_dim; i++) {
        agg_ct.ciphertext[i] = NativeInteger(buffer[i]);
    }

    agg_in.close();
    return agg_ct;
}

static size_t load_size_from_file(const string& filename) {
    ifstream in(filename);
    if (!in) throw runtime_error("Failed to open " + filename);
    size_t v = 0;
    in >> v;
    return v;
}

int main(int argc, char* argv[]) {
    if (argc < 2 || argc > 5) {
        cerr << "Usage: " << argv[0] << " <n_timestamps> [epsilon] [dp_mechanism] [delta]" << endl;
        cerr << "  dp_mechanism: none (default), laplace, gaussian" << endl;
        cerr << "  delta: required for gaussian mechanism (e.g., 1e-5)" << endl;
        return 1;
    }

    CsvTimings timings("data/results/timings.trusted.summary.csv");
    const bool log_per_timestamp = (std::getenv("TERSE_LOG_PER_TIMESTAMP") != nullptr);

    size_t n_timestamps = stoull(argv[1]);
    double epsilon = (argc >= 3) ? stod(argv[2]) : 0.0;
    string dp_mechanism = (argc >= 4) ? string(argv[3]) : "none";
    double delta = (argc >= 5) ? stod(argv[4]) : 0.0;

    bool enable_dp = (dp_mechanism != "none");

    if (enable_dp && epsilon <= 0) {
        cerr << "Error: epsilon must be positive when DP is enabled" << endl;
        return 1;
    }

    if (dp_mechanism == "gaussian" && delta <= 0) {
        cerr << "Error: delta must be positive for Gaussian mechanism" << endl;
        return 1;
    }

    // Load metadata (for context fields, though summary ignores them)
    int64_t n_clients_meta = -1;
    size_t saved_n_timestamps = 0;
    size_t vector_dim = 0;

    {
        ScopeTimer t(timings, "trusted", "load_metadata",
                     -1, -1, -1, -1, (int64_t)n_timestamps);

        // Optional n_clients for context (best-effort)
        try { n_clients_meta = (int64_t)load_size_from_file("data/n_clients.txt"); } catch (...) {}

        saved_n_timestamps = load_size_from_file("data/n_timestamps.txt");
        vector_dim = load_size_from_file("data/vector_dim.txt");
    }

    if (saved_n_timestamps != n_timestamps) {
        throw runtime_error("Timestamp count mismatch");
    }

    TERSEParams params = TERSEParams::load("data/params.bin");
    TERSESystem system(params);

    TERSEServer server;
    {
        ScopeTimer t(timings, "trusted", "load_server_key",
                     -1, -1, (int64_t)vector_dim, n_clients_meta, (int64_t)n_timestamps);
        server = system.load_server_key("data/server_key.bin");
    }

    NativeInteger q_mod = system.get_context()->GetCryptoParameters()
                          ->GetElementParams()->GetParams()[0]->GetModulus();
    uint64_t q_val = q_mod.ConvertToInt();
    uint64_t t_plain = params.plain_modulus;

    cout << "=== TERSE Decryption (summary CSV -> data/results/timings.trusted.summary.csv) ===" << endl;
    cout << "DP: " << (enable_dp ? "ENABLED" : "DISABLED") << endl;
    if (enable_dp) {
        cout << "  Mechanism: " << dp_mechanism << endl;
        cout << "  Epsilon: " << epsilon << endl;
        if (dp_mechanism == "gaussian") cout << "  Delta: " << delta << endl;
    }
    cout << "Processing " << n_timestamps << " timestamps..." << endl;

    bool all_passed = true;

    {
        ScopeTimer t_total(timings, "trusted", "decrypt_total",
                           -1, -1, (int64_t)vector_dim, n_clients_meta, (int64_t)n_timestamps);

        for (size_t ts_idx = 0; ts_idx < n_timestamps; ts_idx++) {
            std::unique_ptr<ScopeTimer> t_ts_total;
            if (log_per_timestamp) {
                t_ts_total = std::make_unique<ScopeTimer>(
                    timings, "trusted", "timestamp_total",
                    -1, (int64_t)ts_idx, (int64_t)vector_dim, n_clients_meta, (int64_t)n_timestamps
                );
            }

            AggregatedCiphertext agg_ct;
            {
                std::unique_ptr<ScopeTimer> t_io;
                if (log_per_timestamp) {
                    t_io = std::make_unique<ScopeTimer>(
                        timings, "trusted", "untrusted_io_load_aggregate",
                        -1, (int64_t)ts_idx, (int64_t)vector_dim, n_clients_meta, (int64_t)n_timestamps
                    );
                }
                agg_ct = load_aggregated_ciphertext_untrusted(ts_idx);
            }

            vector<uint32_t> decrypted_sum(vector_dim);
            {
                std::unique_ptr<ScopeTimer> t_dec;
                if (log_per_timestamp) {
                    t_dec = std::make_unique<ScopeTimer>(
                        timings, "trusted", "trusted_decrypt",
                        -1, (int64_t)ts_idx, (int64_t)vector_dim, n_clients_meta, (int64_t)n_timestamps
                    );
                }

                for (size_t coord = 0; coord < vector_dim; coord++) {
                    size_t stream_idx = ts_idx * vector_dim + coord;

                    NativeInteger sum = agg_ct.ciphertext[coord].ModAdd(
                        server.precomputed_p_prime[stream_idx], q_mod);

                    uint64_t raw = sum.ConvertToInt();

                    int64_t signed_val;
                    if (raw > q_val / 2) {
                        signed_val = static_cast<int64_t>(raw) - static_cast<int64_t>(q_val);
                    } else {
                        signed_val = static_cast<int64_t>(raw);
                    }

                    int64_t result = signed_val % static_cast<int64_t>(t_plain);
                    if (result < 0) result += static_cast<int64_t>(t_plain);

                    decrypted_sum[coord] = static_cast<uint32_t>(result);
                }
            }

            if (enable_dp) {
                vector<double> final_result;
                {
                    std::unique_ptr<ScopeTimer> t_dp;
                    if (log_per_timestamp) {
                        t_dp = std::make_unique<ScopeTimer>(
                            timings, "trusted", "trusted_dp_noise",
                            -1, (int64_t)ts_idx, (int64_t)vector_dim, n_clients_meta, (int64_t)n_timestamps
                        );
                    }

                    uint32_t sensitivity = (uint32_t)(t_plain - 1);

                    if (dp_mechanism == "laplace") {
                        final_result = add_laplace_noise(decrypted_sum, epsilon, sensitivity);
                    } else if (dp_mechanism == "gaussian") {
                        final_result = add_gaussian_noise(decrypted_sum, epsilon, delta, sensitivity);
                    } else {
                        cerr << "Unknown DP mechanism: " << dp_mechanism << endl;
                        return 1;
                    }
                }

                {
                    std::unique_ptr<ScopeTimer> t_save;
                    if (log_per_timestamp) {
                        t_save = std::make_unique<ScopeTimer>(
                            timings, "trusted", "save_noisy_sum",
                            -1, (int64_t)ts_idx, (int64_t)vector_dim, n_clients_meta, (int64_t)n_timestamps
                        );
                    }

                    string noisy_file = "data/noisy_sum_" + to_string(ts_idx) + ".txt";
                    ofstream noisy_out(noisy_file);
                    for (size_t coord = 0; coord < vector_dim; coord++) {
                        noisy_out << final_result[coord];
                        if (coord + 1 < vector_dim) noisy_out << ' ';
                    }
                    noisy_out << endl;
                }
            } else {
                std::unique_ptr<ScopeTimer> t_verify;
                if (log_per_timestamp) {
                    t_verify = std::make_unique<ScopeTimer>(
                        timings, "trusted", "verify_expected_sum",
                        -1, (int64_t)ts_idx, (int64_t)vector_dim, n_clients_meta, (int64_t)n_timestamps
                    );
                }

                string sum_file = "data/expected_sum_" + to_string(ts_idx) + ".txt";
                ifstream sum_in(sum_file);
                if (!sum_in) {
                    throw runtime_error("Failed to open " + sum_file);
                }

                for (size_t coord = 0; coord < vector_dim; coord++) {
                    uint64_t expected;
                    sum_in >> expected;
                    if (decrypted_sum[coord] != expected) {
                        cerr << "Timestamp " << ts_idx << " coord " << coord
                             << " FAILED: Expected " << expected
                             << ", Got " << decrypted_sum[coord] << endl;
                        all_passed = false;
                    }
                }
            }
        }
    }

    timings.flush();

    if (enable_dp) {
        cout << "Noisy results saved to data/noisy_sum_*.txt" << endl;
    } else {
        cout << "Verification: " << (all_passed ? "ALL PASSED" : "SOME FAILED") << endl;
    }

    return (enable_dp || all_passed) ? 0 : 1;
}
