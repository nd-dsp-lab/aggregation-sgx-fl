// trusted_round.cpp (SUMMARY CSV timings)
//
// Writes aggregated summary timing stats to:
//   data/results/timings.trusted_round.summary.csv
//
// CSV columns:
//   component,phase,count,mean_us,stddev_us,min_us,max_us,range_us
//
// Notes:
// - `ts` is used as an index in code, but summary output aggregates only by (component, phase).
//
// Optional env vars:
// - TERSE_LOG_PER_TIMESTAMP=1  -> include per-ts phases in the summary inside decrypt_range

#include "terse/terse.h"
#include "common/terse_timings_summary.h"

#include <cmath>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <memory>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <cstdlib>

using namespace std;

static int64_t load_i64_from_file_or(const string& filename, int64_t fallback) {
    ifstream in(filename);
    if (!in) return fallback;
    long long v = 0;
    in >> v;
    if (!in) return fallback;
    return (int64_t)v;
}

// ---------------------- app code ----------------------

struct AggregatedCiphertext {
    vector<NativeInteger> ciphertext;
};

struct DPConfig {
    // 0 none, 1 laplace, 2 gaussian
    int mech = 0;
    double epsilon = 0.0;
    double delta = 0.0;       // gaussian only
    uint32_t sensitivity = 0; // in quantized integer units
};

static AggregatedCiphertext load_aggregated_ciphertext_untrusted(size_t ts_idx,
                                                                 size_t expected_vector_dim) {
    string agg_file = "data/encrypted_aggregate_" + to_string(ts_idx) + ".bin";
    ifstream agg_in(agg_file, ios::binary);
    if (!agg_in) {
        throw runtime_error("Failed to open " + agg_file);
    }

    size_t vector_dim_in_file = 0;
    agg_in.read(reinterpret_cast<char*>(&vector_dim_in_file), sizeof(vector_dim_in_file));
    if (!agg_in) {
        throw runtime_error("Failed reading vector_dim from " + agg_file);
    }

    if (vector_dim_in_file != expected_vector_dim) {
        throw runtime_error(
            "Vector dim mismatch in " + agg_file +
            " (file: " + to_string(vector_dim_in_file) +
            ", expected: " + to_string(expected_vector_dim) + ")"
        );
    }

    AggregatedCiphertext agg_ct;
    agg_ct.ciphertext.resize(expected_vector_dim);

    vector<uint64_t> buffer(expected_vector_dim);
    agg_in.read(reinterpret_cast<char*>(buffer.data()),
                expected_vector_dim * sizeof(uint64_t));
    if (!agg_in) {
        throw runtime_error("Failed reading ciphertext payload from " + agg_file);
    }

    for (size_t i = 0; i < expected_vector_dim; i++) {
        agg_ct.ciphertext[i] = NativeInteger(buffer[i]);
    }

    return agg_ct;
}

static void save_decrypted_sum(size_t ts_idx, const vector<uint32_t>& decrypted_sum) {
    string out_file = "data/decrypted_" + to_string(ts_idx) + ".bin";
    ofstream out(out_file, ios::binary);
    if (!out) {
        throw runtime_error("Failed to open " + out_file + " for writing");
    }

    out.write(reinterpret_cast<const char*>(decrypted_sum.data()),
              decrypted_sum.size() * sizeof(uint32_t));
    if (!out) {
        throw runtime_error("Failed writing " + out_file);
    }
}

static inline int64_t mod_to_signed(int64_t x_mod_t, int64_t t) {
    int64_t half = t / 2;
    if (x_mod_t > half) return x_mod_t - t;
    return x_mod_t;
}

static inline uint32_t signed_to_mod_u32(int64_t x, uint64_t t) {
    int64_t tm = static_cast<int64_t>(t);
    int64_t r = x % tm;
    if (r < 0) r += tm;
    return static_cast<uint32_t>(r);
}

static double sample_laplace(std::mt19937_64& gen, double scale) {
    std::exponential_distribution<double> exp_dist(1.0 / scale);
    std::uniform_real_distribution<double> unif(0.0, 1.0);

    double noise = exp_dist(gen);
    if (unif(gen) < 0.5) noise = -noise;
    return noise;
}

static double sample_gaussian(std::mt19937_64& gen, double sigma) {
    std::normal_distribution<double> gauss(0.0, sigma);
    return gauss(gen);
}

static void apply_dp_inplace(vector<uint32_t>& vec_mod_t, uint64_t t, const DPConfig& dp) {
    if (dp.mech == 0) return;

    if (dp.epsilon <= 0.0) {
        throw runtime_error("DP: epsilon must be > 0");
    }
    if (dp.sensitivity == 0) {
        throw runtime_error("DP: sensitivity must be > 0");
    }

    std::random_device rd;
    std::mt19937_64 gen(rd());

    double scale_or_sigma = 0.0;

    if (dp.mech == 1) {
        scale_or_sigma = static_cast<double>(dp.sensitivity) / dp.epsilon;
        if (!(scale_or_sigma > 0.0)) throw runtime_error("DP: invalid Laplace scale");
    } else if (dp.mech == 2) {
        if (!(dp.delta > 0.0 && dp.delta < 1.0)) {
            throw runtime_error("DP: delta must be in (0,1) for Gaussian");
        }
        scale_or_sigma =
            static_cast<double>(dp.sensitivity) *
            std::sqrt(2.0 * std::log(1.25 / dp.delta)) / dp.epsilon;
        if (!(scale_or_sigma > 0.0)) throw runtime_error("DP: invalid Gaussian sigma");
    } else {
        throw runtime_error("DP: unknown mechanism code");
    }

    int64_t t_i64 = static_cast<int64_t>(t);

    for (size_t i = 0; i < vec_mod_t.size(); i++) {
        int64_t x_mod = static_cast<int64_t>(vec_mod_t[i]); // in [0,t)
        int64_t x_signed = mod_to_signed(x_mod, t_i64);

        double noise = 0.0;
        if (dp.mech == 1) {
            noise = sample_laplace(gen, scale_or_sigma);
        } else {
            noise = sample_gaussian(gen, scale_or_sigma);
        }

        int64_t noisy = static_cast<int64_t>(llround(static_cast<double>(x_signed) + noise));
        vec_mod_t[i] = signed_to_mod_u32(noisy, t);
    }
}

static void decrypt_range(
    size_t start_ts,
    size_t n_chunks,
    size_t vector_dim,
    TERSESystem& system,
    TERSEServer& server,
    const TERSEParams& params,
    const DPConfig& dp,
    CsvTimings& timings,
    bool log_per_timestamp,
    int64_t n_clients_meta,
    int64_t n_timestamps_meta
) {
    NativeInteger q_mod = system.get_context()->GetCryptoParameters()
                          ->GetElementParams()->GetParams()[0]->GetModulus();
    uint64_t q_val = q_mod.ConvertToInt();
    uint64_t t = params.plain_modulus;

    ScopeTimer t_range(timings, "trusted_round", "decrypt_range_total",
                       -1, (int64_t)start_ts, (int64_t)vector_dim, n_clients_meta, n_timestamps_meta);

    for (size_t k = 0; k < n_chunks; k++) {
        size_t ts_idx = start_ts + k;

        std::unique_ptr<ScopeTimer> t_ts_total;
        if (log_per_timestamp) {
            t_ts_total = std::make_unique<ScopeTimer>(
                timings, "trusted_round", "timestamp_total",
                -1, (int64_t)ts_idx, (int64_t)vector_dim, n_clients_meta, n_timestamps_meta
            );
        }

        AggregatedCiphertext agg_ct;
        {
            std::unique_ptr<ScopeTimer> t_io;
            if (log_per_timestamp) {
                t_io = std::make_unique<ScopeTimer>(
                    timings, "trusted_round", "untrusted_io_load_aggregate",
                    -1, (int64_t)ts_idx, (int64_t)vector_dim, n_clients_meta, n_timestamps_meta
                );
            }
            agg_ct = load_aggregated_ciphertext_untrusted(ts_idx, vector_dim);
        }

        vector<uint32_t> decrypted_sum(vector_dim);
        {
            std::unique_ptr<ScopeTimer> t_dec;
            if (log_per_timestamp) {
                t_dec = std::make_unique<ScopeTimer>(
                    timings, "trusted_round", "trusted_decrypt",
                    -1, (int64_t)ts_idx, (int64_t)vector_dim, n_clients_meta, n_timestamps_meta
                );
            }

            for (size_t coord = 0; coord < vector_dim; coord++) {
                size_t stream_idx = ts_idx * vector_dim + coord;

                NativeInteger sum = agg_ct.ciphertext[coord].ModAdd(
                    server.precomputed_p_prime[stream_idx], q_mod);

                uint64_t raw = sum.ConvertToInt();

                int64_t signed_val = (raw > q_val / 2)
                    ? (static_cast<int64_t>(raw) - static_cast<int64_t>(q_val))
                    : static_cast<int64_t>(raw);

                int64_t result = signed_val % static_cast<int64_t>(t);
                if (result < 0) result += static_cast<int64_t>(t);

                decrypted_sum[coord] = static_cast<uint32_t>(result);
            }
        }

        {
            std::unique_ptr<ScopeTimer> t_dp;
            if (log_per_timestamp) {
                t_dp = std::make_unique<ScopeTimer>(
                    timings, "trusted_round", "trusted_dp_apply",
                    -1, (int64_t)ts_idx, (int64_t)vector_dim, n_clients_meta, n_timestamps_meta
                );
            }
            apply_dp_inplace(decrypted_sum, t, dp);
        }

        {
            std::unique_ptr<ScopeTimer> t_save;
            if (log_per_timestamp) {
                t_save = std::make_unique<ScopeTimer>(
                    timings, "trusted_round", "save_decrypted_sum",
                    -1, (int64_t)ts_idx, (int64_t)vector_dim, n_clients_meta, n_timestamps_meta
                );
            }
            save_decrypted_sum(ts_idx, decrypted_sum);
        }
    }
}

static DPConfig parse_dp_args_or_default(std::istringstream& iss) {
    DPConfig dp;

    int mech = 0;
    double eps = 0.0;
    double del = 0.0;
    uint64_t sens64 = 0;

    if (!(iss >> mech)) {
        return dp; // none
    }
    if (!(iss >> eps >> del >> sens64)) {
        throw runtime_error("bad_dp_args");
    }

    dp.mech = mech;
    dp.epsilon = eps;
    dp.delta = del;
    dp.sensitivity = static_cast<uint32_t>(sens64);
    return dp;
}

int main(int argc, char* argv[]) {
    std::ios::sync_with_stdio(false);
    std::cin.tie(nullptr);

    CsvTimings timings("data/results/timings.trusted_round.summary.csv");
    const bool log_per_timestamp = (std::getenv("TERSE_LOG_PER_TIMESTAMP") != nullptr);

    // Best-effort metadata for context columns (ignored by summary logger, but kept for call-site compatibility)
    const int64_t n_clients_meta = load_i64_from_file_or("data/n_clients.txt", -1);
    const int64_t n_timestamps_meta = load_i64_from_file_or("data/n_timestamps.txt", -1);

    TERSEParams params;
    TERSESystem* system_ptr = nullptr;
    TERSESystem system_dummy(TERSEParams(4096, 65537, 0, HEStd_128_classic, 3.2)); // never used; avoids default ctor issues
    (void)system_dummy;

    {
        ScopeTimer t(timings, "trusted_round", "load_params",
                     -1, -1, -1, n_clients_meta, n_timestamps_meta);
        params = TERSEParams::load("data/params.bin");
    }

    TERSESystem system(params);
    system_ptr = &system;

    TERSEServer server;
    {
        ScopeTimer t(timings, "trusted_round", "load_server_key",
                     -1, -1, -1, n_clients_meta, n_timestamps_meta);
        server = system.load_server_key("data/server_key.bin");
    }

    // One-shot mode:
    // trusted_round <start_ts> <n_chunks> <vector_dim> [dp_mech epsilon delta sensitivity]
    if (argc == 4 || argc == 8) {
        size_t start_ts   = stoull(argv[1]);
        size_t n_chunks   = stoull(argv[2]);
        size_t vector_dim = stoull(argv[3]);

        DPConfig dp;
        if (argc == 8) {
            dp.mech = stoi(argv[4]);
            dp.epsilon = stod(argv[5]);
            dp.delta = stod(argv[6]);
            dp.sensitivity = static_cast<uint32_t>(stoull(argv[7]));
        }

        {
            ScopeTimer t(timings, "trusted_round", "oneshot_total",
                         -1, (int64_t)start_ts, (int64_t)vector_dim, n_clients_meta, n_timestamps_meta);

            decrypt_range(start_ts, n_chunks, vector_dim, *system_ptr, server, params, dp,
                          timings, log_per_timestamp, n_clients_meta, n_timestamps_meta);
        }

        timings.flush();
        return 0;
    }

    // Persistent service mode (no argv):
    // Commands on stdin:
    // - DECRYPT <start_ts> <n_chunks> <vector_dim> <dp_mech> <epsilon> <delta> <sensitivity>
    // - QUIT
    //
    // Responses on stdout:
    // - OK
    // - ERR <message>
    string cmd;
    string line;

    while (true) {
        if (!(cin >> cmd)) break;

        if (cmd == "QUIT") {
            cout << "OK\n" << std::flush;
            timings.flush();
            return 0;
        }

        if (cmd == "DECRYPT") {
            getline(cin, line);
            std::istringstream iss(line);

            size_t start_ts = 0;
            size_t n_chunks = 0;
            size_t vector_dim = 0;

            if (!(iss >> start_ts >> n_chunks >> vector_dim)) {
                cout << "ERR bad_args\n" << std::flush;
                continue;
            }

            DPConfig dp;
            try {
                dp = parse_dp_args_or_default(iss);
            } catch (const exception& e) {
                cout << "ERR " << e.what() << "\n" << std::flush;
                continue;
            }

            try {
                ScopeTimer t_cmd(timings, "trusted_round", "service_decrypt_command_total",
                                 -1, (int64_t)start_ts, (int64_t)vector_dim, n_clients_meta, n_timestamps_meta);

                decrypt_range(start_ts, n_chunks, vector_dim, *system_ptr, server, params, dp,
                              timings, log_per_timestamp, n_clients_meta, n_timestamps_meta);

                cout << "OK\n" << std::flush;
            } catch (const exception& e) {
                cout << "ERR " << e.what() << "\n" << std::flush;
            }
            continue;
        }

        cout << "ERR unknown_command\n" << std::flush;
    }

    timings.flush();
    return 0;
}
