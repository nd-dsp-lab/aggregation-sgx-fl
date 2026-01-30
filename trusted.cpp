// trusted.cpp - Correct implementation matching the paper
#include "terse.h"
#include <iostream>
#include <fstream>
#include <chrono>

using namespace std;
using namespace std::chrono;

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

int main(int argc, char* argv[]) {
    if (argc != 2) {
        cerr << "Usage: " << argv[0] << " <n_timestamps>" << endl;
        return 1;
    }

    size_t n_timestamps = stoull(argv[1]);

    TERSEParams params = TERSEParams::load("data/params.bin");
    TERSESystem system(params);
    TERSEServer server = system.load_server_key("data/server_key.bin");

    ifstream n_ts_file("data/n_timestamps.txt");
    size_t saved_n_timestamps;
    n_ts_file >> saved_n_timestamps;
    n_ts_file.close();

    if (saved_n_timestamps != n_timestamps) {
        throw runtime_error("Timestamp count mismatch");
    }

    ifstream vd_file("data/vector_dim.txt");
    size_t vector_dim;
    vd_file >> vector_dim;
    vd_file.close();

    NativeInteger q_mod = system.get_context()->GetCryptoParameters()
                          ->GetElementParams()->GetParams()[0]->GetModulus();
    uint64_t q_val = q_mod.ConvertToInt();
    uint64_t t = params.plain_modulus;

    cout << "=== TERSE Decryption ===" << endl;
    cout << "Processing " << n_timestamps << " timestamps..." << endl;

    double total_untrusted_io_ms = 0;
    double total_trusted_decrypt_ms = 0;
    bool all_passed = true;

    for (size_t ts_idx = 0; ts_idx < n_timestamps; ts_idx++) {
        // UNTRUSTED: Load aggregated ciphertext (ŷ from server)
        auto io_start = high_resolution_clock::now();
        AggregatedCiphertext agg_ct = load_aggregated_ciphertext_untrusted(ts_idx);
        auto io_end = high_resolution_clock::now();
        double io_time_ms = duration_cast<nanoseconds>(io_end - io_start).count() / 1e6;
        total_untrusted_io_ms += io_time_ms;

        // TRUSTED: Decrypt using enclave's p' material
        // Dec(st_enc, ts, ŷ) := [[p'_θ[τ] + ŷ]_q]_t
        auto decrypt_start = high_resolution_clock::now();

        vector<uint32_t> decrypted_sum(vector_dim);
        for (size_t coord = 0; coord < vector_dim; coord++) {
            size_t stream_idx = ts_idx * vector_dim + coord;

            // Add p'[stream_idx] to the aggregated ciphertext ŷ
            NativeInteger sum = agg_ct.ciphertext[coord].ModAdd(
                server.precomputed_p_prime[stream_idx], q_mod);

            uint64_t raw = sum.ConvertToInt();

            // Center around zero for signed reduction
            int64_t signed_val;
            if (raw > q_val / 2) {
                signed_val = static_cast<int64_t>(raw) - static_cast<int64_t>(q_val);
            } else {
                signed_val = static_cast<int64_t>(raw);
            }

            // Reduce mod t
            int64_t result = signed_val % static_cast<int64_t>(t);
            if (result < 0) {
                result += static_cast<int64_t>(t);
            }

            decrypted_sum[coord] = static_cast<uint32_t>(result);
        }

        auto decrypt_end = high_resolution_clock::now();
        double decrypt_time_ms = duration_cast<nanoseconds>(decrypt_end - decrypt_start).count() / 1e6;
        total_trusted_decrypt_ms += decrypt_time_ms;

        // Verify
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
        sum_in.close();
    }

    cout << "\n=== Performance Results ===" << endl;
    cout << "Per-Timestamp Breakdown:" << endl;
    cout << "  Untrusted I/O (avg): " << (total_untrusted_io_ms / n_timestamps) << " ms" << endl;
    cout << "  Trusted decrypt (avg): " << (total_trusted_decrypt_ms / n_timestamps) << " ms" << endl;
    cout << "  Total per timestamp: " << ((total_untrusted_io_ms + total_trusted_decrypt_ms) / n_timestamps) << " ms" << endl;

    cout << "\nTotal Times:" << endl;
    cout << "  Untrusted I/O: " << total_untrusted_io_ms << " ms" << endl;
    cout << "  Trusted decryption: " << total_trusted_decrypt_ms << " ms" << endl;
    cout << "  Combined runtime: " << (total_untrusted_io_ms + total_trusted_decrypt_ms) << " ms" << endl;

    cout << "\nVerification: " << (all_passed ? "ALL PASSED" : "SOME FAILED") << endl;

    return all_passed ? 0 : 1;
}