#include <algorithm>
#include <cstdint>
#include <numeric>
#include <random>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

#include "aes_common.h"


static inline void add_in_place(std::vector<double>& acc, const float* x, size_t n) {
    for (size_t i = 0; i < n; ++i) acc[i] += (double)x[i];
}

int main(int argc, char** argv) {
    uint32_t n_clients = kDefaultNClients;
    uint32_t n_rounds = kDefaultNRounds;
    uint32_t vector_dim = kDefaultVectorDim;

    for (int i = 1; i < argc; ++i) {
        if (arg_eq(argv[i], "--n_clients")) n_clients = read_u32_flag(argc, argv, i);
        else if (arg_eq(argv[i], "--n_rounds")) n_rounds = read_u32_flag(argc, argv, i);
        else if (arg_eq(argv[i], "--vector_dim")) vector_dim = read_u32_flag(argc, argv, i);
        else throw std::runtime_error(std::string("unknown arg: ") + argv[i]);
    }

    ensure_dir_exists(kDataDir);
    ensure_dir_exists(kResultsDir);

    StatsCsvSink sink(kTrustedMetricsPath);

    {
        StatsScopeTimer t(sink, "aes_trusted", "setup_create_master_key_if_missing");
        create_master_key_16_if_missing(kMasterKeyPath);
    }

    uint8_t master_key[16];
    {
        StatsScopeTimer t(sink, "aes_trusted", "setup_load_master_key");
        load_master_key_16(kMasterKeyPath, master_key);
    }

    std::unordered_map<uint32_t, std::array<uint8_t, 16>> key_store;
    key_store.reserve((size_t)n_clients);

    {
        StatsScopeTimer t(sink, "aes_trusted", "setup_build_key_store");
        for (uint32_t c = 0; c < n_clients; ++c) {
            key_store.emplace(c, derive_client_key_16_hmacsha256(master_key, c));
        }
    }

    std::vector<uint32_t> order(n_clients);
    std::iota(order.begin(), order.end(), 0u);

    // Fixed seed => reproducible benchmark ordering.
    std::mt19937 rng(12345);

    for (uint32_t r = 0; r < n_rounds; ++r) {
        StatsScopeTimer t_round(sink, "aes_trusted", "round_total");

        std::shuffle(order.begin(), order.end(), rng);

        std::vector<double> acc(vector_dim, 0.0);

        for (uint32_t j = 0; j < n_clients; ++j) {
            const uint32_t file_c = order[j];
            const std::string path = ct_path(r, file_c);

            AesCtHeader hdr;
            std::vector<uint8_t> ct;
            {
                StatsScopeTimer t(sink, "aes_trusted", "read_ct_file");
                load_ciphertext_file(path, &hdr, &ct);
            }

            if (hdr.round_idx != r || hdr.vector_dim != vector_dim) {
                throw std::runtime_error("header mismatch in " + path);
            }
            if (hdr.client_idx >= n_clients) {
                throw std::runtime_error("header client_idx out of range in " + path);
            }

            const std::array<uint8_t, 16>* key_ptr = nullptr;
            {
                StatsScopeTimer t(sink, "aes_trusted", "lookup_client_key");
                auto it = key_store.find(hdr.client_idx);
                if (it == key_store.end()) {
                    throw std::runtime_error("missing key for client_idx=" + std::to_string(hdr.client_idx));
                }
                key_ptr = &it->second;
            }

            std::vector<uint8_t> pt;
            {
                StatsScopeTimer t(sink, "aes_trusted", "decrypt_vector");
                pt = aes128ctr_crypt(key_ptr->data(), hdr.iv, ct.data(), ct.size());
            }

            const size_t expected_bytes = (size_t)vector_dim * sizeof(float);
            if (pt.size() != expected_bytes) {
                throw std::runtime_error("bad plaintext size in " + path);
            }

            const float* vec = (const float*)pt.data();
            {
                StatsScopeTimer t(sink, "aes_trusted", "add_vector");
                add_in_place(acc, vec, vector_dim);
            }
        }
    }

    sink.flush();
    return 0;
}
