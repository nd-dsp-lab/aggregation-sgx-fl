#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

#include "aes_common.h"

static void fill_dummy_update(std::vector<float>& v, uint32_t client_idx, uint32_t round_idx) {
    for (size_t i = 0; i < v.size(); ++i) {
        v[i] = (float)((client_idx + 1) * 1e-3 + (round_idx + 1) * 1e-6 + (double)(i % 1024) * 1e-7);
    }
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

    StatsCsvSink sink(kClientMetricsPath);

    {
        StatsScopeTimer t(sink, "aes_client", "setup_create_master_key_if_missing");
        create_master_key_16_if_missing(kMasterKeyPath);
    }

    uint8_t master_key[16];
    {
        StatsScopeTimer t(sink, "aes_client", "setup_load_master_key");
        load_master_key_16(kMasterKeyPath, master_key);
    }

    std::vector<std::array<uint8_t, 16>> client_keys(n_clients);
    {
        StatsScopeTimer t(sink, "aes_client", "setup_derive_all_client_keys");
        for (uint32_t c = 0; c < n_clients; ++c) {
            client_keys[c] = derive_client_key_16_hmacsha256(master_key, c);
        }
    }

    for (uint32_t r = 0; r < n_rounds; ++r) {
        {
            StatsScopeTimer t_round(sink, "aes_client", "round_total");

            for (uint32_t c = 0; c < n_clients; ++c) {
                std::vector<float> update(vector_dim);
                fill_dummy_update(update, c, r);

                uint8_t iv[16];
                if (RAND_bytes(iv, (int)sizeof(iv)) != 1) {
                    throw std::runtime_error("RAND_bytes failed (iv)");
                }

                const uint8_t* pt = (const uint8_t*)update.data();
                const size_t pt_len = update.size() * sizeof(float);

                std::vector<uint8_t> ct;
                {
                    StatsScopeTimer t(sink, "aes_client", "encrypt_vector");
                    ct = aes128ctr_crypt(client_keys[c].data(), iv, pt, pt_len);
                }

                AesCtHeader hdr;
                hdr.round_idx = r;
                hdr.client_idx = c;
                hdr.vector_dim = vector_dim;
                std::memcpy(hdr.iv, iv, sizeof(iv));
                hdr.ct_bytes = (uint64_t)ct.size();

                const std::string path = ct_path(r, c);
                {
                    StatsScopeTimer t(sink, "aes_client", "write_ct_file");
                    save_ciphertext_file(path, hdr, ct);
                }
            }
        }
    }

    sink.flush();
    (void)vector_dim; // parameters still used for work sizing; suppress unused warnings if you refactor later
    return 0;
}
