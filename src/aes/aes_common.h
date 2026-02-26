#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

// Summary-only metrics sink/timer (mean/stddev/range)
#include "common/metrics_stats_csv.h"

// =========================
// Hard-coded paths (benchmark convenience)
// =========================
static constexpr const char* kDataDir    = "data";
static constexpr const char* kResultsDir = "data/results";

// Separate CSVs to avoid interleaving client and trusted output.
static constexpr const char* kClientMetricsPath  = "data/results/aes_client_metrics.csv";
static constexpr const char* kTrustedMetricsPath = "data/results/aes_trusted_metrics.csv";

// Master key stored on disk (shared secret for the benchmark).
static constexpr const char* kMasterKeyPath = "data/aes_master_key.bin";

// Defaults (override via CLI)
static constexpr uint32_t kDefaultNClients  = 1000;
static constexpr uint32_t kDefaultNRounds   = 1;
static constexpr uint32_t kDefaultVectorDim = 62000;

// =========================
// Minimal CLI parsing
// =========================
static inline bool arg_eq(const char* a, const char* b) { return std::string(a) == std::string(b); }

static inline uint32_t read_u32_flag(int argc, char** argv, int& i) {
    if (i + 1 >= argc) throw std::runtime_error(std::string("missing value after ") + argv[i]);
    return (uint32_t)std::stoul(std::string(argv[++i]));
}

// =========================
// Files / directories
// =========================
static inline bool file_exists_nonempty(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    return in.good() && in.peek() != std::ifstream::traits_type::eof();
}

static inline void ensure_dir_exists(const std::string& dir) {
    std::filesystem::create_directories(std::filesystem::path(dir));
}

// =========================
// Master key (16 bytes) + per-client key derivation
// - Master key is stored on disk (benchmark).
// - Per-client key = HMAC-SHA256(master_key, "AES-CLIENT-KEY"||client_idx_le)[:16]
// =========================
static inline void create_master_key_16_if_missing(const std::string& path) {
    if (file_exists_nonempty(path)) return;

    // Ensure parent directory exists.
    {
        std::filesystem::path p(path);
        if (!p.parent_path().empty()) std::filesystem::create_directories(p.parent_path());
    }

    uint8_t mk[16];
    if (RAND_bytes(mk, (int)sizeof(mk)) != 1) throw std::runtime_error("RAND_bytes failed (master key)");

    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out.good()) throw std::runtime_error("failed to open for write: " + path);
    out.write((const char*)mk, (std::streamsize)sizeof(mk));
    out.close();
}

static inline void load_master_key_16(const std::string& path, uint8_t out_key16[16]) {
    if (!file_exists_nonempty(path)) throw std::runtime_error("master key missing/empty: " + path);

    std::ifstream in(path, std::ios::binary);
    if (!in.good()) throw std::runtime_error("failed to open: " + path);

    in.read((char*)out_key16, 16);
    if (in.gcount() != 16) throw std::runtime_error("master key wrong size (need 16 bytes): " + path);
}

static inline std::array<uint8_t, 16> derive_client_key_16_hmacsha256(
    const uint8_t master_key16[16],
    uint32_t client_idx) {

    uint8_t msg[14 + 4];
    const char* label = "AES-CLIENT-KEY"; // 14 bytes
    std::memcpy(msg, label, 14);

    // client_idx little-endian
    msg[14] = (uint8_t)(client_idx & 0xFF);
    msg[15] = (uint8_t)((client_idx >> 8) & 0xFF);
    msg[16] = (uint8_t)((client_idx >> 16) & 0xFF);
    msg[17] = (uint8_t)((client_idx >> 24) & 0xFF);

    unsigned int out_len = 0;
    uint8_t digest[32];

    if (!HMAC(EVP_sha256(), master_key16, 16, msg, sizeof(msg), digest, &out_len)) {
        throw std::runtime_error("HMAC failed");
    }
    if (out_len < 16) throw std::runtime_error("HMAC output too short");

    std::array<uint8_t, 16> k{};
    std::memcpy(k.data(), digest, 16);
    return k;
}

// =========================
// AES-128-CTR (no authentication)
// =========================
static inline std::vector<uint8_t> aes128ctr_crypt(
    const uint8_t key16[16],
    const uint8_t iv16[16],
    const uint8_t* in,
    size_t in_len) {

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    std::vector<uint8_t> out(in_len);
    int outl1 = 0;
    int outl2 = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), nullptr, key16, iv16) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex failed");
    }
    if (EVP_EncryptUpdate(ctx, out.data(), &outl1, in, (int)in_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptUpdate failed");
    }
    if (EVP_EncryptFinal_ex(ctx, out.data() + outl1, &outl2) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
    }

    EVP_CIPHER_CTX_free(ctx);
    out.resize((size_t)(outl1 + outl2));
    return out;
}

// =========================
// Ciphertext file format + helpers
// =========================
static constexpr uint32_t kAesWireMagic   = 0x41455331; // "AES1"
static constexpr uint32_t kAesWireVersion = 1;

#pragma pack(push, 1)
struct AesCtHeader {
    uint32_t magic = kAesWireMagic;
    uint32_t version = kAesWireVersion;
    uint32_t round_idx = 0;
    uint32_t client_idx = 0;
    uint32_t vector_dim = 0;
    uint32_t reserved0 = 0;
    uint8_t iv[16] = {0};
    uint64_t ct_bytes = 0;
};
#pragma pack(pop)

static inline void write_all(FILE* f, const void* p, size_t n) {
    if (std::fwrite(p, 1, n, f) != n) throw std::runtime_error("write_all failed");
}

static inline void read_all(FILE* f, void* p, size_t n) {
    if (std::fread(p, 1, n, f) != n) throw std::runtime_error("read_all failed");
}

static inline std::string ct_path(uint32_t round_idx, uint32_t client_idx) {
    char buf[512];
    std::snprintf(buf, sizeof(buf), "%s/aes_ct_r%06u_c%06u.bin", kDataDir, round_idx, client_idx);
    return std::string(buf);
}

static inline void save_ciphertext_file(const std::string& path, const AesCtHeader& hdr, const std::vector<uint8_t>& ct) {
    FILE* f = std::fopen(path.c_str(), "wb");
    if (!f) throw std::runtime_error("open for write failed: " + path);
    write_all(f, &hdr, sizeof(hdr));
    if (!ct.empty()) write_all(f, ct.data(), ct.size());
    std::fclose(f);
}

static inline void load_ciphertext_file(const std::string& path, AesCtHeader* hdr_out, std::vector<uint8_t>* ct_out) {
    FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) throw std::runtime_error("open for read failed: " + path);

    AesCtHeader hdr{};
    read_all(f, &hdr, sizeof(hdr));
    if (hdr.magic != kAesWireMagic || hdr.version != kAesWireVersion) {
        std::fclose(f);
        throw std::runtime_error("bad header (magic/version) in: " + path);
    }

    std::vector<uint8_t> ct((size_t)hdr.ct_bytes);
    if (!ct.empty()) read_all(f, ct.data(), ct.size());
    std::fclose(f);

    *hdr_out = hdr;
    *ct_out = std::move(ct);
}
