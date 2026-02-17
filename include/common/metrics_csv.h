#pragma once
#include <chrono>
#include <cstdint>
#include <fstream>
#include <mutex>
#include <string>
#include <vector>

struct CsvEvent {
    uint64_t unix_ns = 0;
    std::string component;
    std::string phase;
    int64_t round = -1;
    int64_t timestamp = -1;
    int64_t chunk = -1;
    int64_t client_idx = -1;
    int64_t vector_dim = -1;
    int64_t n_clients = -1;
    uint64_t duration_us = 0;
};

class CsvSink {
public:
    explicit CsvSink(std::string path) : path_(std::move(path)) {}

    void add(CsvEvent e) {
        std::lock_guard<std::mutex> lk(mu_);
        buf_.push_back(std::move(e));
    }

    void flush() {
        std::lock_guard<std::mutex> lk(mu_);
        const bool need_header = !file_exists_nonempty_();
        std::ofstream out(path_, std::ios::app);
        if (need_header) {
            out << "unix_ns,component,phase,round,timestamp,chunk,client_idx,vector_dim,n_clients,duration_us\n";
        }
        for (const auto& e : buf_) {
            out << e.unix_ns << ","
                << e.component << ","
                << e.phase << ","
                << e.round << ","
                << e.timestamp << ","
                << e.chunk << ","
                << e.client_idx << ","
                << e.vector_dim << ","
                << e.n_clients << ","
                << e.duration_us
                << "\n";
        }
        buf_.clear();
    }

    ~CsvSink() {
        try { flush(); } catch (...) {}
    }

private:
    bool file_exists_nonempty_() const {
        std::ifstream in(path_, std::ios::binary);
        return in.good() && in.peek() != std::ifstream::traits_type::eof();
    }

    std::string path_;
    std::mutex mu_;
    std::vector<CsvEvent> buf_;
};

class ScopeTimer {
public:
    using Clock = std::chrono::steady_clock;
    ScopeTimer(CsvSink& sink, CsvEvent e)
        : sink_(sink), e_(std::move(e)), start_(Clock::now()) {}

    ~ScopeTimer() {
        auto end = Clock::now();
        e_.duration_us = (uint64_t)std::chrono::duration_cast<std::chrono::microseconds>(end - start_).count();
        sink_.add(std::move(e_));
    }

private:
    CsvSink& sink_;
    CsvEvent e_;
    Clock::time_point start_;
};
