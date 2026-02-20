#pragma once

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>

// Online mean/stddev via Welford's algorithm
struct OnlineStats {
    uint64_t n = 0;
    double mean = 0.0;
    double m2 = 0.0;
    uint64_t min_v = UINT64_MAX;
    uint64_t max_v = 0;

    void add(uint64_t x) {
        n++;
        min_v = std::min(min_v, x);
        max_v = std::max(max_v, x);

        double dx = (double)x - mean;
        mean += dx / (double)n;
        double dx2 = (double)x - mean;
        m2 += dx * dx2;
    }

    double stddev_sample() const {
        if (n <= 1) return 0.0;
        return std::sqrt(m2 / (double)(n - 1));
    }
};

struct OpKey {
    std::string component;
    std::string phase;

    bool operator==(const OpKey& o) const {
        return component == o.component && phase == o.phase;
    }
};

struct OpKeyHash {
    size_t operator()(const OpKey& k) const noexcept {
        size_t h1 = std::hash<std::string>{}(k.component);
        size_t h2 = std::hash<std::string>{}(k.phase);
        return h1 ^ (h2 << 1);
    }
};

class StatsCsvSink {
public:
    explicit StatsCsvSink(std::string path) : path_(std::move(path)) {}

    void add(const std::string& component, const std::string& phase, uint64_t duration_us) {
        std::lock_guard<std::mutex> lk(mu_);
        stats_[OpKey{component, phase}].add(duration_us);
    }

    void flush() {
        std::lock_guard<std::mutex> lk(mu_);
        const bool need_header = !file_exists_nonempty_();

        std::ofstream out(path_, std::ios::app);
        if (need_header) {
            out << "component,phase,count,mean_us,stddev_us,min_us,max_us,range_us\n";
        }

        for (const auto& kv : stats_) {
            const OpKey& k = kv.first;
            const OnlineStats& s = kv.second;

            const uint64_t min_us = (s.n ? s.min_v : 0);
            const uint64_t max_us = (s.n ? s.max_v : 0);
            const uint64_t range_us = (s.n ? (max_us - min_us) : 0);

            out << k.component << ","
                << k.phase << ","
                << s.n << ","
                << s.mean << ","
                << s.stddev_sample() << ","
                << min_us << ","
                << max_us << ","
                << range_us
                << "\n";
        }

        stats_.clear();
    }

    ~StatsCsvSink() {
        try { flush(); } catch (...) {}
    }

private:
    bool file_exists_nonempty_() const {
        std::ifstream in(path_, std::ios::binary);
        return in.good() && in.peek() != std::ifstream::traits_type::eof();
    }

    std::string path_;
    std::mutex mu_;
    std::unordered_map<OpKey, OnlineStats, OpKeyHash> stats_;
};

class StatsScopeTimer {
public:
    using Clock = std::chrono::steady_clock;

    StatsScopeTimer(StatsCsvSink& sink, std::string component, std::string phase)
        : sink_(sink),
          component_(std::move(component)),
          phase_(std::move(phase)),
          start_(Clock::now()) {}

    ~StatsScopeTimer() {
        auto end = Clock::now();
        uint64_t us = (uint64_t)std::chrono::duration_cast<std::chrono::microseconds>(end - start_).count();
        sink_.add(component_, phase_, us);
    }

private:
    StatsCsvSink& sink_;
    std::string component_;
    std::string phase_;
    Clock::time_point start_;
};
