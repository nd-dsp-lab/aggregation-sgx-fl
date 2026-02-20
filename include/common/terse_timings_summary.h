#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <utility>

// Reuse the summary sink used in AES.
#include "common/metrics_stats_csv.h"

// Drop-in replacement for your existing CsvTimings, but summary-only.
// It ignores all fields except (component, phase, duration_us).
class CsvTimings {
public:
    explicit CsvTimings(std::string path) : sink_(std::move(path)) {}

    void log_event(uint64_t /*unix_ns*/,
                   const std::string& component,
                   const std::string& phase,
                   int64_t /*client_idx*/,
                   int64_t /*ts*/,
                   int64_t /*vector_dim*/,
                   int64_t /*n_clients*/,
                   int64_t /*n_timestamps*/,
                   uint64_t duration_us) {
        sink_.add(component, phase, duration_us);
    }

    void flush() { sink_.flush(); }

    ~CsvTimings() {
        try { flush(); } catch (...) {}
    }

private:
    StatsCsvSink sink_;
};

// Drop-in replacement for your existing ScopeTimer.
// Keeps the same constructor signature so you don't have to touch call sites.
class ScopeTimer {
public:
    using Clock = std::chrono::steady_clock;

    ScopeTimer(CsvTimings& timings,
               std::string component,
               std::string phase,
               int64_t /*client_idx*/,
               int64_t /*ts*/,
               int64_t /*vector_dim*/,
               int64_t /*n_clients*/,
               int64_t /*n_timestamps*/)
        : timings_(timings),
          component_(std::move(component)),
          phase_(std::move(phase)),
          start_(Clock::now()) {}

    ~ScopeTimer() {
        auto end = Clock::now();
        uint64_t us = (uint64_t)std::chrono::duration_cast<std::chrono::microseconds>(end - start_).count();

        // These extra fields are ignored by CsvTimings in summary mode.
        timings_.log_event(/*unix_ns=*/0,
                           component_, phase_,
                           /*client_idx=*/-1,
                           /*ts=*/-1,
                           /*vector_dim=*/-1,
                           /*n_clients=*/-1,
                           /*n_timestamps=*/-1,
                           us);
    }

private:
    CsvTimings& timings_;
    std::string component_;
    std::string phase_;
    Clock::time_point start_;
};
