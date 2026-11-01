#pragma once

#include "process_tracker.hpp"
#include <string>
#include <vector>
#include <cstdint>

namespace r2e {

struct ForensicReport {
    pid_t pid{0};
    std::string process_name;
    std::string cmdline;
    std::string timestamp;
    std::string action_taken;
    bool reversal_success{false};
    std::string encryption_algorithm_suspected;
    std::string identified_key_or_keystream;
    size_t total_files_affected{0};
    std::vector<std::string> sample_files;
    double average_entropy{0.0};
    std::string sample_ciphertext_hex;
};

class ForensicsLogger {
public:
    explicit ForensicsLogger(const std::string& log_filepath = "r2e_forensic_log.json");
    void log_incident(const ForensicReport& report);
    const std::string& get_log_filepath() const { return log_filepath_; }

private:
    std::string log_filepath_;
    std::mutex log_mutex_;
};

} // namespace r2e
