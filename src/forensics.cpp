#include "forensics.hpp"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <chrono>

namespace r2e {

static std::string escape_json(const std::string& s) {
    std::ostringstream o;
    for (char c : s) {
        if (c == '"') o << "\\\"";
        else if (c == '\\') o << "\\\\";
        else if (c == '\b') o << "\\b";
        else if (c == '\f') o << "\\f";
        else if (c == '\n') o << "\\n";
        else if (c == '\r') o << "\\r";
        else if (c == '\t') o << "\\t";
        else if ('\x00' <= c && c <= '\x1f') {
            o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)c;
        } else {
            o << c;
        }
    }
    return o.str();
}

ForensicsLogger::ForensicsLogger(const std::string& log_filepath)
    : log_filepath_(log_filepath) {}

void ForensicsLogger::log_incident(const ForensicReport& report) {
    std::lock_guard<std::mutex> lock(log_mutex_);
    std::ofstream out(log_filepath_, std::ios::app);
    if (!out.is_open()) {
        std::cerr << "[R2E FORENSICS] Error opening forensic log file: " << log_filepath_ << std::endl;
        return;
    }

    out << "{\n";
    out << "  \"timestamp\": \"" << escape_json(report.timestamp) << "\",\n";
    out << "  \"pid\": " << report.pid << ",\n";
    out << "  \"process_name\": \"" << escape_json(report.process_name) << "\",\n";
    out << "  \"cmdline\": \"" << escape_json(report.cmdline) << "\",\n";
    out << "  \"action_taken\": \"" << escape_json(report.action_taken) << "\",\n";
    out << "  \"reversal_success\": " << (report.reversal_success ? "true" : "false") << ",\n";
    out << "  \"encryption_algorithm_suspected\": \"" << escape_json(report.encryption_algorithm_suspected) << "\",\n";
    out << "  \"identified_key_or_keystream\": \"" << escape_json(report.identified_key_or_keystream) << "\",\n";
    out << "  \"total_files_affected\": " << report.total_files_affected << ",\n";
    out << "  \"average_entropy\": " << std::fixed << std::setprecision(4) << report.average_entropy << ",\n";
    out << "  \"sample_ciphertext_hex\": \"" << escape_json(report.sample_ciphertext_hex) << "\",\n";
    out << "  \"sample_files\": [\n";
    for (size_t i = 0; i < report.sample_files.size(); ++i) {
        out << "    \"" << escape_json(report.sample_files[i]) << "\""
            << (i + 1 < report.sample_files.size() ? "," : "") << "\n";
    }
    out << "  ]\n";
    out << "}\n";
    out.flush();

    std::cout << "[R2E FORENSICS] Incident recorded for PID " << report.pid
              << " (" << report.process_name << ") in " << log_filepath_ << std::endl;
}

} // namespace r2e
