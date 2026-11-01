#include "process_tracker.hpp"
#include "entropy.hpp"

#include <fstream>
#include <sstream>
#include <iostream>
#include <unistd.h>

namespace r2e {

ProcessTracker::ProcessTracker(
    double entropy_threshold,
    size_t file_threshold,
    std::chrono::milliseconds window_duration)
    : entropy_threshold_(entropy_threshold),
      file_threshold_(file_threshold),
      window_duration_(window_duration) {}

void ProcessTracker::set_thresholds(
    double entropy_thresh,
    size_t file_thresh,
    std::chrono::milliseconds window) {
    std::lock_guard<std::mutex> lock(tracker_mutex_);
    entropy_threshold_ = entropy_thresh;
    file_threshold_ = file_thresh;
    window_duration_ = window;
}

std::string ProcessTracker::get_process_name_from_pid(pid_t pid) {
    std::string comm_path = "/proc/" + std::to_string(pid) + "/comm";
    std::ifstream comm_file(comm_path);
    if (comm_file.is_open()) {
        std::string name;
        if (std::getline(comm_file, name)) {
            return name;
        }
    }
    return "unknown";
}

std::string ProcessTracker::get_process_cmdline_from_pid(pid_t pid) {
    std::string cmdline_path = "/proc/" + std::to_string(pid) + "/cmdline";
    std::ifstream cmd_file(cmdline_path, std::ios::binary);
    if (cmd_file.is_open()) {
        std::ostringstream ss;
        char ch;
        while (cmd_file.get(ch)) {
            ss << (ch == '\0' ? ' ' : ch);
        }
        return ss.str();
    }
    return "unknown";
}

bool ProcessTracker::is_flagged(pid_t pid) {
    std::lock_guard<std::mutex> lock(tracker_mutex_);
    auto it = processes_.find(pid);
    if (it != processes_.end()) {
        return it->second.is_flagged_ransomware;
    }
    return false;
}

ProcessActivity ProcessTracker::get_process_activity(pid_t pid) {
    std::lock_guard<std::mutex> lock(tracker_mutex_);
    auto it = processes_.find(pid);
    if (it != processes_.end()) {
        return it->second;
    }
    ProcessActivity empty;
    empty.pid = pid;
    return empty;
}

bool ProcessTracker::record_write(pid_t pid, const std::string& filepath, const uint8_t* data, size_t size) {
    const auto now = std::chrono::steady_clock::now();
    double entropy = calculate_entropy(data, size);

    std::lock_guard<std::mutex> lock(tracker_mutex_);
    auto& proc = processes_[pid];
    if (proc.pid == 0) {
        proc.pid = pid;
        proc.process_name = get_process_name_from_pid(pid);
        proc.cmdline = get_process_cmdline_from_pid(pid);
    }

    if (proc.is_flagged_ransomware) {
        proc.affected_files.insert(filepath);
        return true;
    }

    proc.recent_writes.push_back({now, filepath, entropy, size});
    proc.affected_files.insert(filepath);

    const auto cutoff = now - window_duration_;
    while (!proc.recent_writes.empty() && proc.recent_writes.front().timestamp < cutoff) {
        proc.recent_writes.pop_front();
    }

    std::unordered_set<std::string> burst_files;
    size_t high_entropy_count = 0;
    double total_entropy = 0.0;

    for (const auto& ev : proc.recent_writes) {
        burst_files.insert(ev.filepath);
        total_entropy += ev.entropy;
        if (ev.entropy >= entropy_threshold_) {
            high_entropy_count++;
        }
    }

    double avg_entropy = proc.recent_writes.empty() ? 0.0 : (total_entropy / proc.recent_writes.size());

    // Flag heuristic:
    // If process attempts to write to more than file_threshold_ (e.g. 50) files within window
    // AND high entropy writes are observed
    if (burst_files.size() > file_threshold_ &&
        (high_entropy_count >= (burst_files.size() / 2) || avg_entropy >= entropy_threshold_)) {
        proc.is_flagged_ransomware = true;
        proc.flagged_time = now;
        return true;
    }

    return false;
}

void ProcessTracker::prune_inactive_processes() {
    const auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(tracker_mutex_);
    for (auto it = processes_.begin(); it != processes_.end();) {
        if (!it->second.is_flagged_ransomware) {
            const auto cutoff = now - (window_duration_ * 5);
            if (it->second.recent_writes.empty() || it->second.recent_writes.back().timestamp < cutoff) {
                it = processes_.erase(it);
                continue;
            }
        }
        ++it;
    }
}

} // namespace r2e
