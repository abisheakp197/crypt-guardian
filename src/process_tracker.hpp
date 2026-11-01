#pragma once

#include <chrono>
#include <deque>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace r2e {

struct ProcessActivity {
    pid_t pid{0};
    std::string process_name;
    std::string cmdline;
    bool is_flagged_ransomware{false};
    std::chrono::steady_clock::time_point flagged_time;

    struct WriteEvent {
        std::chrono::steady_clock::time_point timestamp;
        std::string filepath;
        double entropy;
        size_t bytes_written;
    };

    std::deque<WriteEvent> recent_writes;
    std::unordered_set<std::string> affected_files;
};

class ProcessTracker {
public:
    ProcessTracker(
        double entropy_threshold = 7.0,
        size_t file_threshold = 50,
        std::chrono::milliseconds window_duration = std::chrono::milliseconds(2000)
    );

    // Records write. Returns true if process is currently or just flagged as ransomware suspect.
    bool record_write(pid_t pid, const std::string& filepath, const uint8_t* data, size_t size);

    bool is_flagged(pid_t pid);
    ProcessActivity get_process_activity(pid_t pid);
    void prune_inactive_processes();
    void set_thresholds(double entropy_thresh, size_t file_thresh, std::chrono::milliseconds window);

private:
    std::string get_process_name_from_pid(pid_t pid);
    std::string get_process_cmdline_from_pid(pid_t pid);

    double entropy_threshold_;
    size_t file_threshold_;
    std::chrono::milliseconds window_duration_;

    std::mutex tracker_mutex_;
    std::unordered_map<pid_t, ProcessActivity> processes_;
};

} // namespace r2e
