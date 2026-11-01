#define FUSE_USE_VERSION 31

#include <fuse3/fuse.h>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <iomanip>

#include "entropy.hpp"
#include "process_tracker.hpp"
#include "shadow_buffer.hpp"
#include "reversal_engine.hpp"
#include "forensics.hpp"

struct R2EContext {
    std::string source_dir;
    std::unique_ptr<r2e::ProcessTracker> tracker;
    std::unique_ptr<r2e::ShadowBufferManager> shadow_manager;
    std::unique_ptr<r2e::ReversalEngine> reversal_engine;
    std::unique_ptr<r2e::ForensicsLogger> forensics_logger;
};

static R2EContext g_ctx;

static std::string get_real_path(const char* path) {
    if (strcmp(path, "/") == 0) {
        return g_ctx.source_dir;
    }
    return g_ctx.source_dir + path;
}

static std::string current_time_str() {
    auto now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);
    std::tm tm_buf{};
    gmtime_r(&now_c, &tm_buf);
    std::ostringstream ss;
    ss << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

static int r2e_getattr(const char* path, struct stat* stbuf, struct fuse_file_info* fi) {
    (void)fi;
    std::string real = get_real_path(path);
    int res = lstat(real.c_str(), stbuf);
    if (res == -1) {
        return -errno;
    }
    return 0;
}

static int r2e_readdir(const char* path, void* buf, fuse_fill_dir_t filler,
                       off_t offset, struct fuse_file_info* fi,
                       enum fuse_readdir_flags flags) {
    (void)offset;
    (void)fi;
    (void)flags;

    std::string real = get_real_path(path);
    DIR* dp = opendir(real.c_str());
    if (dp == nullptr) {
        return -errno;
    }

    struct dirent* de;
    while ((de = readdir(dp)) != nullptr) {
        struct stat st{};
        st.st_ino = de->d_ino;
        st.st_mode = de->d_type << 12;
        if (filler(buf, de->d_name, &st, 0, static_cast<fuse_fill_dir_flags>(0))) {
            break;
        }
    }
    closedir(dp);
    return 0;
}

static int r2e_open(const char* path, struct fuse_file_info* fi) {
    std::string real = get_real_path(path);
    int fd = open(real.c_str(), fi->flags);
    if (fd == -1) {
        return -errno;
    }
    fi->fh = fd;
    return 0;
}

static int r2e_create(const char* path, mode_t mode, struct fuse_file_info* fi) {
    std::string real = get_real_path(path);
    int fd = creat(real.c_str(), mode);
    if (fd == -1) {
        return -errno;
    }
    fi->fh = fd;
    return 0;
}

static int r2e_read(const char* path, char* buf, size_t size, off_t offset,
                    struct fuse_file_info* fi) {
    struct fuse_context* fc = fuse_get_context();
    pid_t pid = fc ? fc->pid : 0;

    if (g_ctx.tracker->is_flagged(pid) && g_ctx.shadow_manager->has_shadow(path)) {
        size_t bytes = g_ctx.shadow_manager->read_from_shadow(
            path, reinterpret_cast<uint8_t*>(buf), size, offset);
        return static_cast<int>(bytes);
    }

    int fd = static_cast<int>(fi->fh);
    if (fd == 0) {
        std::string real = get_real_path(path);
        fd = open(real.c_str(), O_RDONLY);
        if (fd == -1) return -errno;
    }

    int res = pread(fd, buf, size, offset);
    if (res == -1) {
        return -errno;
    }
    return res;
}

static int r2e_write(const char* path, const char* buf, size_t size, off_t offset,
                     struct fuse_file_info* fi) {
    struct fuse_context* fc = fuse_get_context();
    pid_t pid = fc ? fc->pid : 0;
    const uint8_t* ubuf = reinterpret_cast<const uint8_t*>(buf);
    std::string virt_path(path);
    std::string real_path = get_real_path(path);

    // Read original baseline data from disk before any overwrites occur
    std::vector<uint8_t> baseline_data;
    if (!g_ctx.shadow_manager->has_shadow(virt_path)) {
        std::ifstream real_in(real_path, std::ios::binary);
        if (real_in.is_open()) {
            baseline_data.assign(
                (std::istreambuf_iterator<char>(real_in)),
                (std::istreambuf_iterator<char>())
            );
        }
    }

    // 1. Process Tracker evaluates write rate & entropy
    bool flagged = g_ctx.tracker->record_write(pid, virt_path, ubuf, size);

    if (flagged) {
        std::cout << "[R2E INTERCEPTION] SUSPICIOUS BURST WRITE: PID=" << pid
                  << " -> " << virt_path << " (redirected to RAM Shadow Buffer)" << std::endl;

        if (!g_ctx.shadow_manager->has_shadow(virt_path)) {
            g_ctx.shadow_manager->init_shadow(virt_path, real_path);
        }

        // REDIRECT WRITE TO RAM SHADOW BUFFER (Preserves real disk file)
        g_ctx.shadow_manager->write_to_shadow(virt_path, ubuf, size, offset, pid);

        // Analyze and attempt Reversal
        std::vector<uint8_t> shadow_data = g_ctx.shadow_manager->get_shadow_data(virt_path);
        auto reversal = g_ctx.reversal_engine->attempt_reversal(virt_path, shadow_data, baseline_data);

        auto proc_act = g_ctx.tracker->get_process_activity(pid);
        double entropy_val = r2e::calculate_entropy(ubuf, size);

        if (reversal.success) {
            std::cout << "[R2E REVERSAL SUCCESS] Reversing " << virt_path
                      << " with " << reversal.algorithm_detected
                      << " (Key: " << reversal.pattern_or_key_hex << ") and committing clean data to disk."
                      << std::endl;

            // Write restored clean data to backing disk
            std::ofstream disk_out(real_path, std::ios::binary | std::ios::trunc);
            if (disk_out.is_open()) {
                disk_out.write(reinterpret_cast<const char*>(reversal.recovered_plaintext.data()),
                               reversal.recovered_plaintext.size());
            }

            r2e::ForensicReport rep;
            rep.pid = pid;
            rep.process_name = proc_act.process_name;
            rep.cmdline = proc_act.cmdline;
            rep.timestamp = current_time_str();
            rep.action_taken = "REVERSED_AND_CLEANED";
            rep.reversal_success = true;
            rep.encryption_algorithm_suspected = reversal.algorithm_detected;
            rep.identified_key_or_keystream = reversal.pattern_or_key_hex;
            rep.total_files_affected = proc_act.affected_files.size();
            for (const auto& f : proc_act.affected_files) {
                rep.sample_files.push_back(f);
                if (rep.sample_files.size() >= 20) break;
            }
            rep.average_entropy = entropy_val;
            rep.sample_ciphertext_hex = reversal.pattern_or_key_hex;
            g_ctx.forensics_logger->log_incident(rep);

        } else {
            // Reversal failed -> KILL SWITCH
            std::cout << "[R2E KILL-SWITCH ACTIVATING] Reversal failed ("
                      << reversal.details << "). Safely terminating PID " << pid << "!" << std::endl;

            r2e::ReversalEngine::execute_kill_switch(pid);

            r2e::ForensicReport rep;
            rep.pid = pid;
            rep.process_name = proc_act.process_name;
            rep.cmdline = proc_act.cmdline;
            rep.timestamp = current_time_str();
            rep.action_taken = "TERMINATED_PROCESS_KILL_SWITCH";
            rep.reversal_success = false;
            rep.encryption_algorithm_suspected = reversal.algorithm_detected;
            rep.identified_key_or_keystream = "NONE (IRREVERSIBLE / STRONG ENCRYPTION)";
            rep.total_files_affected = proc_act.affected_files.size();
            for (const auto& f : proc_act.affected_files) {
                rep.sample_files.push_back(f);
                if (rep.sample_files.size() >= 20) break;
            }
            rep.average_entropy = entropy_val;
            rep.sample_ciphertext_hex = reversal.pattern_or_key_hex;
            g_ctx.forensics_logger->log_incident(rep);
        }

        // Return size to caller so rogue process believes write succeeded
        return static_cast<int>(size);
    }

    // Normal legitimate write -> pass through directly to underlying real disk
    int fd = static_cast<int>(fi->fh);
    if (fd <= 0) {
        fd = open(real_path.c_str(), O_WRONLY);
        if (fd == -1) return -errno;
    }

    int res = pwrite(fd, buf, size, offset);
    if (res == -1) {
        return -errno;
    }
    return res;
}

static int r2e_unlink(const char* path) {
    std::string real = get_real_path(path);
    int res = unlink(real.c_str());
    if (res == -1) {
        return -errno;
    }
    g_ctx.shadow_manager->clear_shadow(path);
    return 0;
}

static int r2e_truncate(const char* path, off_t size, struct fuse_file_info* fi) {
    (void)fi;
    std::string real = get_real_path(path);
    int res = truncate(real.c_str(), size);
    if (res == -1) {
        return -errno;
    }
    return 0;
}

static int r2e_release(const char* path, struct fuse_file_info* fi) {
    (void)path;
    if (fi->fh > 0) {
        close(static_cast<int>(fi->fh));
    }
    return 0;
}

static struct fuse_operations r2e_oper = []() {
    struct fuse_operations ops{};
    ops.getattr  = r2e_getattr;
    ops.readdir  = r2e_readdir;
    ops.open     = r2e_open;
    ops.create   = r2e_create;
    ops.read     = r2e_read;
    ops.write    = r2e_write;
    ops.unlink   = r2e_unlink;
    ops.truncate = r2e_truncate;
    ops.release  = r2e_release;
    return ops;
}();

void print_usage(const char* prog) {
    std::cout << "R2E - Real-Time Cryptographic Reversal Engine (Prototype Driver)\n"
              << "Usage: " << prog << " [FUSE options] <source_backing_dir> <mount_point> [options]\n"
              << "Options:\n"
              << "  --entropy-threshold <float>   Shannon entropy threshold (default: 7.0)\n"
              << "  --file-threshold <int>        Files write count threshold (default: 50)\n"
              << "  --window-ms <int>             Time window in ms (default: 2000)\n"
              << "  --forensic-log <path>         Forensic log JSON file (default: r2e_forensics.json)\n";
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        print_usage(argv[0]);
        return 1;
    }

    double entropy_thresh = 7.0;
    size_t file_thresh = 50;
    int window_ms = 2000;
    std::string forensic_log = "r2e_forensics.json";

    std::vector<char*> fuse_args;
    fuse_args.push_back(argv[0]);

    std::string source_dir;
    std::string mount_point;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--entropy-threshold" && i + 1 < argc) {
            entropy_thresh = std::stod(argv[++i]);
        } else if (arg == "--file-threshold" && i + 1 < argc) {
            file_thresh = std::stoul(argv[++i]);
        } else if (arg == "--window-ms" && i + 1 < argc) {
            window_ms = std::stoi(argv[++i]);
        } else if (arg == "--forensic-log" && i + 1 < argc) {
            forensic_log = argv[++i];
        } else if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        } else if (arg[0] == '-') {
            fuse_args.push_back(argv[i]);
        } else {
            if (source_dir.empty()) {
                source_dir = arg;
            } else if (mount_point.empty()) {
                mount_point = arg;
            } else {
                fuse_args.push_back(argv[i]);
            }
        }
    }

    if (source_dir.empty() || mount_point.empty()) {
        std::cerr << "Error: Must specify source_backing_dir and mount_point." << std::endl;
        print_usage(argv[0]);
        return 1;
    }

    char resolved_source[PATH_MAX];
    if (realpath(source_dir.c_str(), resolved_source) == nullptr) {
        perror("realpath on source_dir");
        return 1;
    }
    g_ctx.source_dir = resolved_source;

    fuse_args.push_back(const_cast<char*>(mount_point.c_str()));

    g_ctx.tracker = std::make_unique<r2e::ProcessTracker>(
        entropy_thresh, file_thresh, std::chrono::milliseconds(window_ms));
    g_ctx.shadow_manager = std::make_unique<r2e::ShadowBufferManager>();
    g_ctx.reversal_engine = std::make_unique<r2e::ReversalEngine>();
    g_ctx.forensics_logger = std::make_unique<r2e::ForensicsLogger>(forensic_log);

    std::cout << "[R2E] Initializing Real-Time Cryptographic Reversal Engine..." << std::endl;
    std::cout << "[R2E] Backing Source Directory : " << g_ctx.source_dir << std::endl;
    std::cout << "[R2E] FUSE Interception Mount : " << mount_point << std::endl;
    std::cout << "[R2E] Entropy Threshold        : " << entropy_thresh << " bits/byte" << std::endl;
    std::cout << "[R2E] Rate Threshold           : >" << file_thresh << " files within " << window_ms << "ms" << std::endl;
    std::cout << "[R2E] Forensic Log Destination : " << forensic_log << std::endl;

    return fuse_main(fuse_args.size(), fuse_args.data(), &r2e_oper, nullptr);
}
