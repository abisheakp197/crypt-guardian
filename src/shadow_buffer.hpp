#pragma once

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace r2e {

struct FileShadow {
    std::string virtual_path;
    std::string real_path;
    std::vector<uint8_t> buffer;
    bool has_modifications{false};
    pid_t writing_pid{0};
};

class ShadowBufferManager {
public:
    ShadowBufferManager() = default;

    bool has_shadow(const std::string& path);
    void init_shadow(const std::string& virtual_path, const std::string& real_path);

    size_t write_to_shadow(
        const std::string& virtual_path,
        const uint8_t* data,
        size_t size,
        off_t offset,
        pid_t pid
    );

    size_t read_from_shadow(
        const std::string& virtual_path,
        uint8_t* data,
        size_t size,
        off_t offset
    );

    std::vector<uint8_t> get_shadow_data(const std::string& virtual_path);
    std::unordered_map<std::string, FileShadow> get_all_shadows();
    void clear_shadow(const std::string& virtual_path);
    void clear_all();

private:
    std::mutex shadow_mutex_;
    std::unordered_map<std::string, FileShadow> shadows_;
};

} // namespace r2e
