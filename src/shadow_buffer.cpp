#include "shadow_buffer.hpp"
#include <fstream>
#include <iostream>

namespace r2e {

bool ShadowBufferManager::has_shadow(const std::string& path) {
    std::lock_guard<std::mutex> lock(shadow_mutex_);
    return shadows_.find(path) != shadows_.end();
}

void ShadowBufferManager::init_shadow(const std::string& virtual_path, const std::string& real_path) {
    std::lock_guard<std::mutex> lock(shadow_mutex_);
    if (shadows_.find(virtual_path) != shadows_.end()) {
        return;
    }

    FileShadow shadow;
    shadow.virtual_path = virtual_path;
    shadow.real_path = real_path;

    std::ifstream file(real_path, std::ios::binary | std::ios::ate);
    if (file.is_open()) {
        std::streamsize size = file.tellg();
        if (size > 0) {
            shadow.buffer.resize(size);
            file.seekg(0, std::ios::beg);
            file.read(reinterpret_cast<char*>(shadow.buffer.data()), size);
        }
    }

    shadows_[virtual_path] = std::move(shadow);
}

size_t ShadowBufferManager::write_to_shadow(
    const std::string& virtual_path,
    const uint8_t* data,
    size_t size,
    off_t offset,
    pid_t pid) {
    std::lock_guard<std::mutex> lock(shadow_mutex_);
    auto& shadow = shadows_[virtual_path];
    shadow.virtual_path = virtual_path;
    shadow.writing_pid = pid;
    shadow.has_modifications = true;

    if (offset + size > shadow.buffer.size()) {
        shadow.buffer.resize(offset + size, 0);
    }

    std::copy(data, data + size, shadow.buffer.begin() + offset);
    return size;
}

size_t ShadowBufferManager::read_from_shadow(
    const std::string& virtual_path,
    uint8_t* data,
    size_t size,
    off_t offset) {
    std::lock_guard<std::mutex> lock(shadow_mutex_);
    auto it = shadows_.find(virtual_path);
    if (it == shadows_.end()) {
        return 0;
    }

    const auto& buf = it->second.buffer;
    if (static_cast<size_t>(offset) >= buf.size()) {
        return 0;
    }

    size_t bytes_to_copy = std::min(size, buf.size() - static_cast<size_t>(offset));
    std::copy(buf.begin() + offset, buf.begin() + offset + bytes_to_copy, data);
    return bytes_to_copy;
}

std::vector<uint8_t> ShadowBufferManager::get_shadow_data(const std::string& virtual_path) {
    std::lock_guard<std::mutex> lock(shadow_mutex_);
    auto it = shadows_.find(virtual_path);
    if (it != shadows_.end()) {
        return it->second.buffer;
    }
    return {};
}

std::unordered_map<std::string, FileShadow> ShadowBufferManager::get_all_shadows() {
    std::lock_guard<std::mutex> lock(shadow_mutex_);
    return shadows_;
}

void ShadowBufferManager::clear_shadow(const std::string& virtual_path) {
    std::lock_guard<std::mutex> lock(shadow_mutex_);
    shadows_.erase(virtual_path);
}

void ShadowBufferManager::clear_all() {
    std::lock_guard<std::mutex> lock(shadow_mutex_);
    shadows_.clear();
}

} // namespace r2e
