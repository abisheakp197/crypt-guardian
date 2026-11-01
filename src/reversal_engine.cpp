#include "reversal_engine.hpp"
#include "entropy.hpp"

#include <iostream>
#include <iomanip>
#include <sstream>
#include <csignal>
#include <unistd.h>
#include <cstring>

namespace r2e {

struct MagicSignature {
    std::string extension;
    std::vector<uint8_t> magic;
    size_t offset{0};
};

static const std::vector<MagicSignature> KNOWN_MAGIC_SIGNATURES = {
    {".png",  {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, 0},
    {".jpg",  {0xFF, 0xD8, 0xFF, 0xE0}, 0},
    {".jpeg", {0xFF, 0xD8, 0xFF, 0xE1}, 0},
    {".pdf",  {0x25, 0x50, 0x44, 0x46, 0x2D}, 0}, // "%PDF-"
    {".zip",  {0x50, 0x4B, 0x03, 0x04}, 0},
    {".docx", {0x50, 0x4B, 0x03, 0x04}, 0},
    {".xlsx", {0x50, 0x4B, 0x03, 0x04}, 0},
    {".elf",  {0x7F, 0x45, 0x4C, 0x46}, 0},
    {".gif",  {0x47, 0x49, 0x46, 0x38}, 0},
    {".bmp",  {0x42, 0x4D}, 0},
};

static std::string to_hex_string(const uint8_t* data, size_t len) {
    std::ostringstream ss;
    for (size_t i = 0; i < len; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }
    return ss.str();
}

ReversalResult ReversalEngine::attempt_reversal(
    const std::string& filepath,
    const std::vector<uint8_t>& encrypted_data,
    const std::vector<uint8_t>& original_baseline_data) {

    if (encrypted_data.empty()) {
        return {false, "none", {}, "", "Empty data buffer"};
    }

    if (!original_baseline_data.empty() && original_baseline_data.size() == encrypted_data.size()) {
        auto res = try_known_plaintext_xor_reversal(encrypted_data, original_baseline_data);
        if (res.success) {
            return res;
        }
    }

    auto magic_res = try_magic_byte_xor_reversal(encrypted_data, filepath);
    if (magic_res.success) {
        return magic_res;
    }

    return analyze_block_cipher(encrypted_data);
}

ReversalResult ReversalEngine::try_known_plaintext_xor_reversal(
    const std::vector<uint8_t>& encrypted_data,
    const std::vector<uint8_t>& original_baseline) {

    size_t sample_len = std::min(encrypted_data.size(), original_baseline.size());
    if (sample_len < 4) {
        return {false, "", {}, "", "Insufficient sample size"};
    }

    std::vector<uint8_t> derived_stream(sample_len);
    for (size_t i = 0; i < sample_len; ++i) {
        derived_stream[i] = encrypted_data[i] ^ original_baseline[i];
    }

    bool single_byte = true;
    for (size_t i = 1; i < sample_len; ++i) {
        if (derived_stream[i] != derived_stream[0]) {
            single_byte = false;
            break;
        }
    }

    if (single_byte) {
        uint8_t key = derived_stream[0];
        std::vector<uint8_t> recovered(encrypted_data.size());
        for (size_t i = 0; i < encrypted_data.size(); ++i) {
            recovered[i] = encrypted_data[i] ^ key;
        }
        return {
            true,
            "Single-byte XOR",
            recovered,
            to_hex_string(&key, 1),
            "Reversed using derived single-byte key against baseline"
        };
    }

    for (size_t key_len = 2; key_len <= 64 && key_len * 2 <= sample_len; ++key_len) {
        bool repeats = true;
        for (size_t i = key_len; i < sample_len; ++i) {
            if (derived_stream[i] != derived_stream[i % key_len]) {
                repeats = false;
                break;
            }
        }

        if (repeats) {
            std::vector<uint8_t> key(derived_stream.begin(), derived_stream.begin() + key_len);
            std::vector<uint8_t> recovered(encrypted_data.size());
            for (size_t i = 0; i < encrypted_data.size(); ++i) {
                recovered[i] = encrypted_data[i] ^ key[i % key_len];
            }
            return {
                true,
                "Repeating XOR (Keystream)",
                recovered,
                to_hex_string(key.data(), key.size()),
                "Reversed using repeating keystream of length " + std::to_string(key_len)
            };
        }
    }

    return {false, "", {}, "", "Non-repeating or complex keystream"};
}

ReversalResult ReversalEngine::try_magic_byte_xor_reversal(
    const std::vector<uint8_t>& encrypted_data,
    const std::string& filepath) {

    for (const auto& sig : KNOWN_MAGIC_SIGNATURES) {
        if (filepath.size() >= sig.extension.size() &&
            filepath.compare(filepath.size() - sig.extension.size(), sig.extension.size(), sig.extension) == 0) {

            if (encrypted_data.size() < sig.offset + sig.magic.size()) {
                continue;
            }

            size_t mlen = sig.magic.size();
            std::vector<uint8_t> candidate_key(mlen);
            for (size_t i = 0; i < mlen; ++i) {
                candidate_key[i] = encrypted_data[sig.offset + i] ^ sig.magic[i];
            }

            bool single_byte = true;
            for (size_t i = 1; i < mlen; ++i) {
                if (candidate_key[i] != candidate_key[0]) {
                    single_byte = false;
                    break;
                }
            }

            if (single_byte) {
                uint8_t key = candidate_key[0];
                std::vector<uint8_t> recovered(encrypted_data.size());
                for (size_t i = 0; i < encrypted_data.size(); ++i) {
                    recovered[i] = encrypted_data[i] ^ key;
                }
                return {
                    true,
                    "Single-byte XOR (Header Inferred)",
                    recovered,
                    to_hex_string(&key, 1),
                    "Reversed using file header signature for " + sig.extension
                };
            }

            // Repeating key matching the magic signature length
            std::vector<uint8_t> recovered(encrypted_data.size());
            for (size_t i = 0; i < encrypted_data.size(); ++i) {
                recovered[i] = encrypted_data[i] ^ candidate_key[i % mlen];
            }
            return {
                true,
                "Repeating XOR (Header Inferred)",
                recovered,
                to_hex_string(candidate_key.data(), candidate_key.size()),
                "Reversed using derived keystream from header signature for " + sig.extension
            };
        }
    }

    return {false, "", {}, "", "No header signature match found for reversal"};
}

ReversalResult ReversalEngine::analyze_block_cipher(
    const std::vector<uint8_t>& encrypted_data) {
    double entropy = calculate_entropy(encrypted_data.data(), encrypted_data.size());
    std::string hex_preview = to_hex_string(encrypted_data.data(), std::min(encrypted_data.size(), size_t(32)));

    std::string algo = (encrypted_data.size() % 16 == 0)
        ? "AES-CBC/ECB (128/256-bit block aligned)"
        : "ChaCha20 / AES-CTR Stream Mode";

    return {
        false,
        algo,
        {},
        hex_preview,
        "Cryptographically secure symmetric cipher detected (entropy " + std::to_string(entropy) +
        "). Asymmetric key encapsulation prevents instant in-memory key derivation."
    };
}

bool ReversalEngine::execute_kill_switch(pid_t pid) {
    if (pid <= 1) {
        std::cerr << "[R2E KILL-SWITCH] Refusing to kill PID " << pid << std::endl;
        return false;
    }

    std::cout << "[R2E KILL-SWITCH] Terminating malicious PID " << pid << "..." << std::endl;
    kill(pid, SIGTERM);
    usleep(50000); // 50ms
    if (kill(pid, 0) == 0) {
        kill(pid, SIGKILL);
    }
    return true;
}

} // namespace r2e
