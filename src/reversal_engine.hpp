#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace r2e {

struct ReversalResult {
    bool success{false};
    std::string algorithm_detected;
    std::vector<uint8_t> recovered_plaintext;
    std::string pattern_or_key_hex;
    std::string details;
};

class ReversalEngine {
public:
    ReversalEngine() = default;

    ReversalResult attempt_reversal(
        const std::string& filepath,
        const std::vector<uint8_t>& encrypted_data,
        const std::vector<uint8_t>& original_baseline_data = {}
    );

    static bool execute_kill_switch(pid_t pid);

private:
    ReversalResult try_magic_byte_xor_reversal(
        const std::vector<uint8_t>& encrypted_data,
        const std::string& filepath
    );

    ReversalResult try_known_plaintext_xor_reversal(
        const std::vector<uint8_t>& encrypted_data,
        const std::vector<uint8_t>& original_baseline
    );

    ReversalResult analyze_block_cipher(
        const std::vector<uint8_t>& encrypted_data
    );
};

} // namespace r2e
