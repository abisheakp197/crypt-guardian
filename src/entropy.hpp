#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace r2e {

// Shannon entropy H(X) = -sum(p_i * log2(p_i)) [0.0, 8.0 bits/byte]
double calculate_entropy(const uint8_t* data, size_t size);
double calculate_entropy(const std::vector<uint8_t>& data);

constexpr double DEFAULT_ENTROPY_THRESHOLD = 7.0;

} // namespace r2e
