#include "entropy.hpp"
#include <cmath>
#include <array>

namespace r2e {

double calculate_entropy(const uint8_t* data, size_t size) {
    if (data == nullptr || size == 0) {
        return 0.0;
    }

    std::array<size_t, 256> freq{};
    for (size_t i = 0; i < size; ++i) {
        freq[data[i]]++;
    }

    double entropy = 0.0;
    const double inv_size = 1.0 / static_cast<double>(size);
    constexpr double log2_c = 1.4426950408889634073599246810018921374266; // 1 / log(2)

    for (size_t count : freq) {
        if (count > 0) {
            double p = static_cast<double>(count) * inv_size;
            entropy -= p * (std::log(p) * log2_c);
        }
    }

    return entropy;
}

double calculate_entropy(const std::vector<uint8_t>& data) {
    return calculate_entropy(data.data(), data.size());
}

} // namespace r2e
