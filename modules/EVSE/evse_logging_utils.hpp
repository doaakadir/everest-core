// SPDX-License-Identifier: Apache-2.0
// Copyright Pionix GmbH and Contributors to EVerest
#pragma once

#include <cctype>
#include <cstdint>
#include <optional>
#include <string>

namespace evse_logging_utils {

inline std::optional<int> extract_second_from_rfc3339(const std::string& timestamp) {
    const auto t_pos = timestamp.find('T');
    if (t_pos == std::string::npos) {
        return std::nullopt;
    }
    const auto start = t_pos + 1;
    if (start + 7 >= timestamp.size()) {
        return std::nullopt;
    }
    if (timestamp[start + 2] != ':' || timestamp[start + 5] != ':') {
        return std::nullopt;
    }
    const char tens = timestamp[start + 6];
    const char ones = timestamp[start + 7];
    if (!std::isdigit(static_cast<unsigned char>(tens)) || !std::isdigit(static_cast<unsigned char>(ones))) {
        return std::nullopt;
    }
    return (tens - '0') * 10 + (ones - '0');
}

inline uint32_t fnv1a_32(const std::string& data) {
    uint32_t hash = 2166136261u;
    for (unsigned char c : data) {
        hash ^= c;
        hash *= 16777619u;
    }
    return hash;
}

} // namespace evse_logging_utils
