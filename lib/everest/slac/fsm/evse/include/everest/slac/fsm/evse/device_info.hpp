// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 - 2025 Pionix GmbH and Contributors to EVerest
#ifndef EVSE_SLAC_DEVICE_INFO_HPP
#define EVSE_SLAC_DEVICE_INFO_HPP

#include <string>
#include <string_view>

#include <slac/slac.hpp>

namespace slac::fsm::evse {

inline std::string get_qualcomm_device_info(slac::messages::qualcomm::op_attr_cnf const& msg) {
    const auto get_string_view = [](auto const& raw) constexpr {
        static_assert(sizeof(uint8_t) == sizeof(char));
        return std::string_view(reinterpret_cast<char const*>(raw), sizeof(raw));
    };

    std::string result("Qualcomm PLC Device Attributes:");
    result += "\n  HW Platform: ";
    result += get_string_view(msg.hw_platform);
    result += "\n  SW Platform: ";
    result += get_string_view(msg.sw_platform);
    result += ("\n  Firmware: " + std::to_string(msg.version_major) + "." + std::to_string(msg.version_minor) + "." +
               std::to_string(msg.version_pib) + "." + std::to_string(msg.reserved) + "-" +
               std::to_string(msg.version_build));
    result += "\n  Build date: ";
    result += get_string_view(msg.build_date);

    result += "\n  ZC signal: ";

    const auto zc_signal = (msg.line_freq_zc >> 2) & 0x03;
    if (zc_signal == 0x01) {
        result += "Detected";
    } else if (zc_signal == 0x02) {
        result += "Missing";
    } else {
        result += ("Unknown (" + std::to_string(zc_signal) + ")");
    }

    result += "\n  Line frequency: ";

    const auto line_freq = (msg.line_freq_zc) & 0x03;
    if (line_freq == 0x01) {
        result += "50Hz";
    } else if (line_freq == 0x02) {
        result += "60Hz";
    } else {
        result += ("Unknown (" + std::to_string(line_freq) + ")");
    }

    return result;
}

inline std::string get_lumissil_device_info(slac::messages::lumissil::nscm_get_version_cnf const& msg) {
    return "Lumissil PLC Device Firmware version: " + std::to_string(msg.version_major) + "." +
           std::to_string(msg.version_minor) + "." + std::to_string(msg.version_patch) + "." +
           std::to_string(msg.version_build);
}

} // namespace slac::fsm::evse

#endif // EVSE_SLAC_DEVICE_INFO_HPP
