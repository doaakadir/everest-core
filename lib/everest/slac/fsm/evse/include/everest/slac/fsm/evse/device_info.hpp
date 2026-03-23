// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 - 2025 Pionix GmbH and Contributors to EVerest
#ifndef EVSE_SLAC_DEVICE_INFO_HPP
#define EVSE_SLAC_DEVICE_INFO_HPP

#include <algorithm>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <string>
#include <type_traits>

#include <slac/slac.hpp>

namespace slac::fsm::evse {

inline std::string format_fixed_string(const uint8_t* raw, const size_t len) {
    const auto end = std::find(raw, raw + len, 0);
    return std::string(reinterpret_cast<const char*>(raw), reinterpret_cast<const char*>(end));
}

inline std::string format_hex_bytes(const uint8_t* raw, const size_t len, const char separator = ':') {
    std::ostringstream ss;
    ss << std::hex << std::uppercase << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        ss << std::setw(2) << static_cast<unsigned>(raw[i]);
        if (i + 1 != len) {
            ss << separator;
        }
    }
    return ss.str();
}

inline std::pair<const uint8_t*, size_t> get_message_payload_view(slac::messages::HomeplugMessage& message) {
    auto* raw_message = message.get_raw_message_ptr();
    auto* payload = raw_message->payload;
    if (raw_message->homeplug_header.mmv !=
        static_cast<std::underlying_type_t<slac::defs::MMV>>(slac::defs::MMV::AV_1_0)) {
        payload += sizeof(slac::messages::homeplug_fragmentation_part);
    }

    const auto* payload_begin = reinterpret_cast<const uint8_t*>(payload);
    const auto* frame_begin = reinterpret_cast<const uint8_t*>(raw_message);
    const auto raw_len = std::max(message.get_raw_msg_len(), 0);
    const auto payload_offset = static_cast<size_t>(payload_begin - frame_begin);
    if (static_cast<size_t>(raw_len) <= payload_offset) {
        return {payload_begin, 0};
    }
    const auto payload_len = static_cast<size_t>(raw_len) - payload_offset;

    return {payload_begin, payload_len};
}

inline std::string get_qualcomm_device_info(slac::messages::qualcomm::op_attr_cnf const& msg) {
    std::string result("Qualcomm PLC Device Attributes:");
    result += "\n  Vendor MME: ";
    result += format_hex_bytes(msg.vendor_mme, sizeof(msg.vendor_mme));
    result += "\n  Success: ";
    result += std::to_string(msg.success);
    result += "\n  Cookie: 0x";
    {
        std::ostringstream ss;
        ss << std::hex << std::uppercase << std::setfill('0') << std::setw(8) << msg.cookie;
        result += ss.str();
    }
    result += "\n  Report type: 0x";
    {
        std::ostringstream ss;
        ss << std::hex << std::uppercase << std::setfill('0') << std::setw(2) << static_cast<unsigned>(msg.report_type);
        result += ss.str();
    }
    result += "\n  Size field: ";
    result += std::to_string(msg.size);
    result += "\n  HW Platform: ";
    result += format_fixed_string(msg.hw_platform, sizeof(msg.hw_platform));
    result += "\n  SW Platform: ";
    result += format_fixed_string(msg.sw_platform, sizeof(msg.sw_platform));
    result += ("\n  Firmware: " + std::to_string(msg.version_major) + "." + std::to_string(msg.version_minor) + "." +
               std::to_string(msg.version_pib) + "." + std::to_string(msg.reserved) + "-" +
               std::to_string(msg.version_build));
    result += "\n  Build date: ";
    result += format_fixed_string(msg.build_date, sizeof(msg.build_date));
    result += "\n  Release type: ";
    result += format_fixed_string(msg.release_type, sizeof(msg.release_type));
    result += "\n  SDRAM type: 0x";
    {
        std::ostringstream ss;
        ss << std::hex << std::uppercase << std::setfill('0') << std::setw(2) << static_cast<unsigned>(msg.sdram_type);
        result += ss.str();
    }
    result += "\n  Reserved2: 0x";
    {
        std::ostringstream ss;
        ss << std::hex << std::uppercase << std::setfill('0') << std::setw(2) << static_cast<unsigned>(msg.reserved2);
        result += ss.str();
    }

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

    result += "\n  SDRAM size: ";
    result += std::to_string(msg.sdram_size);
    result += "\n  Authorization mode: 0x";
    {
        std::ostringstream ss;
        ss << std::hex << std::uppercase << std::setfill('0') << std::setw(2)
           << static_cast<unsigned>(msg.authorization_mode);
        result += ss.str();
    }

    return result;
}

inline std::string get_lumissil_device_info(slac::messages::lumissil::nscm_get_version_cnf const& msg) {
    return "Lumissil PLC Device Firmware version: " + std::to_string(msg.version_major) + "." +
           std::to_string(msg.version_minor) + "." + std::to_string(msg.version_patch) + "." +
           std::to_string(msg.version_build);
}

inline void append_hex_dump(std::string& result, const uint8_t* data, const size_t len) {
    std::ostringstream dump;
    dump << std::hex << std::uppercase << std::setfill('0');

    for (size_t offset = 0; offset < len; offset += 16) {
        dump << "\n    " << std::setw(4) << offset << ": ";
        const auto line_end = std::min(offset + 16, len);
        for (size_t i = offset; i < line_end; ++i) {
            dump << std::setw(2) << static_cast<unsigned>(data[i]);
            if (i + 1 != line_end) {
                dump << " ";
            }
        }
    }

    result += dump.str();
}

inline size_t get_dump_len(const size_t total_len, const int max_dump_bytes) {
    if (max_dump_bytes <= 0) {
        return total_len;
    }

    return std::min(total_len, static_cast<size_t>(max_dump_bytes));
}

inline void append_hex_dump_section(std::string& result, const std::string& label, const uint8_t* data,
                                    const size_t total_len, const int max_dump_bytes) {
    const auto dump_len = get_dump_len(total_len, max_dump_bytes);

    result += "\n  " + label + " (";
    if (dump_len < total_len) {
        result += "showing first " + std::to_string(dump_len) + " of " + std::to_string(total_len) + " bytes";
    } else {
        result += std::to_string(total_len) + " bytes";
    }
    result += "):";
    append_hex_dump(result, data, dump_len);
}

inline std::string get_qualcomm_device_info_debug(slac::messages::HomeplugMessage& message, const int max_dump_bytes) {
    const auto [payload_ptr, payload_len] = get_message_payload_view(message);
    const auto raw_msg_len = std::max(message.get_raw_msg_len(), 0);

    slac::messages::qualcomm::op_attr_cnf msg{};
    const auto copied_len = std::min(payload_len, sizeof(msg));
    std::memcpy(&msg, payload_ptr, copied_len);

    std::string result = get_qualcomm_device_info(msg);
    result += "\n  OP_ATTR payload length: ";
    result += std::to_string(payload_len);
    result += " bytes";
    if (payload_len < sizeof(msg)) {
        result += " (shorter than expected ";
        result += std::to_string(sizeof(msg));
        result += " bytes)";
    }

    std::ostringstream line_freq;
    line_freq << std::hex << std::uppercase << std::setfill('0');
    line_freq << "\n  line_freq_zc raw: 0x" << std::setw(2) << static_cast<unsigned>(msg.line_freq_zc);
    line_freq << " (zc_bits=0x" << std::setw(1) << static_cast<unsigned>((msg.line_freq_zc >> 2) & 0x03);
    line_freq << ", freq_bits=0x" << std::setw(1) << static_cast<unsigned>(msg.line_freq_zc & 0x03) << ")";
    result += line_freq.str();

    append_hex_dump_section(result, "Raw OP_ATTR payload bytes", payload_ptr, payload_len, max_dump_bytes);
    append_hex_dump_section(result, "Raw HomePlug frame bytes",
                            reinterpret_cast<const uint8_t*>(message.get_raw_message_ptr()),
                            static_cast<size_t>(raw_msg_len), max_dump_bytes);

    return result;
}

inline std::string get_qualcomm_nw_info_debug(slac::messages::HomeplugMessage& message, const int max_dump_bytes) {
    const auto [payload_ptr, payload_len] = get_message_payload_view(message);
    const auto raw_msg_len = std::max(message.get_raw_msg_len(), 0);

    std::string result("Qualcomm PLC Network Info:");
    result += "\n  MMType: 0x";
    {
        std::ostringstream ss;
        ss << std::hex << std::uppercase << std::setfill('0') << std::setw(4) << message.get_mmtype();
        result += ss.str();
    }
    append_hex_dump_section(result, "Raw NW_INFO payload bytes", payload_ptr, payload_len, max_dump_bytes);
    append_hex_dump_section(result, "Raw HomePlug frame bytes",
                            reinterpret_cast<const uint8_t*>(message.get_raw_message_ptr()),
                            static_cast<size_t>(raw_msg_len), max_dump_bytes);

    return result;
}

} // namespace slac::fsm::evse

#endif // EVSE_SLAC_DEVICE_INFO_HPP
