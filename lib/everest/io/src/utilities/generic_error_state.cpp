// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 - 2025 Pionix GmbH and Contributors to EVerest
#include <everest/io/utilities/generic_error_state.hpp>
#include <string.h>

namespace everest::lib::io::utilities {

bool generic_error_state::set_error_status(int error_code) {
    std::lock_guard<std::mutex> lock(m_state_mutex);
    m_current_error = error_code;
    auto on_error = error_code != 0;
    m_clear_error_pending = (not on_error) and m_on_error;
    m_on_error = on_error;
    return not m_on_error;
}

bool generic_error_state::clear_error_pending() const {
    std::lock_guard<std::mutex> lock(m_state_mutex);
    return m_clear_error_pending;
}

bool generic_error_state::on_error() const {
    std::lock_guard<std::mutex> lock(m_state_mutex);
    return m_on_error;
}

int generic_error_state::current_error() const {
    std::lock_guard<std::mutex> lock(m_state_mutex);
    return m_current_error;
}

void generic_error_state::call_error_handler(cb_error& handler) const {
    if (!handler) {
        return;
    }

    int current_error_snapshot = 0;
    {
        std::lock_guard<std::mutex> lock(m_state_mutex);
        current_error_snapshot = m_current_error;
    }
    handler(current_error_snapshot, strerror(current_error_snapshot));
}

void generic_error_state::clear_error_handler(cb_error& handler) {
    if (handler) {
        handler(0, strerror(0));
    }
    set_error_cleared();
}

void generic_error_state::set_error_cleared() {
    std::lock_guard<std::mutex> lock(m_state_mutex);
    m_clear_error_pending = false;
}

} // namespace everest::lib::io::utilities
