// SPDX-License-Identifier: Apache-2.0
// Copyright Pionix GmbH and Contributors to EVerest

#include "external_energy_limitsImpl.hpp"
#include <everest/logging.hpp>

namespace module {
namespace external_limits {

void external_energy_limitsImpl::init() {
}

void external_energy_limitsImpl::ready() {
}

void external_energy_limitsImpl::handle_set_external_limits(types::energy::ExternalLimits& value) {
    auto log_limits = [](const char* label, const types::energy::ScheduleReqEntry& entry) {
        const auto& l = entry.limits_to_leaves;
        if (l.total_power_W.has_value()) {
            EVLOG_info << "[ExternalLimits] " << label << " power_W=" << l.total_power_W->value
                       << " source=" << l.total_power_W->source;
        }
        if (l.ac_max_current_A.has_value()) {
            EVLOG_info << "[ExternalLimits] " << label << " current_A=" << l.ac_max_current_A->value
                       << " source=" << l.ac_max_current_A->source;
        }
        if (l.ac_max_phase_count.has_value()) {
            EVLOG_info << "[ExternalLimits] " << label << " phases=" << l.ac_max_phase_count->value
                       << " source=" << l.ac_max_phase_count->source;
        }
    };

    if (!value.schedule_import.empty()) {
        log_limits("import", value.schedule_import.front());
    }
    if (!value.schedule_export.empty()) {
        log_limits("export", value.schedule_export.front());
    }

    mod->signalExternalLimit(value);
};

} // namespace external_limits
} // namespace module
