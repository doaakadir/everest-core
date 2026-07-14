// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 - 2022 Pionix GmbH and Contributors to EVerest

#include "energyImpl.hpp"
#include <chrono>
#include <date/date.h>
#include <date/tz.h>
#include <utils/date.hpp>

namespace module {
namespace energy_grid {

namespace {
bool energy_flow_request_contains_uuid(const types::energy::EnergyFlowRequest& request, const std::string& uuid) {
    if (request.uuid == uuid) {
        return true;
    }

    for (const auto& child : request.children) {
        if (energy_flow_request_contains_uuid(child, uuid)) {
            return true;
        }
    }

    return false;
}
} // namespace

void energyImpl::init() {

    // UUID must be unique also beyond this charging station -> will be handled on framework level and above later
    energy_flow_request.uuid = mod->info.id;
    energy_flow_request.node_type = types::energy::NodeType::Generic;

    source_cfg = mod->info.id + "/module_config";

    // Initialize with sane defaults
    energy_flow_request.schedule_import = get_local_schedule();
    energy_flow_request.schedule_export = get_local_schedule();

    child_energy_flow_requests.resize(mod->r_energy_consumer.size());
    std::size_t child_index = 0;
    for (auto& entry : mod->r_energy_consumer) {
        const auto index = child_index++;
        entry->subscribe_energy_flow_request([this, index](types::energy::EnergyFlowRequest e) {
            // Received new energy_flow_request object from a child. Update in the cached object and republish.
            std::scoped_lock lock(energy_mutex);

            if (index < child_energy_flow_requests.size()) {
                child_energy_flow_requests[index] = e;
            }

            bool child_found = false;
            for (auto& child : energy_flow_request.children) {
                if (child.uuid == e.uuid) {
                    child = e;
                    child_found = true;
                }
            }

            if (!child_found) {
                energy_flow_request.children.push_back(e);
            }

            publish_complete_energy_object();
        });
    }

    if (!mod->r_powermeter.empty()) {
        mod->r_powermeter[0]->subscribe_powermeter([this](types::powermeter::Powermeter p) {
            EVLOG_debug << "Incoming powermeter readings: " << p;
            std::scoped_lock lock(energy_mutex);
            energy_flow_request.energy_usage_root = p;
            publish_complete_energy_object();
        });
    }

    if (!mod->r_price_information.empty()) {
        mod->r_price_information[0]->subscribe_energy_pricing(
            [this](types::energy_price_information::EnergyPriceSchedule p) {
                EVLOG_debug << "Incoming price schedule: " << p;
                std::scoped_lock lock(energy_mutex);
                energy_pricing = p;
                publish_complete_energy_object();
            });
    }
}

types::energy::ScheduleReqEntry energyImpl::get_local_schedule_req_entry() {
    // local schedule of this module
    types::energy::ScheduleReqEntry local_schedule;
    auto tp = date::utc_clock::now();

    local_schedule.timestamp =
        Everest::Date::to_rfc3339(date::floor<std::chrono::hours>(tp) + date::get_leap_second_info(tp).elapsed);
    local_schedule.limits_to_root.ac_max_phase_count = {mod->config.phase_count, source_cfg};
    local_schedule.limits_to_root.ac_max_current_A = {static_cast<float>(mod->config.fuse_limit_A), source_cfg};
    local_schedule.limits_to_leaves.ac_max_phase_count = {mod->config.phase_count, source_cfg};
    local_schedule.limits_to_leaves.ac_max_current_A = {static_cast<float>(mod->config.fuse_limit_A), source_cfg};

    return local_schedule;
}

std::vector<types::energy::ScheduleReqEntry> energyImpl::get_local_schedule() {
    const auto local_schedule = get_local_schedule_req_entry();
    return std::vector<types::energy::ScheduleReqEntry>({local_schedule});
}

void energyImpl::set_external_limits(types::energy::ExternalLimits& l) {
    std::scoped_lock lock(energy_mutex);

    energy_flow_request.schedule_import = l.schedule_import;
    if (not energy_flow_request.schedule_import.empty()) {
        // add limits from our own fuse settings
        for (auto& e : energy_flow_request.schedule_import) {
            if (!e.limits_to_root.ac_max_current_A.has_value() ||
                e.limits_to_root.ac_max_current_A.value().value > mod->config.fuse_limit_A)
                e.limits_to_root.ac_max_current_A = {static_cast<float>(mod->config.fuse_limit_A), source_cfg};

            if (!e.limits_to_root.ac_max_phase_count.has_value() ||
                e.limits_to_root.ac_max_phase_count.value().value > mod->config.phase_count)
                e.limits_to_root.ac_max_phase_count = {mod->config.phase_count, source_cfg};
        }
    } else {
        // At least add our local config limit even if the external limit did not set an import schedule
        energy_flow_request.schedule_import = get_local_schedule();
    }

    energy_flow_request.schedule_export = l.schedule_export;

    if (not energy_flow_request.schedule_export.empty()) {
        // add limits from our own fuse settings
        for (auto& e : energy_flow_request.schedule_export) {
            if (!e.limits_to_root.ac_max_current_A.has_value() ||
                e.limits_to_root.ac_max_current_A.value().value > mod->config.fuse_limit_A)
                e.limits_to_root.ac_max_current_A = {static_cast<float>(mod->config.fuse_limit_A), source_cfg};

            if (!e.limits_to_root.ac_max_phase_count.has_value() ||
                e.limits_to_root.ac_max_phase_count.value().value > mod->config.phase_count)
                e.limits_to_root.ac_max_phase_count = {mod->config.phase_count, source_cfg};
        }
    } else {
        // At least add our local config limit even if the external limit did not set an export schedule
        energy_flow_request.schedule_export = get_local_schedule();
    }

    energy_flow_request.schedule_setpoints = l.schedule_setpoints;
}

void energyImpl::publish_complete_energy_object() {
    // join the different schedules to the complete array (with resampling)
    types::energy::EnergyFlowRequest energy_complete = energy_flow_request;

    if (not energy_flow_request.schedule_export.empty() and not energy_pricing.schedule_export.empty()) {
        merge_price_into_schedule(energy_complete.schedule_export, energy_pricing.schedule_export);
    }

    publish_energy_flow_request(energy_complete);
}

void energyImpl::merge_price_into_schedule(std::vector<types::energy::ScheduleReqEntry>& schedule,
                                           const std::vector<types::energy_price_information::PricePerkWh>& price) {
    auto it_schedule = schedule.begin();
    auto it_price = price.begin();

    std::vector<types::energy::ScheduleReqEntry> joined_schedule;

    // The first element is already valid now even if the timestamp is in the future (per agreement)
    auto next_entry_schedule = *it_schedule;
    auto next_entry_price = *it_price;
    auto currently_valid_entry_schedule = next_entry_schedule;
    auto currently_valid_entry_price = next_entry_price;

    while (it_schedule != schedule.end() && it_price != price.end()) {
        auto tp_schedule = Everest::Date::from_rfc3339(next_entry_schedule.timestamp);
        auto tp_price = Everest::Date::from_rfc3339(next_entry_price.timestamp);

        if ((tp_schedule < tp_price && it_schedule != schedule.end()) || it_price == price.end()) {
            currently_valid_entry_schedule = next_entry_schedule;
            auto joined_entry = currently_valid_entry_schedule;

            joined_entry.price_per_kwh = currently_valid_entry_price;
            joined_schedule.push_back(joined_entry);
            it_schedule++;
            if (it_schedule != schedule.end()) {
                next_entry_schedule = *it_schedule;
            }
            continue;
        }

        if ((tp_price < tp_schedule && it_price != price.end()) || it_schedule == schedule.end()) {
            currently_valid_entry_price = next_entry_price;
            auto joined_entry = currently_valid_entry_schedule;
            joined_entry.price_per_kwh = currently_valid_entry_price;
            joined_entry.timestamp = currently_valid_entry_price.timestamp;
            joined_schedule.push_back(joined_entry);
            it_price++;
            if (it_price != price.end()) {
                next_entry_price = *it_price;
            }
            continue;
        }
    }
}

void energyImpl::ready() {
    // publish own limits at least once
    publish_energy_flow_request(energy_flow_request);
    mod->signalExternalLimit.connect([this](types::energy::ExternalLimits& l) { set_external_limits(l); });
}

std::optional<std::size_t> energyImpl::find_child_index_for_uuid_locked(const std::string& uuid) const {
    for (std::size_t index = 0; index < child_energy_flow_requests.size(); ++index) {
        if (child_energy_flow_requests[index].has_value() &&
            energy_flow_request_contains_uuid(child_energy_flow_requests[index].value(), uuid)) {
            return index;
        }
    }

    return std::nullopt;
}

void energyImpl::handle_enforce_limits(types::energy::EnforcedLimits& value) {

    // route to children if it is not for me
    if (value.uuid != energy_flow_request.uuid) {
        EVLOG_info << "[ENERGY_DIAG] energy_node enforce route begin node=" << energy_flow_request.uuid
                   << " target=" << value.uuid << " valid_for=" << value.valid_for
                   << "s children=" << mod->r_energy_consumer.size();

        std::optional<std::size_t> routed_child_index;
        {
            std::scoped_lock lock(energy_mutex);
            routed_child_index = find_child_index_for_uuid_locked(value.uuid);
        }

        if (routed_child_index.has_value() && routed_child_index.value() < mod->r_energy_consumer.size()) {
            const auto child_index = routed_child_index.value();
            EVLOG_info << "[ENERGY_DIAG] energy_node forward begin node=" << energy_flow_request.uuid
                       << " target=" << value.uuid << " child_index=" << child_index;
            const auto forward_start = std::chrono::steady_clock::now();
            mod->r_energy_consumer[child_index]->call_enforce_limits(value);
            const auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                         std::chrono::steady_clock::now() - forward_start)
                                         .count();
            EVLOG_info << "[ENERGY_DIAG] energy_node forward end node=" << energy_flow_request.uuid
                       << " target=" << value.uuid << " child_index=" << child_index
                       << " duration_ms=" << duration_ms;
        } else {
            EVLOG_warning << "[ENERGY_DIAG] energy_node target branch unknown, broadcasting fallback node="
                          << energy_flow_request.uuid << " target=" << value.uuid;
            int child_index = 0;
            for (auto& entry : mod->r_energy_consumer) {
                EVLOG_info << "[ENERGY_DIAG] energy_node forward begin node=" << energy_flow_request.uuid
                           << " target=" << value.uuid << " child_index=" << child_index;
                const auto forward_start = std::chrono::steady_clock::now();
                entry->call_enforce_limits(value);
                const auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                             std::chrono::steady_clock::now() - forward_start)
                                             .count();
                EVLOG_info << "[ENERGY_DIAG] energy_node forward end node=" << energy_flow_request.uuid
                           << " target=" << value.uuid << " child_index=" << child_index
                           << " duration_ms=" << duration_ms;
                child_index++;
            }
        }
        EVLOG_info << "[ENERGY_DIAG] energy_node enforce route end node=" << energy_flow_request.uuid
                   << " target=" << value.uuid;
    } else {
        EVLOG_info << "[ENERGY_DIAG] energy_node enforce consumed by node=" << energy_flow_request.uuid
                   << " target=" << value.uuid;
    }
};

} // namespace energy_grid
} // namespace module
