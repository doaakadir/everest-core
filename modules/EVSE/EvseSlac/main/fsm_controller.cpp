// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 - 2023 Pionix GmbH and Contributors to EVerest
#include "fsm_controller.hpp"

#include <everest/slac/fsm/evse/device_info.hpp>
#include <everest/slac/fsm/evse/states/others.hpp>

#include <optional>

FSMController::FSMController(slac::fsm::evse::Context& context) : ctx(context){};

bool FSMController::should_poll_qualcomm_op_attr() const {
    if (!ctx.slac_config.qualcomm_op_attr_polling || ctx.modem_vendor != slac::fsm::evse::ModemVendor::Qualcomm) {
        return false;
    }

    return ctx.internal_state == slac::fsm::evse::InternalState::Idle ||
           ctx.internal_state == slac::fsm::evse::InternalState::Matched;
}

bool FSMController::should_poll_qualcomm_nw_info() const {
    if (!ctx.slac_config.qualcomm_nw_info_polling || ctx.modem_vendor != slac::fsm::evse::ModemVendor::Qualcomm) {
        return false;
    }

    return ctx.internal_state == slac::fsm::evse::InternalState::Idle ||
           ctx.internal_state == slac::fsm::evse::InternalState::Matched;
}

std::chrono::seconds FSMController::get_qualcomm_op_attr_poll_interval() const {
    const auto interval_s =
        ctx.slac_config.qualcomm_op_attr_poll_interval_s > 0 ? ctx.slac_config.qualcomm_op_attr_poll_interval_s : 1;
    return std::chrono::seconds(interval_s);
}

void FSMController::poll_qualcomm_op_attr() {
    slac::messages::qualcomm::op_attr_req op_attr_req;
    ctx.send_slac_message(ctx.slac_config.plc_peer_mac, op_attr_req);
}

void FSMController::poll_qualcomm_nw_info() {
    slac::messages::qualcomm::nw_info_req nw_info_req;
    ctx.send_slac_message(ctx.slac_config.plc_peer_mac, nw_info_req);
}

void FSMController::signal_new_slac_message(slac::messages::HomeplugMessage& msg) {
    if (running == false) {
        return;
    }
    {
        const std::lock_guard<std::mutex> feed_lck(feed_mtx);
        const auto mmtype = msg.get_mmtype();
        if (ctx.slac_config.qualcomm_op_attr_polling &&
            ctx.modem_vendor == slac::fsm::evse::ModemVendor::Qualcomm &&
            mmtype == (slac::defs::qualcomm::MMTYPE_OP_ATTR | slac::defs::MMTYPE_MODE_CNF)) {
            const auto device_info = slac::fsm::evse::get_qualcomm_device_info_debug(msg);
            ctx.log_info(device_info);
        } else if (ctx.slac_config.qualcomm_nw_info_polling &&
                   ctx.modem_vendor == slac::fsm::evse::ModemVendor::Qualcomm &&
                   mmtype == (slac::defs::qualcomm::MMTYPE_NW_INFO | slac::defs::MMTYPE_MODE_CNF)) {
            const auto nw_info = slac::fsm::evse::get_qualcomm_nw_info_debug(msg);
            ctx.log_info(nw_info);
        }
        ctx.slac_message_payload = msg;
        fsm.handle_event(slac::fsm::evse::Event::SLAC_MESSAGE);
    }

    new_event = true;
    new_event_cv.notify_all();
}

void FSMController::signal_reset() {
    signal_simple_event(slac::fsm::evse::Event::RESET);
}

bool FSMController::signal_enter_bcd() {
    return signal_simple_event(slac::fsm::evse::Event::ENTER_BCD);
}

bool FSMController::signal_leave_bcd() {
    return signal_simple_event(slac::fsm::evse::Event::LEAVE_BCD);
}

bool FSMController::signal_simple_event(slac::fsm::evse::Event ev) {
    const std::lock_guard<std::mutex> feed_lck(feed_mtx);
    auto event_result = fsm.handle_event(ev);

    new_event = true;
    new_event_cv.notify_all();

    return event_result == fsm::HandleEventResult::SUCCESS;
}

void FSMController::run() {
    ctx.log_info("Starting the SLAC state machine");

    fsm.reset<slac::fsm::evse::InitState>(ctx);

    std::unique_lock<std::mutex> feed_lck(feed_mtx);

    running = true;
    next_qualcomm_op_attr_poll = std::chrono::steady_clock::now() + get_qualcomm_op_attr_poll_interval();

    while (true) {
        auto feed_result = fsm.feed();

        if (feed_result.transition()) {
            // call immediately again
            continue;
        } else if (feed_result.internal_error() || feed_result.unhandled_event()) {
            // FIXME (aw): would need to log here!
        }

        std::optional<std::chrono::milliseconds> wait_timeout;
        if (feed_result.has_value() == true) {
            wait_timeout = std::chrono::milliseconds(*feed_result);
        }

        if (ctx.slac_config.qualcomm_op_attr_polling || ctx.slac_config.qualcomm_nw_info_polling) {
            const auto now = std::chrono::steady_clock::now();
            const auto poll_timeout =
                next_qualcomm_op_attr_poll > now
                    ? std::chrono::duration_cast<std::chrono::milliseconds>(next_qualcomm_op_attr_poll - now)
                    : std::chrono::milliseconds(0);

            if (!wait_timeout.has_value() || poll_timeout < *wait_timeout) {
                wait_timeout = poll_timeout;
            }
        }

        if (wait_timeout.has_value()) {
            const auto timeout = wait_timeout->count();
            if (timeout == 0) {
                if ((ctx.slac_config.qualcomm_op_attr_polling || ctx.slac_config.qualcomm_nw_info_polling) &&
                    std::chrono::steady_clock::now() >= next_qualcomm_op_attr_poll) {
                    if (should_poll_qualcomm_op_attr()) {
                        poll_qualcomm_op_attr();
                    }
                    if (should_poll_qualcomm_nw_info()) {
                        poll_qualcomm_nw_info();
                    }
                    next_qualcomm_op_attr_poll = std::chrono::steady_clock::now() + get_qualcomm_op_attr_poll_interval();
                }
                continue;
            }
            new_event_cv.wait_for(feed_lck, std::chrono::milliseconds(timeout), [this] { return new_event; });
        } else {
            // nothing happened, no return value -> wait for new event
            new_event_cv.wait(feed_lck, [this] { return new_event; });
        }

        if (new_event) {
            // we got a new event, reset it and let run feed again
            new_event = false;
        } else if ((ctx.slac_config.qualcomm_op_attr_polling || ctx.slac_config.qualcomm_nw_info_polling) &&
                   std::chrono::steady_clock::now() >= next_qualcomm_op_attr_poll) {
            if (should_poll_qualcomm_op_attr()) {
                poll_qualcomm_op_attr();
            }
            if (should_poll_qualcomm_nw_info()) {
                poll_qualcomm_nw_info();
            }
            next_qualcomm_op_attr_poll = std::chrono::steady_clock::now() + get_qualcomm_op_attr_poll_interval();
        }
    }
}
