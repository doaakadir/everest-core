// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 - 2023 Pionix GmbH and Contributors to EVerest
#include "fsm_controller.hpp"

#include <everest/slac/fsm/evse/device_info.hpp>
#include <everest/slac/fsm/evse/states/others.hpp>

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

void FSMController::qualcomm_poll_loop() {
    while (running) {
        std::this_thread::sleep_for(get_qualcomm_op_attr_poll_interval());

        if (!running) {
            break;
        }

        std::unique_lock<std::mutex> feed_lck(feed_mtx, std::try_to_lock);
        if (!feed_lck.owns_lock()) {
            continue;
        }

        if (should_poll_qualcomm_op_attr()) {
            poll_qualcomm_op_attr();
        }
        if (should_poll_qualcomm_nw_info()) {
            poll_qualcomm_nw_info();
        }
    }
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
            const auto device_info =
                slac::fsm::evse::get_qualcomm_device_info_debug(msg, ctx.slac_config.qualcomm_debug_dump_max_bytes);
            ctx.log_info(device_info);
        } else if (ctx.slac_config.qualcomm_nw_info_polling &&
                   ctx.modem_vendor == slac::fsm::evse::ModemVendor::Qualcomm &&
                   mmtype == (slac::defs::qualcomm::MMTYPE_NW_INFO | slac::defs::MMTYPE_MODE_CNF)) {
            const auto nw_info =
                slac::fsm::evse::get_qualcomm_nw_info_debug(msg, ctx.slac_config.qualcomm_debug_dump_max_bytes);
            ctx.log_info(nw_info);
        }
        ctx.slac_message_payload = msg;
        fsm.handle_event(slac::fsm::evse::Event::SLAC_MESSAGE);
        new_event = true;
    }
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
    fsm::HandleEventResult event_result;
    {
        const std::lock_guard<std::mutex> feed_lck(feed_mtx);
        event_result = fsm.handle_event(ev);
        new_event = true;
    }
    new_event_cv.notify_all();

    return event_result == fsm::HandleEventResult::SUCCESS;
}

/*
bool FSMController::signal_simple_event(slac::fsm::evse::Event ev) {
    const std::lock_guard<std::mutex> feed_lck(feed_mtx);
    auto event_result = fsm.handle_event(ev);

    new_event = true;
    new_event_cv.notify_all();

    return event_result == fsm::HandleEventResult::SUCCESS;
}
*/


void FSMController::run() {
    ctx.log_info("Starting the SLAC state machine");

    fsm.reset<slac::fsm::evse::InitState>(ctx);

    std::unique_lock<std::mutex> feed_lck(feed_mtx);

    running = true;

    if (ctx.slac_config.qualcomm_op_attr_polling || ctx.slac_config.qualcomm_nw_info_polling) {
        qualcomm_poll_thread = std::thread(&FSMController::qualcomm_poll_loop, this);
        qualcomm_poll_thread.detach();
    }

    while (true) {
        auto feed_result = fsm.feed();

        if (feed_result.transition()) {
            // call immediately again
            continue;
        } else if (feed_result.internal_error() || feed_result.unhandled_event()) {
            // FIXME (aw): would need to log here!
        } else if (feed_result.has_value() == true) {
            const auto timeout = *feed_result;
            if (timeout == 0) {
                // call feed directly again
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
        }
    }
}