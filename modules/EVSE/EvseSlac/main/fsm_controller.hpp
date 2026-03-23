// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 - 2023 Pionix GmbH and Contributors to EVerest
#ifndef EVSE_SLAC_FSM_CONTROLLER_HPP
#define EVSE_SLAC_FSM_CONTROLLER_HPP

#include <everest/slac/fsm/evse/fsm.hpp>

#include <chrono>
#include <condition_variable>
#include <mutex>

class FSMController {
public:
    explicit FSMController(slac::fsm::evse::Context& ctx);

    void signal_new_slac_message(slac::messages::HomeplugMessage&);
    void signal_reset();
    bool signal_enter_bcd();
    bool signal_leave_bcd();
    void run();

private:
    static constexpr auto qualcomm_op_attr_poll_interval = std::chrono::seconds(10);

    bool signal_simple_event(slac::fsm::evse::Event ev);
    bool should_poll_qualcomm_op_attr() const;
    void poll_qualcomm_op_attr();
    slac::fsm::evse::Context& ctx;
    slac::fsm::evse::FSM fsm;

    bool running{false};

    std::mutex feed_mtx;
    std::condition_variable new_event_cv;
    bool new_event{false};
    std::chrono::steady_clock::time_point next_qualcomm_op_attr_poll{};
};

#endif // EVSE_SLAC_FSM_CONTROLLER_HPP
