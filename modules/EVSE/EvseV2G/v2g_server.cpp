// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023 chargebyte GmbH
// Copyright (C) 2023 Contributors to EVerest
#include "v2g_server.hpp"

#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <inttypes.h>
#include <nlohmann/json.hpp>
#include <string.h>
#include <unistd.h>

#include <cbv2g/app_handshake/appHand_Decoder.h>
#include <cbv2g/app_handshake/appHand_Encoder.h>
#include <cbv2g/common/exi_basetypes.h>
#include <cbv2g/din/din_msgDefDecoder.h>
#include <cbv2g/din/din_msgDefEncoder.h>
#include <cbv2g/exi_v2gtp.h>
#include <cbv2g/iso_2/iso2_msgDefDecoder.h>
#include <cbv2g/iso_2/iso2_msgDefEncoder.h>

#include "connection.hpp"
#include "din_server.hpp"
#include "iso_server.hpp"
#include "log.hpp"
#include "tools.hpp"

#define MAX_RES_TIME 98

static types::iso15118::V2gMessageId get_v2g_message_id(enum V2gMsgTypeId v2g_msg, enum v2g_protocol selected_protocol,
                                                        bool is_req) {
    switch (v2g_msg) {
    case V2G_SUPPORTED_APP_PROTOCOL_MSG:
        return is_req == true ? types::iso15118::V2gMessageId::SupportedAppProtocolReq
                              : types::iso15118::V2gMessageId::SupportedAppProtocolRes;
    case V2G_SESSION_SETUP_MSG:
        return is_req == true ? types::iso15118::V2gMessageId::SessionSetupReq
                              : types::iso15118::V2gMessageId::SessionSetupRes;
    case V2G_SERVICE_DISCOVERY_MSG:
        return is_req == true ? types::iso15118::V2gMessageId::ServiceDiscoveryReq
                              : types::iso15118::V2gMessageId::ServiceDiscoveryRes;
    case V2G_SERVICE_DETAIL_MSG:
        return is_req == true ? types::iso15118::V2gMessageId::ServiceDetailReq
                              : types::iso15118::V2gMessageId::ServiceDetailRes;
    case V2G_PAYMENT_SERVICE_SELECTION_MSG:
        return is_req == true                            ? selected_protocol == V2G_PROTO_DIN70121
                                                               ? types::iso15118::V2gMessageId::ServicePaymentSelectionReq
                                                               : types::iso15118::V2gMessageId::PaymentServiceSelectionReq
               : selected_protocol == V2G_PROTO_DIN70121 ? types::iso15118::V2gMessageId::ServicePaymentSelectionRes
                                                         : types::iso15118::V2gMessageId::PaymentServiceSelectionRes;
    case V2G_PAYMENT_DETAILS_MSG:
        return is_req == true ? types::iso15118::V2gMessageId::PaymentDetailsReq
                              : types::iso15118::V2gMessageId::PaymentDetailsRes;
    case V2G_AUTHORIZATION_MSG:
        return is_req == true                            ? selected_protocol == V2G_PROTO_DIN70121
                                                               ? types::iso15118::V2gMessageId::ContractAuthenticationReq
                                                               : types::iso15118::V2gMessageId::AuthorizationReq
               : selected_protocol == V2G_PROTO_DIN70121 ? types::iso15118::V2gMessageId::ContractAuthenticationRes
                                                         : types::iso15118::V2gMessageId::AuthorizationRes;
    case V2G_CHARGE_PARAMETER_DISCOVERY_MSG:
        return is_req == true ? types::iso15118::V2gMessageId::ChargeParameterDiscoveryReq
                              : types::iso15118::V2gMessageId::ChargeParameterDiscoveryRes;
    case V2G_METERING_RECEIPT_MSG:
        return is_req == true ? types::iso15118::V2gMessageId::MeteringReceiptReq
                              : types::iso15118::V2gMessageId::MeteringReceiptRes;
    case V2G_CERTIFICATE_UPDATE_MSG:
        return is_req == true ? types::iso15118::V2gMessageId::CertificateUpdateReq
                              : types::iso15118::V2gMessageId::CertificateUpdateRes;
    case V2G_CERTIFICATE_INSTALLATION_MSG:
        return is_req == true ? types::iso15118::V2gMessageId::CertificateInstallationReq
                              : types::iso15118::V2gMessageId::CertificateInstallationRes;
    case V2G_CHARGING_STATUS_MSG:
        return is_req == true ? types::iso15118::V2gMessageId::ChargingStatusReq
                              : types::iso15118::V2gMessageId::ChargingStatusRes;
    case V2G_CABLE_CHECK_MSG:
        return is_req == true ? types::iso15118::V2gMessageId::CableCheckReq
                              : types::iso15118::V2gMessageId::CableCheckRes;
    case V2G_PRE_CHARGE_MSG:
        return is_req == true ? types::iso15118::V2gMessageId::PreChargeReq
                              : types::iso15118::V2gMessageId::PreChargeRes;
    case V2G_POWER_DELIVERY_MSG:
        return is_req == true ? types::iso15118::V2gMessageId::PowerDeliveryReq
                              : types::iso15118::V2gMessageId::PowerDeliveryRes;
    case V2G_CURRENT_DEMAND_MSG:
        return is_req == true ? types::iso15118::V2gMessageId::CurrentDemandReq
                              : types::iso15118::V2gMessageId::CurrentDemandRes;
    case V2G_WELDING_DETECTION_MSG:
        return is_req == true ? types::iso15118::V2gMessageId::WeldingDetectionReq
                              : types::iso15118::V2gMessageId::WeldingDetectionRes;
    case V2G_SESSION_STOP_MSG:
        return is_req == true ? types::iso15118::V2gMessageId::SessionStopReq
                              : types::iso15118::V2gMessageId::SessionStopRes;
    case V2G_UNKNOWN_MSG:
    default:
        return types::iso15118::V2gMessageId::UnknownMessage;
    }
}

namespace {

using json = nlohmann::json;

static const char* protocol_to_string(const enum v2g_protocol protocol) {
    switch (protocol) {
    case V2G_PROTO_DIN70121:
        return "DIN70121";
    case V2G_PROTO_ISO15118_2010:
        return "ISO15118-2-2010";
    case V2G_PROTO_ISO15118_2013:
        return "ISO15118-2-2013";
    case V2G_UNKNOWN_PROTOCOL:
    default:
        return "Unknown";
    }
}

static std::string bytes_to_hex(const uint8_t* bytes, const size_t len) {
    std::string hex_string;
    hex_string.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        char hex[3];
        snprintf(hex, sizeof(hex), "%02x", bytes[i]);
        hex_string += hex;
    }
    return hex_string;
}

template <typename T> static std::string bytes_field_to_hex(const T& value) {
    return bytes_to_hex(value.bytes, value.bytesLen);
}

template <typename T> static std::string characters_to_string(const T& value) {
    return std::string(reinterpret_cast<const char*>(value.characters), value.charactersLen);
}

template <typename T> static double physical_value_to_double(const T& value) {
    return calc_physical_value(value.Value, value.Multiplier);
}

template <typename T> static json physical_value_to_json(const T& value, const char* unit) {
    return {{"value", physical_value_to_double(value)}, {"unit", unit}};
}

template <typename T> static void add_physical_value(json& target, const char* key, const T& value, const char* unit) {
    target[key] = physical_value_to_json(value, unit);
}

static const char* v2g_message_type_to_string(const enum V2gMsgTypeId message_type) {
    const auto idx = static_cast<size_t>(message_type);
    return idx < ARRAY_SIZE(v2g_msg_type) ? v2g_msg_type[idx] : "Unknown";
}

template <typename ResponseCodeT, size_t N>
static json response_code_to_json(const ResponseCodeT code, const char* const (&names)[N]) {
    const auto idx = static_cast<size_t>(code);
    return {{"raw", static_cast<int>(code)}, {"name", idx < N ? names[idx] : "Unknown"}};
}

static json iso_dc_ev_status_to_json(const iso2_DC_EVStatusType& status) {
    return {{"ev_ready", static_cast<bool>(status.EVReady)},
            {"ev_error_code", static_cast<int>(status.EVErrorCode)},
            {"soc_percent", static_cast<int>(status.EVRESSSOC)}};
}

static json din_dc_ev_status_to_json(const din_DC_EVStatusType& status) {
    return {{"ev_ready", static_cast<bool>(status.EVReady)},
            {"ev_error_code", static_cast<int>(status.EVErrorCode)},
            {"soc_percent", static_cast<int>(status.EVRESSSOC)}};
}

static json iso_dc_evse_status_to_json(const iso2_DC_EVSEStatusType& status) {
    json out = {{"evse_notification", static_cast<int>(status.EVSENotification)},
                {"evse_status_code", static_cast<int>(status.EVSEStatusCode)},
                {"notification_max_delay_s", status.NotificationMaxDelay}};
    if (status.EVSEIsolationStatus_isUsed == 1) {
        out["evse_isolation_status"] = static_cast<int>(status.EVSEIsolationStatus);
    }
    return out;
}

static json din_dc_evse_status_to_json(const din_DC_EVSEStatusType& status) {
    json out = {{"evse_notification", static_cast<int>(status.EVSENotification)},
                {"evse_status_code", static_cast<int>(status.EVSEStatusCode)},
                {"notification_max_delay_s", status.NotificationMaxDelay}};
    if (status.EVSEIsolationStatus_isUsed == 1) {
        out["evse_isolation_status"] = static_cast<int>(status.EVSEIsolationStatus);
    }
    return out;
}

static json build_app_handshake_json(const v2g_connection* conn, const bool is_req) {
    json payload;
    if (is_req) {
        json protocols = json::array();
        const auto& req = conn->handshake_req.supportedAppProtocolReq;
        for (uint16_t i = 0; i < req.AppProtocol.arrayLen; i++) {
            const auto& app_proto = req.AppProtocol.array[i];
            protocols.push_back({{"namespace", characters_to_string(app_proto.ProtocolNamespace)},
                                 {"version_major", app_proto.VersionNumberMajor},
                                 {"version_minor", app_proto.VersionNumberMinor},
                                 {"schema_id", app_proto.SchemaID},
                                 {"priority", app_proto.Priority}});
        }
        payload["app_protocols"] = protocols;
    } else {
        const auto& res = conn->handshake_resp.supportedAppProtocolRes;
        payload["response_code"] = static_cast<int>(res.ResponseCode);
        if (res.SchemaID_isUsed == 1) {
            payload["schema_id"] = res.SchemaID;
        }
    }
    return payload;
}

static json build_iso_request_payload(const v2g_connection* conn) {
    const auto& body = conn->exi_in.iso2EXIDocument->V2G_Message.Body;
    switch (conn->ctx->current_v2g_msg) {
    case V2G_SESSION_SETUP_MSG:
        return {{"evcc_id", bytes_field_to_hex(body.SessionSetupReq.EVCCID)}};

    case V2G_SERVICE_DISCOVERY_MSG: {
        json payload;
        if (body.ServiceDiscoveryReq.ServiceScope_isUsed == 1) {
            payload["service_scope"] = characters_to_string(body.ServiceDiscoveryReq.ServiceScope);
        }
        if (body.ServiceDiscoveryReq.ServiceCategory_isUsed == 1) {
            payload["service_category"] = static_cast<int>(body.ServiceDiscoveryReq.ServiceCategory);
        }
        return payload;
    }

    case V2G_SERVICE_DETAIL_MSG:
        return {{"service_id", body.ServiceDetailReq.ServiceID}};

    case V2G_PAYMENT_SERVICE_SELECTION_MSG:
        return {{"selected_payment_option", static_cast<int>(body.PaymentServiceSelectionReq.SelectedPaymentOption)},
                {"selected_service_count",
                 body.PaymentServiceSelectionReq.SelectedServiceList.SelectedService.arrayLen}};

    case V2G_PAYMENT_DETAILS_MSG: {
        const auto& req = body.PaymentDetailsReq;
        json payload = {{"emaid", characters_to_string(req.eMAID)},
                        {"contract_certificate_bytes", req.ContractSignatureCertChain.Certificate.bytesLen},
                        {"sub_certificates_used",
                         static_cast<bool>(req.ContractSignatureCertChain.SubCertificates_isUsed)}};
        if (req.ContractSignatureCertChain.SubCertificates_isUsed == 1) {
            payload["sub_certificate_count"] = req.ContractSignatureCertChain.SubCertificates.Certificate.arrayLen;
        }
        return payload;
    }

    case V2G_AUTHORIZATION_MSG:
        return {{"gen_challenge_used", static_cast<bool>(body.AuthorizationReq.GenChallenge_isUsed)},
                {"id_used", static_cast<bool>(body.AuthorizationReq.Id_isUsed)}};

    case V2G_CHARGE_PARAMETER_DISCOVERY_MSG: {
        const auto& req = body.ChargeParameterDiscoveryReq;
        json payload = {{"requested_energy_transfer_mode", static_cast<int>(req.RequestedEnergyTransferMode)}};
        if (req.MaxEntriesSAScheduleTuple_isUsed == 1) {
            payload["max_entries_sa_schedule_tuple"] = req.MaxEntriesSAScheduleTuple;
        }
        if (req.AC_EVChargeParameter_isUsed == 1) {
            json ac;
            const auto& ac_param = req.AC_EVChargeParameter;
            if (ac_param.DepartureTime_isUsed == 1) {
                ac["departure_time_s"] = ac_param.DepartureTime;
            }
            add_physical_value(ac, "energy_amount", ac_param.EAmount, "Wh");
            add_physical_value(ac, "ev_max_voltage", ac_param.EVMaxVoltage, "V");
            add_physical_value(ac, "ev_max_current", ac_param.EVMaxCurrent, "A");
            add_physical_value(ac, "ev_min_current", ac_param.EVMinCurrent, "A");
            payload["ac_ev_charge_parameter"] = ac;
        }
        if (req.DC_EVChargeParameter_isUsed == 1) {
            json dc;
            const auto& dc_param = req.DC_EVChargeParameter;
            if (dc_param.DepartureTime_isUsed == 1) {
                dc["departure_time_s"] = dc_param.DepartureTime;
            }
            if (dc_param.EVEnergyCapacity_isUsed == 1) {
                add_physical_value(dc, "ev_energy_capacity", dc_param.EVEnergyCapacity, "Wh");
            }
            if (dc_param.EVEnergyRequest_isUsed == 1) {
                add_physical_value(dc, "ev_energy_request", dc_param.EVEnergyRequest, "Wh");
            }
            if (dc_param.FullSOC_isUsed == 1) {
                dc["full_soc_percent"] = dc_param.FullSOC;
            }
            if (dc_param.BulkSOC_isUsed == 1) {
                dc["bulk_soc_percent"] = dc_param.BulkSOC;
            }
            add_physical_value(dc, "ev_max_current", dc_param.EVMaximumCurrentLimit, "A");
            if (dc_param.EVMaximumPowerLimit_isUsed == 1) {
                add_physical_value(dc, "ev_max_power", dc_param.EVMaximumPowerLimit, "W");
            }
            add_physical_value(dc, "ev_max_voltage", dc_param.EVMaximumVoltageLimit, "V");
            dc["dc_ev_status"] = iso_dc_ev_status_to_json(dc_param.DC_EVStatus);
            payload["dc_ev_charge_parameter"] = dc;
        }
        return payload;
    }

    case V2G_CABLE_CHECK_MSG:
        return {{"dc_ev_status", iso_dc_ev_status_to_json(body.CableCheckReq.DC_EVStatus)}};

    case V2G_PRE_CHARGE_MSG: {
        const auto& req = body.PreChargeReq;
        json payload = {{"dc_ev_status", iso_dc_ev_status_to_json(req.DC_EVStatus)}};
        add_physical_value(payload, "ev_target_voltage", req.EVTargetVoltage, "V");
        add_physical_value(payload, "ev_target_current", req.EVTargetCurrent, "A");
        return payload;
    }

    case V2G_POWER_DELIVERY_MSG: {
        const auto& req = body.PowerDeliveryReq;
        json payload = {{"charge_progress", static_cast<int>(req.ChargeProgress)},
                        {"sa_schedule_tuple_id", req.SAScheduleTupleID},
                        {"charging_profile_used", static_cast<bool>(req.ChargingProfile_isUsed)}};
        if (req.DC_EVPowerDeliveryParameter_isUsed == 1) {
            const auto& dc = req.DC_EVPowerDeliveryParameter;
            payload["dc_ev_power_delivery_parameter"] = {
                {"charging_complete", static_cast<bool>(dc.ChargingComplete)},
                {"bulk_charging_complete_used", static_cast<bool>(dc.BulkChargingComplete_isUsed)},
                {"dc_ev_status", iso_dc_ev_status_to_json(dc.DC_EVStatus)}};
            if (dc.BulkChargingComplete_isUsed == 1) {
                payload["dc_ev_power_delivery_parameter"]["bulk_charging_complete"] =
                    static_cast<bool>(dc.BulkChargingComplete);
            }
        }
        return payload;
    }

    case V2G_CURRENT_DEMAND_MSG: {
        const auto& req = body.CurrentDemandReq;
        json payload = {{"dc_ev_status", iso_dc_ev_status_to_json(req.DC_EVStatus)},
                        {"charging_complete", static_cast<bool>(req.ChargingComplete)},
                        {"bulk_charging_complete_used", static_cast<bool>(req.BulkChargingComplete_isUsed)}};
        if (req.BulkChargingComplete_isUsed == 1) {
            payload["bulk_charging_complete"] = static_cast<bool>(req.BulkChargingComplete);
        }
        add_physical_value(payload, "ev_target_voltage", req.EVTargetVoltage, "V");
        add_physical_value(payload, "ev_target_current", req.EVTargetCurrent, "A");
        if (req.EVMaximumCurrentLimit_isUsed == 1) {
            add_physical_value(payload, "ev_max_current", req.EVMaximumCurrentLimit, "A");
        }
        if (req.EVMaximumPowerLimit_isUsed == 1) {
            add_physical_value(payload, "ev_max_power", req.EVMaximumPowerLimit, "W");
        }
        if (req.EVMaximumVoltageLimit_isUsed == 1) {
            add_physical_value(payload, "ev_max_voltage", req.EVMaximumVoltageLimit, "V");
        }
        if (req.RemainingTimeToFullSoC_isUsed == 1) {
            add_physical_value(payload, "remaining_time_to_full_soc", req.RemainingTimeToFullSoC, "s");
        }
        if (req.RemainingTimeToBulkSoC_isUsed == 1) {
            add_physical_value(payload, "remaining_time_to_bulk_soc", req.RemainingTimeToBulkSoC, "s");
        }
        return payload;
    }

    case V2G_METERING_RECEIPT_MSG: {
        const auto& req = body.MeteringReceiptReq;
        json payload = {{"id", characters_to_string(req.Id)},
                        {"sa_schedule_tuple_id", req.SAScheduleTupleID},
                        {"session_id", bytes_field_to_hex(req.SessionID)},
                        {"meter_status", req.MeterInfo.MeterStatus},
                        {"meter_id", characters_to_string(req.MeterInfo.MeterID)},
                        {"meter_reading_used", static_cast<bool>(req.MeterInfo.MeterReading_isUsed)},
                        {"t_meter", req.MeterInfo.TMeter}};
        if (req.MeterInfo.MeterReading_isUsed == 1) {
            payload["meter_reading"] = req.MeterInfo.MeterReading;
        }
        return payload;
    }

    case V2G_WELDING_DETECTION_MSG:
        return {{"dc_ev_status", iso_dc_ev_status_to_json(body.WeldingDetectionReq.DC_EVStatus)}};

    case V2G_SESSION_STOP_MSG:
        return {{"charging_session", static_cast<int>(body.SessionStopReq.ChargingSession)}};

    default:
        return json::object();
    }
}

static json build_iso_response_payload(const v2g_connection* conn) {
    const auto& body = conn->exi_out.iso2EXIDocument->V2G_Message.Body;
    switch (conn->ctx->current_v2g_msg) {
    case V2G_SESSION_SETUP_MSG: {
        const auto& res = body.SessionSetupRes;
        json payload = {{"response_code", response_code_to_json(res.ResponseCode, isoResponse)},
                        {"evse_id", characters_to_string(res.EVSEID)}};
        if (res.EVSETimeStamp_isUsed == 1) {
            payload["evse_timestamp"] = res.EVSETimeStamp;
        }
        return payload;
    }

    case V2G_SERVICE_DISCOVERY_MSG: {
        const auto& res = body.ServiceDiscoveryRes;
        return {{"response_code", response_code_to_json(res.ResponseCode, isoResponse)},
                {"payment_option_count", res.PaymentOptionList.PaymentOption.arrayLen},
                {"charge_service_id", res.ChargeService.ServiceID},
                {"charge_service_free", static_cast<bool>(res.ChargeService.FreeService)}};
    }

    case V2G_SERVICE_DETAIL_MSG:
        return {{"response_code", response_code_to_json(body.ServiceDetailRes.ResponseCode, isoResponse)},
                {"service_id", body.ServiceDetailRes.ServiceID}};

    case V2G_PAYMENT_SERVICE_SELECTION_MSG:
        return {{"response_code", response_code_to_json(body.PaymentServiceSelectionRes.ResponseCode, isoResponse)}};

    case V2G_PAYMENT_DETAILS_MSG:
        return {{"response_code", response_code_to_json(body.PaymentDetailsRes.ResponseCode, isoResponse)},
                {"evse_time_stamp", body.PaymentDetailsRes.EVSETimeStamp}};

    case V2G_AUTHORIZATION_MSG:
        return {{"response_code", response_code_to_json(body.AuthorizationRes.ResponseCode, isoResponse)},
                {"evse_processing", static_cast<int>(body.AuthorizationRes.EVSEProcessing)}};

    case V2G_CHARGE_PARAMETER_DISCOVERY_MSG: {
        const auto& res = body.ChargeParameterDiscoveryRes;
        json payload = {{"response_code", response_code_to_json(res.ResponseCode, isoResponse)},
                        {"evse_processing", static_cast<int>(res.EVSEProcessing)},
                        {"sa_schedule_list_used", static_cast<bool>(res.SAScheduleList_isUsed)}};
        if (res.DC_EVSEChargeParameter_isUsed == 1) {
            const auto& dc = res.DC_EVSEChargeParameter;
            json dc_json = {{"dc_evse_status", iso_dc_evse_status_to_json(dc.DC_EVSEStatus)}};
            add_physical_value(dc_json, "evse_max_current", dc.EVSEMaximumCurrentLimit, "A");
            add_physical_value(dc_json, "evse_max_power", dc.EVSEMaximumPowerLimit, "W");
            add_physical_value(dc_json, "evse_max_voltage", dc.EVSEMaximumVoltageLimit, "V");
            add_physical_value(dc_json, "evse_min_current", dc.EVSEMinimumCurrentLimit, "A");
            add_physical_value(dc_json, "evse_min_voltage", dc.EVSEMinimumVoltageLimit, "V");
            payload["dc_evse_charge_parameter"] = dc_json;
        }
        if (res.AC_EVSEChargeParameter_isUsed == 1) {
            const auto& ac = res.AC_EVSEChargeParameter;
            json ac_json;
            add_physical_value(ac_json, "evse_max_current", ac.EVSEMaxCurrent, "A");
            add_physical_value(ac_json, "evse_nominal_voltage", ac.EVSENominalVoltage, "V");
            payload["ac_evse_charge_parameter"] = ac_json;
        }
        return payload;
    }

    case V2G_CHARGING_STATUS_MSG: {
        const auto& res = body.ChargingStatusRes;
        json payload = {{"response_code", response_code_to_json(res.ResponseCode, isoResponse)},
                        {"evse_id", characters_to_string(res.EVSEID)},
                        {"receipt_required", static_cast<bool>(res.ReceiptRequired)},
                        {"sa_schedule_tuple_id", res.SAScheduleTupleID}};
        if (res.EVSEMaxCurrent_isUsed == 1) {
            add_physical_value(payload, "evse_max_current", res.EVSEMaxCurrent, "A");
        }
        return payload;
    }

    case V2G_METERING_RECEIPT_MSG:
        return {{"response_code", response_code_to_json(body.MeteringReceiptRes.ResponseCode, isoResponse)}};

    case V2G_CABLE_CHECK_MSG:
        return {{"response_code", response_code_to_json(body.CableCheckRes.ResponseCode, isoResponse)},
                {"evse_processing", static_cast<int>(body.CableCheckRes.EVSEProcessing)},
                {"dc_evse_status", iso_dc_evse_status_to_json(body.CableCheckRes.DC_EVSEStatus)}};

    case V2G_PRE_CHARGE_MSG: {
        const auto& res = body.PreChargeRes;
        json payload = {{"response_code", response_code_to_json(res.ResponseCode, isoResponse)},
                        {"dc_evse_status", iso_dc_evse_status_to_json(res.DC_EVSEStatus)}};
        add_physical_value(payload, "evse_present_voltage", res.EVSEPresentVoltage, "V");
        return payload;
    }

    case V2G_POWER_DELIVERY_MSG: {
        const auto& res = body.PowerDeliveryRes;
        json payload = {{"response_code", response_code_to_json(res.ResponseCode, isoResponse)}};
        if (res.DC_EVSEStatus_isUsed == 1) {
            payload["dc_evse_status"] = iso_dc_evse_status_to_json(res.DC_EVSEStatus);
        }
        return payload;
    }

    case V2G_CURRENT_DEMAND_MSG: {
        const auto& res = body.CurrentDemandRes;
        json payload = {{"response_code", response_code_to_json(res.ResponseCode, isoResponse)},
                        {"dc_evse_status", iso_dc_evse_status_to_json(res.DC_EVSEStatus)},
                        {"current_limit_achieved", static_cast<bool>(res.EVSECurrentLimitAchieved)},
                        {"voltage_limit_achieved", static_cast<bool>(res.EVSEVoltageLimitAchieved)},
                        {"power_limit_achieved", static_cast<bool>(res.EVSEPowerLimitAchieved)},
                        {"receipt_required_used", static_cast<bool>(res.ReceiptRequired_isUsed)},
                        {"sa_schedule_tuple_id", res.SAScheduleTupleID}};
        add_physical_value(payload, "evse_present_voltage", res.EVSEPresentVoltage, "V");
        add_physical_value(payload, "evse_present_current", res.EVSEPresentCurrent, "A");
        if (res.EVSEMaximumCurrentLimit_isUsed == 1) {
            add_physical_value(payload, "evse_max_current", res.EVSEMaximumCurrentLimit, "A");
        }
        if (res.EVSEMaximumPowerLimit_isUsed == 1) {
            add_physical_value(payload, "evse_max_power", res.EVSEMaximumPowerLimit, "W");
        }
        if (res.EVSEMaximumVoltageLimit_isUsed == 1) {
            add_physical_value(payload, "evse_max_voltage", res.EVSEMaximumVoltageLimit, "V");
        }
        if (res.ReceiptRequired_isUsed == 1) {
            payload["receipt_required"] = static_cast<bool>(res.ReceiptRequired);
        }
        return payload;
    }

    case V2G_WELDING_DETECTION_MSG: {
        const auto& res = body.WeldingDetectionRes;
        json payload = {{"response_code", response_code_to_json(res.ResponseCode, isoResponse)},
                        {"dc_evse_status", iso_dc_evse_status_to_json(res.DC_EVSEStatus)}};
        add_physical_value(payload, "evse_present_voltage", res.EVSEPresentVoltage, "V");
        return payload;
    }

    case V2G_SESSION_STOP_MSG:
        return {{"response_code", response_code_to_json(body.SessionStopRes.ResponseCode, isoResponse)}};

    default:
        return json::object();
    }
}

static json build_din_request_payload(const v2g_connection* conn) {
    const auto& body = conn->exi_in.dinEXIDocument->V2G_Message.Body;
    switch (conn->ctx->current_v2g_msg) {
    case V2G_SESSION_SETUP_MSG:
        return {{"evcc_id", bytes_field_to_hex(body.SessionSetupReq.EVCCID)}};

    case V2G_SERVICE_DISCOVERY_MSG:
        return json::object();

    case V2G_PAYMENT_SERVICE_SELECTION_MSG:
        return {{"selected_payment_option", static_cast<int>(body.ServicePaymentSelectionReq.SelectedPaymentOption)},
                {"selected_service_count",
                 body.ServicePaymentSelectionReq.SelectedServiceList.SelectedService.arrayLen}};

    case V2G_AUTHORIZATION_MSG:
        return json::object();

    case V2G_CHARGE_PARAMETER_DISCOVERY_MSG: {
        const auto& req = body.ChargeParameterDiscoveryReq;
        json payload = {{"requested_energy_transfer_type", static_cast<int>(req.EVRequestedEnergyTransferType)}};
        if (req.DC_EVChargeParameter_isUsed == 1) {
            const auto& dc = req.DC_EVChargeParameter;
            json dc_json = {{"dc_ev_status", din_dc_ev_status_to_json(dc.DC_EVStatus)}};
            if (dc.EVEnergyCapacity_isUsed == 1) {
                add_physical_value(dc_json, "ev_energy_capacity", dc.EVEnergyCapacity, "Wh");
            }
            if (dc.EVEnergyRequest_isUsed == 1) {
                add_physical_value(dc_json, "ev_energy_request", dc.EVEnergyRequest, "Wh");
            }
            if (dc.FullSOC_isUsed == 1) {
                dc_json["full_soc_percent"] = dc.FullSOC;
            }
            if (dc.BulkSOC_isUsed == 1) {
                dc_json["bulk_soc_percent"] = dc.BulkSOC;
            }
            add_physical_value(dc_json, "ev_max_current", dc.EVMaximumCurrentLimit, "A");
            if (dc.EVMaximumPowerLimit_isUsed == 1) {
                add_physical_value(dc_json, "ev_max_power", dc.EVMaximumPowerLimit, "W");
            }
            add_physical_value(dc_json, "ev_max_voltage", dc.EVMaximumVoltageLimit, "V");
            payload["dc_ev_charge_parameter"] = dc_json;
        }
        return payload;
    }

    case V2G_CABLE_CHECK_MSG:
        return {{"dc_ev_status", din_dc_ev_status_to_json(body.CableCheckReq.DC_EVStatus)}};

    case V2G_PRE_CHARGE_MSG: {
        const auto& req = body.PreChargeReq;
        json payload = {{"dc_ev_status", din_dc_ev_status_to_json(req.DC_EVStatus)}};
        add_physical_value(payload, "ev_target_voltage", req.EVTargetVoltage, "V");
        add_physical_value(payload, "ev_target_current", req.EVTargetCurrent, "A");
        return payload;
    }

    case V2G_POWER_DELIVERY_MSG: {
        const auto& req = body.PowerDeliveryReq;
        json payload = {{"ready_to_charge_state", static_cast<bool>(req.ReadyToChargeState)},
                        {"charging_profile_used", static_cast<bool>(req.ChargingProfile_isUsed)}};
        if (req.DC_EVPowerDeliveryParameter_isUsed == 1) {
            const auto& dc = req.DC_EVPowerDeliveryParameter;
            payload["dc_ev_power_delivery_parameter"] = {
                {"charging_complete", static_cast<bool>(dc.ChargingComplete)},
                {"bulk_charging_complete_used", static_cast<bool>(dc.BulkChargingComplete_isUsed)},
                {"dc_ev_status", din_dc_ev_status_to_json(dc.DC_EVStatus)}};
            if (dc.BulkChargingComplete_isUsed == 1) {
                payload["dc_ev_power_delivery_parameter"]["bulk_charging_complete"] =
                    static_cast<bool>(dc.BulkChargingComplete);
            }
        }
        return payload;
    }

    case V2G_CURRENT_DEMAND_MSG: {
        const auto& req = body.CurrentDemandReq;
        json payload = {{"dc_ev_status", din_dc_ev_status_to_json(req.DC_EVStatus)},
                        {"charging_complete", static_cast<bool>(req.ChargingComplete)},
                        {"bulk_charging_complete_used", static_cast<bool>(req.BulkChargingComplete_isUsed)}};
        if (req.BulkChargingComplete_isUsed == 1) {
            payload["bulk_charging_complete"] = static_cast<bool>(req.BulkChargingComplete);
        }
        add_physical_value(payload, "ev_target_voltage", req.EVTargetVoltage, "V");
        add_physical_value(payload, "ev_target_current", req.EVTargetCurrent, "A");
        if (req.EVMaximumCurrentLimit_isUsed == 1) {
            add_physical_value(payload, "ev_max_current", req.EVMaximumCurrentLimit, "A");
        }
        if (req.EVMaximumPowerLimit_isUsed == 1) {
            add_physical_value(payload, "ev_max_power", req.EVMaximumPowerLimit, "W");
        }
        if (req.EVMaximumVoltageLimit_isUsed == 1) {
            add_physical_value(payload, "ev_max_voltage", req.EVMaximumVoltageLimit, "V");
        }
        if (req.RemainingTimeToFullSoC_isUsed == 1) {
            add_physical_value(payload, "remaining_time_to_full_soc", req.RemainingTimeToFullSoC, "s");
        }
        if (req.RemainingTimeToBulkSoC_isUsed == 1) {
            add_physical_value(payload, "remaining_time_to_bulk_soc", req.RemainingTimeToBulkSoC, "s");
        }
        return payload;
    }

    case V2G_WELDING_DETECTION_MSG:
        return {{"dc_ev_status", din_dc_ev_status_to_json(body.WeldingDetectionReq.DC_EVStatus)}};

    case V2G_SESSION_STOP_MSG:
        return {{"session_stop", true}};

    default:
        return json::object();
    }
}

static json build_din_response_payload(const v2g_connection* conn) {
    const auto& body = conn->exi_out.dinEXIDocument->V2G_Message.Body;
    switch (conn->ctx->current_v2g_msg) {
    case V2G_SESSION_SETUP_MSG: {
        const auto& res = body.SessionSetupRes;
        json payload = {{"response_code", response_code_to_json(res.ResponseCode, dinResponse)},
                        {"evse_id", bytes_field_to_hex(res.EVSEID)}};
        if (res.DateTimeNow_isUsed == 1) {
            payload["date_time_now"] = res.DateTimeNow;
        }
        return payload;
    }

    case V2G_SERVICE_DISCOVERY_MSG: {
        const auto& res = body.ServiceDiscoveryRes;
        return {{"response_code", response_code_to_json(res.ResponseCode, dinResponse)},
                {"payment_option_count", res.PaymentOptions.PaymentOption.arrayLen},
                {"charge_service_id", res.ChargeService.ServiceTag.ServiceID},
                {"charge_service_free", static_cast<bool>(res.ChargeService.FreeService)},
                {"energy_transfer_type", static_cast<int>(res.ChargeService.EnergyTransferType)}};
    }

    case V2G_PAYMENT_SERVICE_SELECTION_MSG:
        return {{"response_code", response_code_to_json(body.ServicePaymentSelectionRes.ResponseCode, dinResponse)}};

    case V2G_AUTHORIZATION_MSG:
        return {{"response_code", response_code_to_json(body.ContractAuthenticationRes.ResponseCode, dinResponse)},
                {"evse_processing", static_cast<int>(body.ContractAuthenticationRes.EVSEProcessing)}};

    case V2G_CHARGE_PARAMETER_DISCOVERY_MSG: {
        const auto& res = body.ChargeParameterDiscoveryRes;
        json payload = {{"response_code", response_code_to_json(res.ResponseCode, dinResponse)},
                        {"evse_processing", static_cast<int>(res.EVSEProcessing)},
                        {"sa_schedule_list_used", static_cast<bool>(res.SAScheduleList_isUsed)}};
        if (res.DC_EVSEChargeParameter_isUsed == 1) {
            const auto& dc = res.DC_EVSEChargeParameter;
            json dc_json = {{"dc_evse_status", din_dc_evse_status_to_json(dc.DC_EVSEStatus)}};
            add_physical_value(dc_json, "evse_max_current", dc.EVSEMaximumCurrentLimit, "A");
            if (dc.EVSEMaximumPowerLimit_isUsed == 1) {
                add_physical_value(dc_json, "evse_max_power", dc.EVSEMaximumPowerLimit, "W");
            }
            add_physical_value(dc_json, "evse_max_voltage", dc.EVSEMaximumVoltageLimit, "V");
            add_physical_value(dc_json, "evse_min_current", dc.EVSEMinimumCurrentLimit, "A");
            add_physical_value(dc_json, "evse_min_voltage", dc.EVSEMinimumVoltageLimit, "V");
            payload["dc_evse_charge_parameter"] = dc_json;
        }
        return payload;
    }

    case V2G_CABLE_CHECK_MSG:
        return {{"response_code", response_code_to_json(body.CableCheckRes.ResponseCode, dinResponse)},
                {"evse_processing", static_cast<int>(body.CableCheckRes.EVSEProcessing)},
                {"dc_evse_status", din_dc_evse_status_to_json(body.CableCheckRes.DC_EVSEStatus)}};

    case V2G_PRE_CHARGE_MSG: {
        const auto& res = body.PreChargeRes;
        json payload = {{"response_code", response_code_to_json(res.ResponseCode, dinResponse)},
                        {"dc_evse_status", din_dc_evse_status_to_json(res.DC_EVSEStatus)}};
        add_physical_value(payload, "evse_present_voltage", res.EVSEPresentVoltage, "V");
        return payload;
    }

    case V2G_POWER_DELIVERY_MSG:
        return {{"response_code", response_code_to_json(body.PowerDeliveryRes.ResponseCode, dinResponse)},
                {"dc_evse_status", din_dc_evse_status_to_json(body.PowerDeliveryRes.DC_EVSEStatus)}};

    case V2G_CURRENT_DEMAND_MSG: {
        const auto& res = body.CurrentDemandRes;
        json payload = {{"response_code", response_code_to_json(res.ResponseCode, dinResponse)},
                        {"dc_evse_status", din_dc_evse_status_to_json(res.DC_EVSEStatus)},
                        {"current_limit_achieved", static_cast<bool>(res.EVSECurrentLimitAchieved)},
                        {"voltage_limit_achieved", static_cast<bool>(res.EVSEVoltageLimitAchieved)},
                        {"power_limit_achieved", static_cast<bool>(res.EVSEPowerLimitAchieved)}};
        add_physical_value(payload, "evse_present_voltage", res.EVSEPresentVoltage, "V");
        add_physical_value(payload, "evse_present_current", res.EVSEPresentCurrent, "A");
        if (res.EVSEMaximumCurrentLimit_isUsed == 1) {
            add_physical_value(payload, "evse_max_current", res.EVSEMaximumCurrentLimit, "A");
        }
        if (res.EVSEMaximumPowerLimit_isUsed == 1) {
            add_physical_value(payload, "evse_max_power", res.EVSEMaximumPowerLimit, "W");
        }
        if (res.EVSEMaximumVoltageLimit_isUsed == 1) {
            add_physical_value(payload, "evse_max_voltage", res.EVSEMaximumVoltageLimit, "V");
        }
        return payload;
    }

    case V2G_WELDING_DETECTION_MSG: {
        const auto& res = body.WeldingDetectionRes;
        json payload = {{"response_code", response_code_to_json(res.ResponseCode, dinResponse)},
                        {"dc_evse_status", din_dc_evse_status_to_json(res.DC_EVSEStatus)}};
        add_physical_value(payload, "evse_present_voltage", res.EVSEPresentVoltage, "V");
        return payload;
    }

    case V2G_SESSION_STOP_MSG:
        return {{"response_code", response_code_to_json(body.SessionStopRes.ResponseCode, dinResponse)}};

    default:
        return json::object();
    }
}

static json build_v2g_message_payload(const v2g_connection* conn, const bool is_req) {
    if (conn->ctx->current_v2g_msg == V2G_SUPPORTED_APP_PROTOCOL_MSG) {
        return build_app_handshake_json(conn, is_req);
    }

    switch (conn->ctx->selected_protocol) {
    case V2G_PROTO_DIN70121:
    case V2G_PROTO_ISO15118_2010:
        return is_req ? build_din_request_payload(conn) : build_din_response_payload(conn);
    case V2G_PROTO_ISO15118_2013:
        return is_req ? build_iso_request_payload(conn) : build_iso_response_payload(conn);
    case V2G_UNKNOWN_PROTOCOL:
    default:
        return json::object();
    }
}

static std::string build_v2g_message_json(const v2g_connection* conn, const types::iso15118::V2gMessageId id,
                                          const bool is_req) {
    try {
        json root = {{"message_id", static_cast<int>(id)},
                     {"message", v2g_message_type_to_string(conn->ctx->current_v2g_msg)},
                     {"direction", is_req ? "EV_to_EVSE" : "EVSE_to_EV"},
                     {"protocol", protocol_to_string(conn->ctx->selected_protocol)}};

        root["payload"] = build_v2g_message_payload(conn, is_req);
        return root.dump();
    } catch (const std::exception& e) {
        json root = {{"message_id", static_cast<int>(id)},
                     {"message", v2g_message_type_to_string(conn->ctx->current_v2g_msg)},
                     {"direction", is_req ? "EV_to_EVSE" : "EVSE_to_EV"},
                     {"protocol", protocol_to_string(conn->ctx->selected_protocol)},
                     {"payload_decode_error", e.what()}};
        return root.dump();
    }
}

} // namespace

/*!
 * \brief publish_var_V2G_Message This function fills a V2gMessages type with the V2G EXI message as HEX and Base64
 * \param conn hold the context of the V2G-connection.
 * \param is_req if it is a V2G request or response: 'true' if a request, and 'false' if a response
 */
static void publish_var_V2G_Message(v2g_connection* conn, bool is_req) {
    types::iso15118::V2gMessages v2g_message;

    u_int8_t* tempbuff = conn->buffer;
    std::string msg_as_hex_string;
    for (int i = 0; ((tempbuff != NULL) && (i < conn->payload_len + V2GTP_HEADER_LENGTH)); i++) {
        char hex[4];
        snprintf(hex, 4, "%x", *tempbuff); // to hex
        if (std::string(hex).size() == 1)
            msg_as_hex_string += '0';
        msg_as_hex_string += hex;
        tempbuff++;
    }

    std::string EXI_Base64;

    EXI_Base64 = openssl::base64_encode(conn->buffer, conn->payload_len + V2GTP_HEADER_LENGTH);
    if (EXI_Base64.size() == 0) {
        dlog(DLOG_LEVEL_WARNING, "Unable to base64 encode EXI buffer");
    }

    v2g_message.exi_base64 = EXI_Base64;
    v2g_message.id = get_v2g_message_id(conn->ctx->current_v2g_msg, conn->ctx->selected_protocol, is_req);
    v2g_message.exi = msg_as_hex_string;
    if (conn->ctx->log_v2g_message_json == true) {
        v2g_message.v2g_json = build_v2g_message_json(conn, v2g_message.id, is_req);
    }
    conn->ctx->p_charger->publish_v2g_messages(v2g_message);
}

/*!
 * \brief v2g_incoming_v2gtp This function reads the V2G transport header
 * \param conn hold the context of the V2G-connection.
 * \return Returns 0 if the V2G-session was successfully stopped, 1 if connection was closed unexpectedly, otherwise -1.
 */
static int v2g_incoming_v2gtp(struct v2g_connection* conn) {
    assert(conn != nullptr);
    assert(conn->read != nullptr);

    int rv;

    /* read and process header */
    rv = conn->read(conn, conn->buffer, V2GTP_HEADER_LENGTH);
    if (rv < 0) {
        dlog(DLOG_LEVEL_ERROR, "connection_read(header) failed: %s",
             (rv == -1) ? strerror(errno) : "connection terminated");
        return -1;
    }
    /* connection was closed unexpectedly (timeout or closed by peer) */
    if (rv == 0)
        return 1;

    if (rv != V2GTP_HEADER_LENGTH) {
        dlog(DLOG_LEVEL_ERROR, "connection_read(header) too short: expected %d, got %d", V2GTP_HEADER_LENGTH, rv);
        return -1;
    }

    rv = V2GTP_ReadHeader(conn->buffer, &conn->payload_len);
    if (rv == -1) {
        dlog(DLOG_LEVEL_ERROR, "Invalid v2gtp header");
        return -1;
    }

    if (conn->payload_len >= UINT32_MAX - V2GTP_HEADER_LENGTH) {
        dlog(DLOG_LEVEL_ERROR, "Prevent integer overflow - payload too long: have %d, would need %u",
             DEFAULT_BUFFER_SIZE, conn->payload_len);
        return -1;
    }

    if (conn->payload_len + V2GTP_HEADER_LENGTH > DEFAULT_BUFFER_SIZE) {
        dlog(DLOG_LEVEL_ERROR, "payload too long: have %d, would need %u", DEFAULT_BUFFER_SIZE,
             conn->payload_len + V2GTP_HEADER_LENGTH);

        /* we have no way to flush/discard remaining unread data from the socket without reading it in chunks,
         * but this opens the chance to bind us in a "endless" read loop; so to protect us, simply close the connection
         */

        return -1;
    }
    /* read request */
    rv = conn->read(conn, &conn->buffer[V2GTP_HEADER_LENGTH], conn->payload_len);
    if (rv < 0) {
        dlog(DLOG_LEVEL_ERROR, "connection_read(payload) failed: %s",
             (rv == -1) ? strerror(errno) : "connection terminated");
        return -1;
    }
    if (rv != conn->payload_len) {
        dlog(DLOG_LEVEL_ERROR, "connection_read(payload) too short: expected %d, got %d", conn->payload_len, rv);
        return -1;
    }
    /* adjust buffer pos to decode request */
    conn->stream.byte_pos = V2GTP_HEADER_LENGTH;
    conn->stream.data_size = conn->payload_len + V2GTP_HEADER_LENGTH;

    return 0;
}

/*!
 * \brief v2g_outgoing_v2gtp This function creates the v2g transport header
 * \param conn hold the context of the v2g-connection.
 * \return Returns 0 if the v2g-session was successfully stopped, otherwise -1.
 */
int v2g_outgoing_v2gtp(struct v2g_connection* conn) {
    assert(conn != nullptr);
    assert(conn->write != nullptr);

    /* fixup/create header */
    const auto len = exi_bitstream_get_length(&conn->stream);

    V2GTP_WriteHeader(conn->buffer, len - V2GTP_HEADER_LENGTH);

    if (conn->write(conn, conn->buffer, len) == -1) {
        dlog(DLOG_LEVEL_ERROR, "connection_write(header) failed: %s", strerror(errno));
        return -1;
    }

    return 0;
}

/*!
 * \brief v2g_handle_apphandshake After receiving a supportedAppProtocolReq message,
 * the SECC shall process the received information. DIN [V2G-DC-436] ISO [V2G2-540]
 * \param conn hold the context of the v2g-connection.
 * \return Returns a v2g-event of type enum v2g_event.
 */
static enum v2g_event v2g_handle_apphandshake(struct v2g_connection* conn) {
    enum v2g_event next_event = V2G_EVENT_NO_EVENT;
    int i;
    uint8_t ev_app_priority = 20; // lowest priority

    /* validate handshake request and create response */
    init_appHand_exiDocument(&conn->handshake_resp);
    conn->handshake_resp.supportedAppProtocolRes_isUsed = 1;
    conn->handshake_resp.supportedAppProtocolRes.ResponseCode =
        appHand_responseCodeType_Failed_NoNegotiation; // [V2G2-172]

    dlog(DLOG_LEVEL_INFO, "Handling SupportedAppProtocolReq");
    conn->ctx->current_v2g_msg = V2G_SUPPORTED_APP_PROTOCOL_MSG;

    if (decode_appHand_exiDocument(&conn->stream, &conn->handshake_req) != 0) {
        dlog(DLOG_LEVEL_ERROR, "decode_appHandExiDocument() failed");
        return V2G_EVENT_TERMINATE_CONNECTION; // If the mesage can't be decoded we have to terminate the tcp-connection
                                               // (e.g. after an unexpected message)
    }

    types::iso15118::AppProtocols app_protocols; // to publish supported app protocol array

    for (i = 0; i < conn->handshake_req.supportedAppProtocolReq.AppProtocol.arrayLen; i++) {
        struct appHand_AppProtocolType* app_proto = &conn->handshake_req.supportedAppProtocolReq.AppProtocol.array[i];
        char* proto_ns = strndup(static_cast<const char*>(app_proto->ProtocolNamespace.characters),
                                 app_proto->ProtocolNamespace.charactersLen);

        if (!proto_ns) {
            dlog(DLOG_LEVEL_ERROR, "out-of-memory condition");
            return V2G_EVENT_TERMINATE_CONNECTION;
        }

        dlog(DLOG_LEVEL_TRACE,
             "handshake_req: Namespace: %s, Version: %" PRIu32 ".%" PRIu32 ", SchemaID: %" PRIu8 ", Priority: %" PRIu8,
             proto_ns, app_proto->VersionNumberMajor, app_proto->VersionNumberMinor, app_proto->SchemaID,
             app_proto->Priority);

        if ((conn->ctx->supported_protocols & (1 << V2G_PROTO_DIN70121)) &&
            (strcmp(proto_ns, DIN_70121_MSG_DEF) == 0) && (app_proto->VersionNumberMajor == DIN_70121_MAJOR) &&
            (ev_app_priority >= app_proto->Priority)) {
            conn->handshake_resp.supportedAppProtocolRes.ResponseCode =
                (app_proto->VersionNumberMinor == DIN_70121_MINOR)
                    ? appHand_responseCodeType_OK_SuccessfulNegotiation
                    : appHand_responseCodeType_OK_SuccessfulNegotiationWithMinorDeviation;
            ev_app_priority = app_proto->Priority;
            conn->handshake_resp.supportedAppProtocolRes.SchemaID = app_proto->SchemaID;
            conn->ctx->selected_protocol = V2G_PROTO_DIN70121;
        } else if ((conn->ctx->supported_protocols & (1 << V2G_PROTO_ISO15118_2013)) &&
                   (strcmp(proto_ns, ISO_15118_2013_MSG_DEF) == 0) &&
                   (app_proto->VersionNumberMajor == ISO_15118_2013_MAJOR) &&
                   (ev_app_priority >= app_proto->Priority)) {

            conn->handshake_resp.supportedAppProtocolRes.ResponseCode =
                (app_proto->VersionNumberMinor == ISO_15118_2013_MINOR)
                    ? appHand_responseCodeType_OK_SuccessfulNegotiation
                    : appHand_responseCodeType_OK_SuccessfulNegotiationWithMinorDeviation;
            ev_app_priority = app_proto->Priority;
            conn->handshake_resp.supportedAppProtocolRes.SchemaID = app_proto->SchemaID;
            conn->ctx->selected_protocol = V2G_PROTO_ISO15118_2013;
        }

        if (conn->ctx->debugMode == true) {
            const types::iso15118::AppProtocol protocol = {
                std::string(proto_ns), static_cast<int32_t>(app_proto->VersionNumberMajor),
                static_cast<int32_t>(app_proto->VersionNumberMinor), static_cast<int32_t>(app_proto->SchemaID),
                static_cast<int32_t>(app_proto->Priority)};

            app_protocols.Protocols.push_back(protocol);
        }

        // TODO: ISO15118v2
        free(proto_ns);
    }

    if (conn->ctx->debugMode == true) {
        conn->ctx->p_charger->publish_ev_app_protocol(app_protocols);
        /* form the content of V2G_Message type and publish the request*/
        publish_var_V2G_Message(conn, true);
    }

    std::string selected_protocol_str;
    if (conn->handshake_resp.supportedAppProtocolRes.ResponseCode ==
            appHand_responseCodeType_OK_SuccessfulNegotiation ||
        conn->handshake_resp.supportedAppProtocolRes.ResponseCode ==
            appHand_responseCodeType_OK_SuccessfulNegotiationWithMinorDeviation) {
        conn->handshake_resp.supportedAppProtocolRes.SchemaID_isUsed = (unsigned int)1;
        if (V2G_PROTO_DIN70121 == conn->ctx->selected_protocol) {
            dlog(DLOG_LEVEL_INFO, "Protocol negotiation was successful. Selected protocol is DIN70121");
            selected_protocol_str = "DIN70121";
        } else if (V2G_PROTO_ISO15118_2013 == conn->ctx->selected_protocol) {
            dlog(DLOG_LEVEL_INFO, "Protocol negotiation was successful. Selected protocol is ISO15118");
            selected_protocol_str = "ISO15118-2-2013";
        } else if (V2G_PROTO_ISO15118_2010 == conn->ctx->selected_protocol) {
            dlog(DLOG_LEVEL_INFO, "Protocol negotiation was successful. Selected protocol is ISO15118-2010");
            selected_protocol_str = "ISO15118-2-2010";
        }
    } else {
        dlog(DLOG_LEVEL_ERROR, "No compatible protocol found");
        selected_protocol_str = "None";
        next_event = V2G_EVENT_SEND_AND_TERMINATE; // Send response and terminate tcp-connection
    }

    if (conn->ctx->debugMode == true) {
        conn->ctx->p_charger->publish_selected_protocol(selected_protocol_str);
    }

    if (conn->ctx->is_connection_terminated == true) {
        dlog(DLOG_LEVEL_ERROR, "Connection is terminated. Abort charging");
        return V2G_EVENT_TERMINATE_CONNECTION; // Abort charging without sending a response
    }

    /* Validate response code */
    if ((conn->ctx->intl_emergency_shutdown == true) || (conn->ctx->stop_hlc == true) ||
        (V2G_EVENT_SEND_AND_TERMINATE == next_event)) {
        conn->handshake_resp.supportedAppProtocolRes.ResponseCode = appHand_responseCodeType_Failed_NoNegotiation;
        dlog(DLOG_LEVEL_ERROR, "Abort charging session");

        if (conn->ctx->terminate_connection_on_failed_response == true) {
            next_event = V2G_EVENT_SEND_AND_TERMINATE; // send response and terminate the TCP-connection
        }
    }

    /* encode response at the right buffer location */
    conn->stream.byte_pos = V2GTP_HEADER_LENGTH;
    conn->stream.bit_count = 0;

    if (encode_appHand_exiDocument(&conn->stream, &conn->handshake_resp) != 0) {
        dlog(DLOG_LEVEL_ERROR, "Encoding of the protocol handshake message failed");
        next_event = V2G_EVENT_SEND_AND_TERMINATE;
    }

    return next_event;
}

int v2g_handle_connection(struct v2g_connection* conn) {
    int rv = -1;
    enum v2g_event rvAppHandshake = V2G_EVENT_NO_EVENT;
    bool stop_receiving_loop = false;
    int64_t start_time = 0; // in ms

    enum v2g_protocol selected_protocol = V2G_UNKNOWN_PROTOCOL;
    v2g_ctx_init_charging_state(conn->ctx, false);
    conn->buffer = static_cast<uint8_t*>(malloc(DEFAULT_BUFFER_SIZE));
    if (!conn->buffer)
        return -1;

    /* static setup */
    conn->stream.data = conn->buffer;

    /* Here is a good point to wait until the customer is ready for a resumed session,
     * because we are waiting for the incoming message of the ev */
    if (conn->dlink_action == MQTT_DLINK_ACTION_PAUSE) {
        // TODO: D_LINK pause
    }

    do {
        /* setup for receive */
        conn->stream.data[0] = 0;
        conn->payload_len = 0;
        exi_bitstream_init(&conn->stream, conn->buffer, 0, 0, nullptr);

        /* next call return -1 on error, 1 if connection was closed unexpectedly, 0 on success */
        rv = v2g_incoming_v2gtp(conn);

        if (rv != 0) {
            dlog(DLOG_LEVEL_ERROR, "v2g_incoming_v2gtp() failed");
            goto error_out;
        }

        if (conn->ctx->is_connection_terminated == true) {
            rv = -1;
            goto error_out;
        }

        /* next call return -1 on non-recoverable errors, 1 on recoverable errors, 0 on success */
        rvAppHandshake = v2g_handle_apphandshake(conn);

        if (rvAppHandshake == V2G_EVENT_IGNORE_MSG) {
            dlog(DLOG_LEVEL_WARNING, "v2g_handle_apphandshake() failed, ignoring packet");
        }
    } while ((rv == 1) && (rvAppHandshake == V2G_EVENT_IGNORE_MSG));

    /* stream setup for sending is done within v2g_handle_apphandshake */
    /* send supportedAppRes message */
    if ((rvAppHandshake == V2G_EVENT_SEND_AND_TERMINATE) || (rvAppHandshake == V2G_EVENT_NO_EVENT)) {
        /* form the content of V2G_Message type and publish the response for debugging*/
        if (conn->ctx->debugMode == true) {
            publish_var_V2G_Message(conn, false);
        }

        rv = v2g_outgoing_v2gtp(conn);

        if (rv == -1) {
            dlog(DLOG_LEVEL_ERROR, "v2g_outgoing_v2gtp() failed");
            goto error_out;
        }
    }

    /* terminate connection, if supportedApp handshake has failed */
    if ((rvAppHandshake == V2G_EVENT_SEND_AND_TERMINATE) || (rvAppHandshake == V2G_EVENT_TERMINATE_CONNECTION)) {
        rv = -1;
        goto error_out;
    }

    /* Backup the selected protocol, because this value is shared and can be reseted while unplugging. */
    selected_protocol = conn->ctx->selected_protocol;

    /* allocate in/out documents dynamically */
    switch (selected_protocol) {
    case V2G_PROTO_DIN70121:
    case V2G_PROTO_ISO15118_2010:
        conn->exi_in.dinEXIDocument = static_cast<struct din_exiDocument*>(calloc(1, sizeof(struct din_exiDocument)));
        if (conn->exi_in.dinEXIDocument == NULL) {
            dlog(DLOG_LEVEL_ERROR, "out-of-memory");
            goto error_out;
        }
        conn->exi_out.dinEXIDocument = static_cast<struct din_exiDocument*>(calloc(1, sizeof(struct din_exiDocument)));
        if (conn->exi_out.dinEXIDocument == NULL) {
            dlog(DLOG_LEVEL_ERROR, "out-of-memory");
            goto error_out;
        }
        break;
    case V2G_PROTO_ISO15118_2013:
        conn->exi_in.iso2EXIDocument =
            static_cast<struct iso2_exiDocument*>(calloc(1, sizeof(struct iso2_exiDocument)));
        if (conn->exi_in.iso2EXIDocument == NULL) {
            dlog(DLOG_LEVEL_ERROR, "out-of-memory");
            goto error_out;
        }
        conn->exi_out.iso2EXIDocument =
            static_cast<struct iso2_exiDocument*>(calloc(1, sizeof(struct iso2_exiDocument)));
        if (conn->exi_out.iso2EXIDocument == NULL) {
            dlog(DLOG_LEVEL_ERROR, "out-of-memory");
            goto error_out;
        }
        break;
    default:
        goto error_out; //     if protocol is unknown
    }

    do {
        /* setup for receive */
        conn->stream.data[0] = 0;
        conn->stream.bit_count = 0;
        conn->stream.byte_pos = 0;
        conn->payload_len = 0;

        /* next call return -1 on error, 1 connection was closed unexpectedly, 0 on success */
        rv = v2g_incoming_v2gtp(conn);

        if (rv == 1) {
            dlog(DLOG_LEVEL_ERROR, "Timeout waiting for next request or peer closed connection");
            break;
        } else if (rv == -1) {
            dlog(DLOG_LEVEL_ERROR, "v2g_incoming_v2gtp() (previous message \"%s\") failed",
                 v2g_msg_type[conn->ctx->last_v2g_msg]);
            break;
        }

        start_time = getmonotonictime(); // To calc the duration of req msg configuration

        /* according to agreed protocol decode the stream */
        enum v2g_event v2gEvent = V2G_EVENT_NO_EVENT;
        switch (selected_protocol) {
        case V2G_PROTO_DIN70121:
        case V2G_PROTO_ISO15118_2010:
            memset(conn->exi_in.dinEXIDocument, 0, sizeof(struct din_exiDocument));
            rv = decode_din_exiDocument(&conn->stream, conn->exi_in.dinEXIDocument);
            if (rv != 0) {
                dlog(DLOG_LEVEL_ERROR, "decode_dinExiDocument() (previous message \"%s\") failed: %d",
                     v2g_msg_type[conn->ctx->last_v2g_msg], rv);
                /* we must ignore packet which we cannot decode, so reset rv to zero to stay in loop */
                rv = 0;
                v2gEvent = V2G_EVENT_IGNORE_MSG;
                break;
            }

            memset(conn->exi_out.dinEXIDocument, 0, sizeof(struct din_exiDocument));

            v2gEvent = din_handle_request(conn);
            break;

        case V2G_PROTO_ISO15118_2013:
            memset(conn->exi_in.iso2EXIDocument, 0, sizeof(struct iso2_exiDocument));
            rv = decode_iso2_exiDocument(&conn->stream, conn->exi_in.iso2EXIDocument);
            if (rv != 0) {
                dlog(DLOG_LEVEL_ERROR, "decode_iso2_exiDocument() (previous message \"%s\") failed: %d",
                     v2g_msg_type[conn->ctx->last_v2g_msg], rv);
                /* we must ignore packet which we cannot decode, so reset rv to zero to stay in loop */
                rv = 0;
                v2gEvent = V2G_EVENT_IGNORE_MSG;
                break;
            }
            conn->stream.byte_pos = 0; // Reset pos for the case if exi msg will be configured over mqtt
            memset(conn->exi_out.iso2EXIDocument, 0, sizeof(struct iso2_exiDocument));

            v2gEvent = iso_handle_request(conn);

            break;
        default:
            goto error_out; //     if protocol is unknown
        }

        /* form the content of V2G_Message type and publish the request*/
        if (conn->ctx->debugMode == true) {
            publish_var_V2G_Message(conn, true);
        }

        switch (v2gEvent) {
        case V2G_EVENT_SEND_AND_TERMINATE:
            stop_receiving_loop = true;
        case V2G_EVENT_NO_EVENT: { // fall-through intended
            /* Reset v2g-buffer */
            conn->stream.data[0] = 0;
            conn->stream.bit_count = 0;
            conn->stream.byte_pos = V2GTP_HEADER_LENGTH;
            conn->stream.data_size = DEFAULT_BUFFER_SIZE;

            /* Configure msg and send */
            switch (selected_protocol) {
            case V2G_PROTO_DIN70121:
            case V2G_PROTO_ISO15118_2010:
                if ((rv = encode_din_exiDocument(&conn->stream, conn->exi_out.dinEXIDocument)) != 0) {
                    dlog(DLOG_LEVEL_ERROR, "encode_dinExiDocument() (message \"%s\") failed: %d",
                         v2g_msg_type[conn->ctx->current_v2g_msg], rv);
                }
                break;
            case V2G_PROTO_ISO15118_2013:
                if ((rv = encode_iso2_exiDocument(&conn->stream, conn->exi_out.iso2EXIDocument)) != 0) {
                    dlog(DLOG_LEVEL_ERROR, "encode_iso2_exiDocument() (message \"%s\") failed: %d",
                         v2g_msg_type[conn->ctx->current_v2g_msg], rv);
                }
                break;
            default:
                goto error_out; //     if protocol is unknown
            }
            /* Wait max. res-time before sending the next response */
            int64_t time_to_conf_res = getmonotonictime() - start_time;

            if (time_to_conf_res < MAX_RES_TIME) {
                // dlog(DLOG_LEVEL_ERROR,"time_to_conf_res %llu", time_to_conf_res);
                std::this_thread::sleep_for(std::chrono::microseconds((MAX_RES_TIME - time_to_conf_res) * 1000));
            } else {
                dlog(DLOG_LEVEL_WARNING, "Response message (type %d) not configured within %d ms (took %" PRIi64 " ms)",
                     conn->ctx->current_v2g_msg, MAX_RES_TIME, time_to_conf_res);
            }
        }
        case V2G_EVENT_SEND_RECV_EXI_MSG: { // fall-through intended
            /* form the content of V2G_Message type and publish the response for debugging*/
            if (conn->ctx->debugMode == true) {
                publish_var_V2G_Message(conn, false);
            }

            /* Write header and send next res-msg */
            if ((rv != 0) || ((rv = v2g_outgoing_v2gtp(conn)) == -1)) {
                dlog(DLOG_LEVEL_ERROR, "v2g_outgoing_v2gtp() \"%s\" failed: %d",
                     v2g_msg_type[conn->ctx->current_v2g_msg], rv);
                break;
            }
            break;
        }
        case V2G_EVENT_IGNORE_MSG:
            dlog(DLOG_LEVEL_ERROR, "Ignoring V2G request message \"%s\". Waiting for next request",
                 v2g_msg_type[conn->ctx->current_v2g_msg]);
            break;
        case V2G_EVENT_TERMINATE_CONNECTION: // fall-through intended
        default:
            dlog(DLOG_LEVEL_ERROR, "Failed to handle V2G request message \"%s\"",
                 v2g_msg_type[conn->ctx->current_v2g_msg]);
            stop_receiving_loop = true;
            break;
        }
    } while ((rv == 0) && (stop_receiving_loop == false));

error_out:
    switch (selected_protocol) {
    case V2G_PROTO_DIN70121:
    case V2G_PROTO_ISO15118_2010:
        if (conn->exi_in.dinEXIDocument != NULL)
            free(conn->exi_in.dinEXIDocument);
        if (conn->exi_out.dinEXIDocument != NULL)
            free(conn->exi_out.dinEXIDocument);
        break;
    case V2G_PROTO_ISO15118_2013:
        if (conn->exi_in.iso2EXIDocument != NULL)
            free(conn->exi_in.iso2EXIDocument);
        if (conn->exi_out.iso2EXIDocument != NULL)
            free(conn->exi_out.iso2EXIDocument);
        break;
    default:
        break;
    }

    if (conn->buffer != NULL) {
        free(conn->buffer);
    }

    v2g_ctx_init_charging_state(conn->ctx, true);

    return rv ? -1 : 0;
}

uint64_t v2g_session_id_from_exi(bool is_iso, void* exi_in) {
    uint64_t session_id = 0;

    if (is_iso) {
        struct iso2_exiDocument* req = static_cast<struct iso2_exiDocument*>(exi_in);
        struct iso2_MessageHeaderType* hdr = &req->V2G_Message.Header;

        /* the provided session id could be smaller (error) in case that the peer did not
         * send our full session id back to us; this is why we init the id with 0 above
         * and only copy the provided byte len
         */
        memcpy(&session_id, &hdr->SessionID.bytes, std::min((int)sizeof(session_id), (int)hdr->SessionID.bytesLen));
    } else {
        struct din_exiDocument* req = static_cast<struct din_exiDocument*>(exi_in);
        struct din_MessageHeaderType* hdr = &req->V2G_Message.Header;

        /* see comment above */
        memcpy(&session_id, &hdr->SessionID.bytes, std::min((int)sizeof(session_id), (int)hdr->SessionID.bytesLen));
    }

    return session_id;
}
