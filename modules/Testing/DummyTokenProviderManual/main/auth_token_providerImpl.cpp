// SPDX-License-Identifier: Apache-2.0
// Copyright Pionix GmbH and Contributors to EVerest

#include "auth_token_providerImpl.hpp"

#include <everest/helpers/helpers.hpp>

namespace module {
namespace main {

void auth_token_providerImpl::init() {
    auto handle_provided_token = [this](const std::string& msg) {
        try {
            types::authorization::ProvidedIdToken token = json::parse(msg);
            EVLOG_info << "Publishing externally provided token: " << everest::helpers::redact(token);
            publish_provided_token(token);
        } catch (const nlohmann::json::exception& e) {
            EVLOG_error << "Failed to handle JSON token from MQTT: " << e.what();
        }
    };

    mod->mqtt.subscribe("everest_api/local_authorization/cmd/provide", handle_provided_token);
    mod->mqtt.subscribe("everest_api/dummy_token_provider/cmd/provide", handle_provided_token);
}

void auth_token_providerImpl::ready() {
}

} // namespace main
} // namespace module
