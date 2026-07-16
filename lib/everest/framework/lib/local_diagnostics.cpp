// SPDX-License-Identifier: Apache-2.0
// Local diagnostics helpers for deployment-specific debugging.

#include <utils/local_diagnostics.hpp>

#include <everest/logging.hpp>

#include <utility>

namespace LocalDiagnostics {

bool enabled(const int configured_level, const Level message_level) {
    return configured_level >= static_cast<int>(message_level);
}

const char* level_name(const Level level) {
    switch (level) {
    case Level::Info:
        return "info";
    case Level::Warning:
        return "warning";
    case Level::Debug:
        return "debug";
    }
    return "unknown";
}

namespace {

const char* level_color(const Level level) {
    switch (level) {
    case Level::Info:
        return "\033[1;34m";
    case Level::Warning:
        return "\033[1;33m";
    case Level::Debug:
        return "\033[0;36m";
    }
    return "";
}

constexpr const char* reset_color() {
    return "\033[0m";
}

} // namespace

std::string prefix(const Level level, const char* category) {
    return std::string(level_color(level)) + "[LOCAL_DIAG][" + level_name(level) + "][" + category + "] " +
           reset_color();
}

Line::Line(const Level level, const char* category) : level(level) {
    stream << prefix(level, category);
}

Line::Line(Line&& other) noexcept : level(other.level), stream(std::move(other.stream)), active(other.active) {
    other.active = false;
}

Line::~Line() {
    if (!active) {
        return;
    }
    const auto message = stream.str();
    switch (level) {
    case Level::Info:
        EVLOG_info << message;
        break;
    case Level::Warning:
        EVLOG_warning << message;
        break;
    case Level::Debug:
        EVLOG_debug << message;
        break;
    }
}

std::optional<Line> make_line(const int configured_level, const Level message_level, const char* category) {
    if (!enabled(configured_level, message_level)) {
        return std::nullopt;
    }
    return std::optional<Line>{std::in_place, message_level, category};
}

} // namespace LocalDiagnostics
