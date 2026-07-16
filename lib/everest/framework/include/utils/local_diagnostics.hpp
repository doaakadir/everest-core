// SPDX-License-Identifier: Apache-2.0
// Local diagnostics helpers for deployment-specific debugging.

#pragma once

#include <optional>
#include <sstream>
#include <string>

namespace LocalDiagnostics {

enum class Level {
    Info = 1,
    Warning = 2,
    Debug = 3,
};

namespace Category {
inline constexpr const char* Energy = "energy";
inline constexpr const char* Auth = "auth";
inline constexpr const char* Error = "error";
inline constexpr const char* Framework = "framework";
} // namespace Category

bool enabled(int configured_level, Level message_level);
const char* level_name(Level level);
std::string prefix(Level level, const char* category);

class Line {
public:
    Line(Level level, const char* category);

    Line(const Line&) = delete;
    Line& operator=(const Line&) = delete;

    Line(Line&& other) noexcept;
    Line& operator=(Line&& other) = delete;

    ~Line();

    template <typename T> Line& operator<<(const T& value) {
        stream << value;
        return *this;
    }

private:
    Level level;
    std::ostringstream stream;
    bool active{true};
};

std::optional<Line> make_line(int configured_level, Level message_level, const char* category);

} // namespace LocalDiagnostics

#define LOCAL_DIAG(configured_level, message_level, category)                                                          \
    for (auto local_diag_line = ::LocalDiagnostics::make_line((configured_level), (message_level), (category));        \
         local_diag_line.has_value(); local_diag_line.reset())                                                         \
    local_diag_line.value()
