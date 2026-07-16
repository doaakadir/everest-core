# Local Diagnostics

`LocalDiagnostics` is a deployment-specific diagnostics helper for local patches.
It is intentionally separate from the upstream EVerest logging API and should only
be used for troubleshooting instrumentation that can stay disabled in normal
operation.

## Files

- Public header: `lib/everest/framework/include/utils/local_diagnostics.hpp`
- Framework implementation: `lib/everest/framework/lib/local_diagnostics.cpp`

## Levels

Module configuration uses an integer `local_diagnostics` field:

- `0`: disabled
- `1`: info
- `2`: info and warning
- `3`: info, warning, and debug

Framework-level diagnostics use the same level semantics through the
`LOCAL_DIAGNOSTICS` environment variable.

For deployments, prefer keeping these variables in a small env file that is
sourced by the manager startup script before `manager` is executed. This keeps
framework diagnostics configurable without editing C++ code or the main EVerest
YAML config.

Example deployment file:

```bash
LOCAL_DIAGNOSTICS=2
LOCAL_OP_QUEUE_DIAG_TOPIC_FILTER=/cmd/enforce_limits
LOCAL_OP_QUEUE_DIAG_BACKLOG_THRESHOLD=20
LOCAL_OP_QUEUE_DIAG_WAIT_MS=200
LOCAL_OP_QUEUE_DIAG_HANDLE_MS=20
```

## Module Usage

Include the helper and emit diagnostics through the single `LOCAL_DIAG` macro:

```cpp
#include <utils/local_diagnostics.hpp>

LOCAL_DIAG(config.local_diagnostics, LocalDiagnostics::Level::Info, LocalDiagnostics::Category::Energy)
    << "energy step begin value=" << value;

LOCAL_DIAG(config.local_diagnostics, LocalDiagnostics::Level::Warning, LocalDiagnostics::Category::Auth)
    << "authorization callback slow duration_ms=" << duration_ms;
```

The first argument is the configured local diagnostics level. If the message
level is not enabled, the stream body is not evaluated.

## Framework Usage

Framework code uses the same macro. Because framework code is not owned by a
single module configuration, read the level from environment-backed local
configuration and pass it into `LOCAL_DIAG`.

Current operation queue diagnostics are enabled with:

```bash
export LOCAL_DIAGNOSTICS=2
export LOCAL_OP_QUEUE_DIAG_TOPIC_FILTER=/cmd/enforce_limits
export LOCAL_OP_QUEUE_DIAG_WAIT_MS=200
export LOCAL_OP_QUEUE_DIAG_HANDLE_MS=20
```

## Categories

Categories are declared in `LocalDiagnostics::Category`. Add a new category
there before using it from local patches.

Existing categories:

- `Energy`
- `Auth`
- `Error`
- `Framework`

## Output

Messages are emitted through the native EVerest log levels:

- `LocalDiagnostics::Level::Info` uses `EVLOG_info`
- `LocalDiagnostics::Level::Warning` uses `EVLOG_warning`
- `LocalDiagnostics::Level::Debug` uses `EVLOG_debug`

The prefix format is:

```text
[LOCAL_DIAG][level][category] message
```

Console color is added centrally by the helper.
