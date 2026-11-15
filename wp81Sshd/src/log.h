#pragma once

/*
 * log.h  -  File logging (from wp81TimerService's FileLogger), made
 *           thread-safe for concurrent SSH sessions, plus a narrow-string
 *           printf-style helper for the protocol code.
 */

#include "Win32Api.h"

#define TRACE_LEVEL_NONE        0   // Tracing is not on
#define TRACE_LEVEL_CRITICAL    1   // Abnormal exit or termination
#define TRACE_LEVEL_ERROR       2   // Severe errors that need logging
#define TRACE_LEVEL_WARNING     3   // Warnings such as allocation failure
#define TRACE_LEVEL_INFORMATION 4   // Includes non-error cases(e.g.,Entry-Exit)
#define TRACE_LEVEL_VERBOSE     5   // Detailed traces from intermediate steps

namespace FileLogger
{
    // Read LogFile from registry; call once at start.
    void Init();

    // Also echo every log line to stdout (console mode).
    void SetConsoleEcho(bool enabled);

    void LogEvent(UCHAR level, const wchar_t* message);
    void LogEventF(UCHAR level, const wchar_t* fmt, ...);
}

// printf-style logging with a narrow (UTF-8) format string.
void LOGF(UCHAR level, const char* fmt, ...);
