/*
 * log.cpp  -  File logger.  Based on wp81TimerService's FileLogger.
 */

#include "log.h"
#include "config.h"
#include <strsafe.h>
#include <stdio.h>
#include <stdarg.h>

namespace FileLogger
{
    static wchar_t          s_logPath[MAX_PATH] = {};   // empty = file logging disabled
    static bool             s_console = false;
    static CRITICAL_SECTION s_lock;
    static volatile LONG    s_lockState = 0;            // 0 = none, 1 = initialising, 2 = ready

    static void EnsureLock()
    {
        if (s_lockState == 2) return;
        if (InterlockedCompareExchange(&s_lockState, 1, 0) == 0)
        {
            InitializeCriticalSectionEx(&s_lock, 0, 0);
            InterlockedExchange(&s_lockState, 2);
        }
        while (s_lockState != 2) api.Sleep(0);
    }

    void Init()
    {
        EnsureLock();
        Config::ReadString(L"LogFile", s_logPath, _countof(s_logPath), L"");
    }

    void SetConsoleEcho(bool enabled)
    {
        EnsureLock();
        s_console = enabled;
    }

    static const wchar_t* LevelTag(UCHAR level)
    {
        switch (level)
        {
        case 1:  return L"CRIT ";
        case 2:  return L"ERROR";
        case 3:  return L"WARN ";
        case 4:  return L"INFO ";
        case 5:  return L"VERB ";
        default: return L"?    ";
        }
    }

    void LogEvent(UCHAR level, const wchar_t* message)
    {
        if (s_logPath[0] == L'\0' && !s_console) return;   // logging not configured

        SYSTEMTIME st;
        GetLocalTime(&st);

        wchar_t line[1280];
        StringCchPrintfW(line, _countof(line),
            L"%04d-%02d-%02d %02d:%02d:%02d [%s] %s\r\n",
            st.wYear, st.wMonth, st.wDay,
            st.wHour, st.wMinute, st.wSecond,
            LevelTag(level),
            message);

        int needed = WideCharToMultiByte(CP_UTF8, 0, line, -1, nullptr, 0, nullptr, nullptr);
        if (needed <= 0) return;

        char* buf = new char[needed];
        WideCharToMultiByte(CP_UTF8, 0, line, -1, buf, needed, nullptr, nullptr);
        int byteCount = needed - 1;

        EnsureLock();
        EnterCriticalSection(&s_lock);

        if (s_console)
        {
            DWORD written;
            WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), buf, static_cast<DWORD>(byteCount), &written, nullptr);
        }

        if (s_logPath[0] != L'\0')
        {
            HANDLE hFile = CreateFileW(
                s_logPath,
                FILE_APPEND_DATA,
                FILE_SHARE_READ,
                nullptr,
                OPEN_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                nullptr);

            if (hFile != INVALID_HANDLE_VALUE)
            {
                DWORD written;
                WriteFile(hFile, buf, static_cast<DWORD>(byteCount), &written, nullptr);
                CloseHandle(hFile);
            }
        }

        LeaveCriticalSection(&s_lock);
        delete[] buf;
    }

    void LogEventF(UCHAR level, const wchar_t* fmt, ...)
    {
        if (s_logPath[0] == L'\0' && !s_console) return;

        wchar_t msg[1024];
        va_list args;
        va_start(args, fmt);
        _vsnwprintf_s(msg, _countof(msg), _TRUNCATE, fmt, args);
        va_end(args);
        LogEvent(level, msg);
    }
}

void LOGF(UCHAR level, const char* fmt, ...)
{
    char    msg[1024];
    wchar_t wmsg[1024];
    va_list args;

    va_start(args, fmt);
    _vsnprintf_s(msg, sizeof(msg), _TRUNCATE, fmt, args);
    va_end(args);

    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, msg, -1, wmsg, _countof(wmsg)) <= 0)
        MultiByteToWideChar(CP_ACP, 0, msg, -1, wmsg, _countof(wmsg));
    wmsg[_countof(wmsg) - 1] = L'\0';
    FileLogger::LogEvent(level, wmsg);
}
