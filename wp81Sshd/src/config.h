#pragma once

/*
 * config.h  -  Registry configuration under
 *   HKLM\SYSTEM\CurrentControlSet\Services\wp81Sshd\Parameters
 */

#include "Win32Api.h"

extern const wchar_t* SERVICE_NAME;

namespace Config
{
    DWORD ReadDword(const wchar_t* name, DWORD defaultValue);

    // Always NUL-terminates; copies defaultValue when the value is missing/empty.
    void  ReadString(const wchar_t* name, wchar_t* buf, DWORD bufChars, const wchar_t* defaultValue);

    // Returns true only if the value exists and is exactly `size` bytes.
    bool  ReadBinary(const wchar_t* name, BYTE* buf, DWORD size);

    // Creates the Parameters key if needed.
    bool  WriteBinary(const wchar_t* name, const BYTE* data, DWORD size);
}
