/*
 * config.cpp  -  Registry configuration helpers.
 */

#include "config.h"
#include <strsafe.h>

namespace Config
{
    static void KeyPath(wchar_t* buf, size_t chars)
    {
        StringCchPrintfW(buf, chars,
            L"SYSTEM\\CurrentControlSet\\Services\\%s\\Parameters", SERVICE_NAME);
    }

    static bool Open(HKEY* hKey)
    {
        wchar_t path[256];
        KeyPath(path, _countof(path));
        return api.RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, hKey) == ERROR_SUCCESS;
    }

    DWORD ReadDword(const wchar_t* name, DWORD defaultValue)
    {
        HKEY hKey;
        if (!Open(&hKey)) return defaultValue;

        DWORD value = 0;
        DWORD type  = 0;
        DWORD size  = sizeof(value);
        bool  ok    = api.RegQueryValueExW(hKey, name, nullptr, &type,
                          reinterpret_cast<LPBYTE>(&value), &size) == ERROR_SUCCESS
                      && type == REG_DWORD;
        api.RegCloseKey(hKey);
        return ok ? value : defaultValue;
    }

    void ReadString(const wchar_t* name, wchar_t* buf, DWORD bufChars, const wchar_t* defaultValue)
    {
        bool ok = false;
        HKEY hKey;
        if (bufChars == 0) return;

        if (Open(&hKey))
        {
            DWORD type = 0;
            DWORD size = (bufChars - 1) * sizeof(wchar_t);   // keep room for NUL
            ok = api.RegQueryValueExW(hKey, name, nullptr, &type,
                     reinterpret_cast<LPBYTE>(buf), &size) == ERROR_SUCCESS
                 && (type == REG_SZ || type == REG_EXPAND_SZ);
            if (ok)
            {
                buf[size / sizeof(wchar_t)] = L'\0';
                ok = buf[0] != L'\0';
            }
            api.RegCloseKey(hKey);
        }

        if (!ok)
            StringCchCopyW(buf, bufChars, defaultValue);
    }

    bool ReadBinary(const wchar_t* name, BYTE* buf, DWORD size)
    {
        HKEY hKey;
        if (!Open(&hKey)) return false;

        DWORD type = 0;
        DWORD got  = size;
        bool  ok   = api.RegQueryValueExW(hKey, name, nullptr, &type, buf, &got) == ERROR_SUCCESS
                     && type == REG_BINARY && got == size;
        api.RegCloseKey(hKey);
        return ok;
    }

    bool WriteBinary(const wchar_t* name, const BYTE* data, DWORD size)
    {
        wchar_t path[256];
        HKEY    hKey;
        KeyPath(path, _countof(path));

        if (api.RegCreateKeyExW(HKEY_LOCAL_MACHINE, path, 0, nullptr, REG_OPTION_NON_VOLATILE,
                KEY_READ | KEY_WRITE, nullptr, &hKey, nullptr) != ERROR_SUCCESS)
            return false;

        bool ok = api.RegSetValueExW(hKey, name, 0, REG_BINARY, data, size) == ERROR_SUCCESS;
        api.RegCloseKey(hKey);
        return ok;
    }
}
