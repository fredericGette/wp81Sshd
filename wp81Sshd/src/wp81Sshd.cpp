/**
 * Context:
 * win32 console application,
 * linked with Msvcr110.dll,
 * architecture ARM 32bit little endian.
 * Use secure functions when possible, example: _snprintf_s instead of _snprintf
 *
 * wp81Sshd: SSH server running as a Windows Phone 8.1 service.
 * Service structure from wp81TimerService, SSH protocol code from wp81ssh.
 */

#include "Win32Api.h"
#include <ws2tcpip.h>
#include <strsafe.h>
#include <stdio.h>
#include <string.h>

#include "log.h"
#include "config.h"
#include "selftest.h"
#include "ssh_server.h"
#include "ssh_transport.h"
#include "base64.h"
#include "crypto/ed25519.h"

// ─── Configuration ────────────────────────────────────────────────────────────
const wchar_t* SERVICE_NAME           = L"wp81Sshd";
static const wchar_t* SERVICE_DISPLAY = L"SSH Server";
static const wchar_t* SERVICE_DESC    = L"Accepts SSH connections and provides a command shell.";

static const DWORD    DEFAULT_PORT         = 22;
static const DWORD    DEFAULT_MAX_SESSIONS = 4;
static const DWORD    MAX_MAX_SESSIONS     = 16;
static const wchar_t* DEFAULT_AUTHORIZED_KEYS = L"C:\\Data\\USERS\\Public\\Documents\\wp81Sshd\\authorized_keys";
static const wchar_t* DEFAULT_SHELL           = L"C:\\Windows\\System32\\cmd.exe";
static const wchar_t* DEFAULT_HOME            = L"C:\\Data\\USERS\\Public\\Documents";
// ─────────────────────────────────────────────────────────────────────────────

Win32Api api;

static SERVICE_STATUS        g_Status       = {};
static SERVICE_STATUS_HANDLE g_StatusHandle = nullptr;
static HANDLE                g_StopEvent    = nullptr;

// ─── Session registry ────────────────────────────────────────────────────────
struct SessionSlot
{
    SshSession* session;   // nullptr = free slot
    HANDLE      thread;
};

static SessionSlot      g_slots[MAX_MAX_SESSIONS] = {};
static CRITICAL_SECTION g_slotsLock;
static unsigned         g_nextSessionId = 1;

static DWORD WINAPI SessionThread(LPVOID param)
{
    SshSession* s = static_cast<SshSession*>(param);

    LOGF(TRACE_LEVEL_INFORMATION, "[%u] connection from %s", s->id, s->peer_addr);
    ssh_session_run(s);

    // Close the socket under the lock so StopAllSessions never touches a
    // closed (and possibly reused) handle.
    EnterCriticalSection(&g_slotsLock);
    shutdown(s->sock, SD_BOTH);
    closesocket(s->sock);
    s->sock = INVALID_SOCKET;
    LeaveCriticalSection(&g_slotsLock);

    LOGF(TRACE_LEVEL_INFORMATION, "[%u] connection closed", s->id);
    return 0;
}

// Free the slots of finished sessions. Returns the number still running.
static DWORD ReapSessions()
{
    DWORD active = 0;
    EnterCriticalSection(&g_slotsLock);
    for (DWORD i = 0; i < MAX_MAX_SESSIONS; i++)
    {
        if (!g_slots[i].session) continue;
        if (api.WaitForSingleObject(g_slots[i].thread, 0) == WAIT_OBJECT_0)
        {
            CloseHandle(g_slots[i].thread);
            ssh_session_free(g_slots[i].session);
            g_slots[i].session = nullptr;
            g_slots[i].thread  = nullptr;
        }
        else
        {
            active++;
        }
    }
    LeaveCriticalSection(&g_slotsLock);
    return active;
}

static void StopAllSessions()
{
    HANDLE threads[MAX_MAX_SESSIONS];
    DWORD  count = 0;

    EnterCriticalSection(&g_slotsLock);
    for (DWORD i = 0; i < MAX_MAX_SESSIONS; i++)
    {
        SshSession* s = g_slots[i].session;
        if (!s) continue;
        InterlockedExchange(&s->closing, 1);
        if (s->sock != INVALID_SOCKET)
            shutdown(s->sock, SD_BOTH);   // unblocks the session's recv()
        threads[count++] = g_slots[i].thread;
    }
    LeaveCriticalSection(&g_slotsLock);

    if (count > 0)
    {
        LOGF(TRACE_LEVEL_INFORMATION, "Waiting for %lu session(s) to end.", count);
        api.WaitForMultipleObjects(count, threads, TRUE, 8000);
    }
    ReapSessions();
}

// ─── Host key ────────────────────────────────────────────────────────────────
// Load the host key from the registry, generating and storing it if missing.
static bool LoadOrCreateHostKey(HostKey* key, bool* created)
{
    *created = false;
    if (!Config::ReadBinary(L"HostKey", key->seed, sizeof(key->seed)))
    {
        if (ssh_random(key->seed, sizeof(key->seed)) != 0)
            return false;
        if (!Config::WriteBinary(L"HostKey", key->seed, sizeof(key->seed)))
        {
            LOGF(TRACE_LEVEL_ERROR, "Cannot store the host key in the registry: %lu", GetLastError());
            SecureZeroMemory(key->seed, sizeof(key->seed));
            return false;
        }
        *created = true;
    }
    ed25519_public_from_seed(key->seed, key->pub);
    return true;
}

static void PublicKeyLine(const HostKey* key, char* out, size_t outSize)
{
    uint8_t blob[SSH_ED25519_BLOB_LEN];
    char    b64[128];
    ssh_ed25519_blob(key->pub, blob);
    base64_encode(blob, sizeof(blob), b64, sizeof(b64), 1);
    _snprintf_s(out, outSize, _TRUNCATE, "ssh-ed25519 %s wp81Sshd", b64);
}

// ─── Server ──────────────────────────────────────────────────────────────────
// Parse a dotted-quad IPv4 address. Returns false if malformed.
static bool ParseIPv4(const wchar_t* str, in_addr* out)
{
    unsigned char bytes[4];
    for (int i = 0; i < 4; i++)
    {
        unsigned value = 0;
        int      digits = 0;
        while (*str >= L'0' && *str <= L'9' && digits < 3)
        {
            value = value * 10 + (unsigned)(*str++ - L'0');
            digits++;
        }
        if (digits == 0 || value > 255) return false;
        bytes[i] = (unsigned char)value;
        if (i < 3 && *str++ != L'.') return false;
    }
    if (*str != L'\0') return false;
    memcpy(out, bytes, 4);
    return true;
}

static void FormatPeer(const sockaddr_in* sa, char* out, size_t outSize)
{
    const unsigned char* b = reinterpret_cast<const unsigned char*>(&sa->sin_addr);
    _snprintf_s(out, outSize, _TRUNCATE, "%u.%u.%u.%u:%u",
        b[0], b[1], b[2], b[3], (unsigned)ntohs(sa->sin_port));
}

// Runs until stopEvent is signalled. Returns false if the server could not start.
static bool RunServer(HANDLE stopEvent)
{
    HostKey  hostKey;
    bool     created = false;
    wchar_t  authorizedKeys[MAX_PATH];
    wchar_t  shell[MAX_PATH];
    wchar_t  home[MAX_PATH];
    wchar_t  listenAddress[64];
    in_addr  bindAddr;
    WSADATA  wsa;
    bool     ok = false;

    DWORD port        = Config::ReadDword(L"Port", DEFAULT_PORT);
    DWORD maxSessions = Config::ReadDword(L"MaxSessions", DEFAULT_MAX_SESSIONS);
    if (port == 0 || port > 65535) port = DEFAULT_PORT;
    if (maxSessions == 0) maxSessions = 1;
    if (maxSessions > MAX_MAX_SESSIONS) maxSessions = MAX_MAX_SESSIONS;
    Config::ReadString(L"AuthorizedKeysFile", authorizedKeys, _countof(authorizedKeys), DEFAULT_AUTHORIZED_KEYS);
    Config::ReadString(L"ShellCommand", shell, _countof(shell), DEFAULT_SHELL);
    Config::ReadString(L"HomeDirectory", home, _countof(home), DEFAULT_HOME);
    Config::ReadString(L"ListenAddress", listenAddress, _countof(listenAddress), L"0.0.0.0");
    if (!ParseIPv4(listenAddress, &bindAddr))
    {
        FileLogger::LogEventF(TRACE_LEVEL_CRITICAL, L"Invalid ListenAddress '%s'.", listenAddress);
        return false;
    }

    if (!LoadOrCreateHostKey(&hostKey, &created))
    {
        LOGF(TRACE_LEVEL_CRITICAL, "No host key available.");
        return false;
    }
    {
        char fp[64];
        ssh_fingerprint(hostKey.pub, fp, sizeof(fp));
        LOGF(TRACE_LEVEL_INFORMATION, "Host key %s: ED25519 %s", created ? "generated" : "loaded", fp);
    }
    FileLogger::LogEventF(TRACE_LEVEL_INFORMATION, L"authorized_keys: %s", authorizedKeys);
    FileLogger::LogEventF(TRACE_LEVEL_INFORMATION, L"Shell: %s", shell);

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        LOGF(TRACE_LEVEL_CRITICAL, "WSAStartup failed: %d", WSAGetLastError());
        SecureZeroMemory(&hostKey, sizeof(hostKey));
        return false;
    }

    SOCKET   listener = INVALID_SOCKET;
    WSAEVENT acceptEvent = WSA_INVALID_EVENT;

    do
    {
        listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listener == INVALID_SOCKET)
        {
            LOGF(TRACE_LEVEL_CRITICAL, "socket failed: %d", WSAGetLastError());
            break;
        }
        // Children (cmd.exe) must not inherit sockets, otherwise a connection
        // stays open as long as any shell is alive.
        SetHandleInformation(reinterpret_cast<HANDLE>(listener), HANDLE_FLAG_INHERIT, 0);

        sockaddr_in addr = {};
        addr.sin_family      = AF_INET;
        addr.sin_addr        = bindAddr;
        addr.sin_port        = htons(static_cast<u_short>(port));
        if (bind(listener, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR)
        {
            FileLogger::LogEventF(TRACE_LEVEL_CRITICAL, L"bind to %s:%lu failed: %d",
                listenAddress, port, WSAGetLastError());
            break;
        }
        if (listen(listener, SOMAXCONN) == SOCKET_ERROR)
        {
            LOGF(TRACE_LEVEL_CRITICAL, "listen failed: %d", WSAGetLastError());
            break;
        }

        acceptEvent = WSACreateEvent();
        if (acceptEvent == WSA_INVALID_EVENT ||
            WSAEventSelect(listener, acceptEvent, FD_ACCEPT) == SOCKET_ERROR)
        {
            LOGF(TRACE_LEVEL_CRITICAL, "WSAEventSelect failed: %d", WSAGetLastError());
            break;
        }

        ok = true;
        FileLogger::LogEventF(TRACE_LEVEL_INFORMATION, L"Listening on %s:%lu (max %lu sessions).",
            listenAddress, port, maxSessions);

        HANDLE waits[2] = { stopEvent, acceptEvent };
        for (;;)
        {
            DWORD w = api.WaitForMultipleObjects(2, waits, FALSE, INFINITE);
            if (w != WAIT_OBJECT_0 + 1)
                break;   // stop requested (or wait failure)

            WSANETWORKEVENTS ne;
            WSAEnumNetworkEvents(listener, acceptEvent, &ne);   // resets the event

            for (;;)
            {
                sockaddr_in peer = {};
                int         peerLen = sizeof(peer);
                SOCKET      client = accept(listener, reinterpret_cast<sockaddr*>(&peer), &peerLen);
                if (client == INVALID_SOCKET)
                    break;   // WSAEWOULDBLOCK: no more pending connections

                // An accepted socket inherits the listener's event selection
                // and non-blocking mode: undo both, sessions use blocking I/O.
                WSAEventSelect(client, nullptr, 0);
                u_long blocking = 0;
                ioctlsocket(client, FIONBIO, &blocking);
                SetHandleInformation(reinterpret_cast<HANDLE>(client), HANDLE_FLAG_INHERIT, 0);
                BOOL nodelay = TRUE;
                setsockopt(client, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&nodelay), sizeof(nodelay));

                char peerStr[64];
                FormatPeer(&peer, peerStr, sizeof(peerStr));

                if (ReapSessions() >= maxSessions)
                {
                    LOGF(TRACE_LEVEL_WARNING, "Refusing connection from %s: too many sessions.", peerStr);
                    closesocket(client);
                    continue;
                }

                SshSession* s = ssh_session_new(client, g_nextSessionId++, peerStr);
                if (!s)
                {
                    closesocket(client);
                    continue;
                }
                s->host_key = &hostKey;
                StringCchCopyW(s->authorized_keys_path, _countof(s->authorized_keys_path), authorizedKeys);
                StringCchCopyW(s->shell_command, _countof(s->shell_command), shell);
                StringCchCopyW(s->home_dir, _countof(s->home_dir), home);

                EnterCriticalSection(&g_slotsLock);
                DWORD slot = 0;
                while (slot < MAX_MAX_SESSIONS && g_slots[slot].session) slot++;
                HANDLE th = (slot < MAX_MAX_SESSIONS)
                    ? CreateThread(nullptr, 0, SessionThread, s, 0, nullptr)
                    : nullptr;
                if (th)
                {
                    g_slots[slot].session = s;
                    g_slots[slot].thread  = th;
                }
                LeaveCriticalSection(&g_slotsLock);

                if (!th)
                {
                    LOGF(TRACE_LEVEL_ERROR, "Cannot start a session thread: %lu", GetLastError());
                    closesocket(client);
                    ssh_session_free(s);
                }
            }
        }
    } while (false);

    if (acceptEvent != WSA_INVALID_EVENT) WSACloseEvent(acceptEvent);
    if (listener != INVALID_SOCKET) closesocket(listener);

    StopAllSessions();   // sessions reference hostKey: stop them before it goes away
    WSACleanup();
    SecureZeroMemory(&hostKey, sizeof(hostKey));
    return ok;
}

// ── Report service status helper ──────────────────────────────────────────────
static void ReportStatus(DWORD currentState, DWORD waitHint = 0, DWORD exitCode = NO_ERROR)
{
    static DWORD checkPoint = 1;
    g_Status.dwCurrentState  = currentState;
    g_Status.dwWaitHint      = waitHint;
    g_Status.dwWin32ExitCode = exitCode;
    g_Status.dwCheckPoint    = (currentState == SERVICE_RUNNING ||
                                currentState == SERVICE_STOPPED) ? 0 : checkPoint++;
    api.SetServiceStatus(g_StatusHandle, &g_Status);
}

// ── Service control handler ───────────────────────────────────────────────────
static DWORD WINAPI ServiceCtrlHandlerEx(DWORD ctrl, DWORD /*eventType*/, LPVOID /*eventData*/, LPVOID /*ctx*/)
{
    if (ctrl == SERVICE_CONTROL_STOP || ctrl == SERVICE_CONTROL_SHUTDOWN)
    {
        FileLogger::LogEvent(TRACE_LEVEL_INFORMATION, L"Service stop requested.");
        ReportStatus(SERVICE_STOP_PENDING, 10000);
        SetEvent(g_StopEvent);
    }
    return NO_ERROR;
}

// ── Main service logic ────────────────────────────────────────────────────────
static VOID WINAPI ServiceMain(DWORD /*argc*/, LPWSTR* /*argv*/)
{
    g_StatusHandle = api.RegisterServiceCtrlHandlerExW(SERVICE_NAME, ServiceCtrlHandlerEx, nullptr);
    if (!g_StatusHandle) return;

    FileLogger::Init();

    g_Status.dwServiceType      = SERVICE_WIN32_OWN_PROCESS;
    g_Status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    g_Status.dwCurrentState     = SERVICE_START_PENDING;
    api.SetServiceStatus(g_StatusHandle, &g_Status);

    g_StopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_StopEvent)
    {
        ReportStatus(SERVICE_STOPPED, 0, GetLastError());
        return;
    }

    ReportStatus(SERVICE_RUNNING);
    FileLogger::LogEvent(TRACE_LEVEL_INFORMATION, L"Service started.");

    bool ok = RunServer(g_StopEvent);

    CloseHandle(g_StopEvent);
    FileLogger::LogEvent(TRACE_LEVEL_INFORMATION, L"Service stopped.");
    ReportStatus(SERVICE_STOPPED, 0, ok ? NO_ERROR : ERROR_SERVICE_SPECIFIC_ERROR);
}

// ── Install / Uninstall helpers ───────────────────────────────────────────────
static bool InstallService()
{
    wchar_t path[MAX_PATH];
    if (!api.GetModuleFileNameW(nullptr, path, MAX_PATH))
    {
        wprintf(L"GetModuleFileName failed: %lu\n", GetLastError());
        return false;
    }

    SC_HANDLE hSCM = api.OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!hSCM) { wprintf(L"OpenSCManager failed: %lu\n", GetLastError()); return false; }

    SC_HANDLE hSvc = api.CreateServiceW(
        hSCM, SERVICE_NAME, SERVICE_DISPLAY,
        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
        path, nullptr, nullptr, nullptr, nullptr, nullptr);

    if (!hSvc)
    {
        wprintf(L"CreateService failed: %lu\n", GetLastError());
        api.CloseServiceHandle(hSCM);
        return false;
    }

    SERVICE_DESCRIPTIONW sd = { const_cast<wchar_t*>(SERVICE_DESC) };
    api.ChangeServiceConfig2W(hSvc, SERVICE_CONFIG_DESCRIPTION, &sd);

    wprintf(L"Service installed successfully.\n");
    wprintf(L"Put your public key(s) (ssh-ed25519 only) in:\n  %s\n", DEFAULT_AUTHORIZED_KEYS);
    wprintf(L"Optional settings:\n");
    wprintf(L"  reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\%s\\Parameters\" /v Port /t REG_DWORD /d 22 /f\n", SERVICE_NAME);
    wprintf(L"  reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\%s\\Parameters\" /v LogFile /t REG_SZ /d \"C:\\path\\to\\wp81Sshd.log\" /f\n", SERVICE_NAME);
    wprintf(L"Show the host key fingerprint:  wp81Sshd.exe hostkey\n");
    wprintf(L"Start the service:              sc start %s\n", SERVICE_NAME);

    api.CloseServiceHandle(hSvc);
    api.CloseServiceHandle(hSCM);
    return true;
}

static bool UninstallService()
{
    SC_HANDLE hSCM = api.OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCM) { wprintf(L"OpenSCManager failed: %lu\n", GetLastError()); return false; }

    SC_HANDLE hSvc = api.OpenServiceW(hSCM, SERVICE_NAME, SERVICE_STOP | DELETE);
    if (!hSvc)
    {
        wprintf(L"OpenService failed: %lu\n", GetLastError());
        api.CloseServiceHandle(hSCM);
        return false;
    }

    SERVICE_STATUS ss;
    api.ControlService(hSvc, SERVICE_CONTROL_STOP, &ss); // try to stop first
    api.Sleep(1000);

    bool ok = api.DeleteService(hSvc) != FALSE;
    if (!ok)
        wprintf(L"DeleteService failed: %lu\n", GetLastError());
    else
        wprintf(L"Service uninstalled successfully.\n");

    api.CloseServiceHandle(hSvc);
    api.CloseServiceHandle(hSCM);
    return ok;
}

// ── Other commands ────────────────────────────────────────────────────────────
static int ShowHostKey()
{
    HostKey key;
    bool    created = false;
    char    line[256];
    char    fp[64];

    if (!LoadOrCreateHostKey(&key, &created))
    {
        wprintf(L"Cannot load or create the host key (run as administrator?).\n");
        return 1;
    }
    PublicKeyLine(&key, line, sizeof(line));
    ssh_fingerprint(key.pub, fp, sizeof(fp));
    printf("%s\n", created ? "New host key generated." : "Existing host key.");
    printf("Fingerprint: ED25519 %s\n", fp);
    printf("Public key : %s\n", line);
    SecureZeroMemory(&key, sizeof(key));
    return 0;
}

static void PrintLine(const char* line)
{
    printf("%s\n", line);
}

static int RunSelfTest()
{
    int fails = crypto_selftest(PrintLine);
    printf(fails ? "%d test(s) FAILED\n" : "All tests passed.\n", fails);
    return fails ? 1 : 0;
}

static int RunConsole()
{
    FileLogger::Init();
    FileLogger::SetConsoleEcho(true);
    printf("Running in the foreground; stop with Ctrl+C or by closing the session.\n");

    HANDLE stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    bool ok = RunServer(stopEvent);   // never signalled: runs until the process is killed
    CloseHandle(stopEvent);
    return ok ? 0 : 1;
}

static void Usage()
{
    wprintf(L"Usage: wp81Sshd.exe [command]\n"
            L"  (no command)  run as a service (started by the SCM)\n"
            L"  install       install the service\n"
            L"  uninstall     stop and remove the service\n"
            L"  hostkey       show (and create if needed) the host key\n"
            L"  console       run the server in the foreground, logging to the console\n"
            L"  selftest      run the cryptographic self tests\n");
}

// ── Entry point ───────────────────────────────────────────────────────────────
int wmain(int argc, wchar_t* argv[])
{
    InitializeCriticalSectionEx(&g_slotsLock, 0, 0);

    if (argc > 1)
    {
        if (_wcsicmp(argv[1], L"install") == 0)   return InstallService()   ? 0 : 1;
        if (_wcsicmp(argv[1], L"uninstall") == 0) return UninstallService() ? 0 : 1;
        if (_wcsicmp(argv[1], L"hostkey") == 0)   return ShowHostKey();
        if (_wcsicmp(argv[1], L"selftest") == 0)  return RunSelfTest();
        if (_wcsicmp(argv[1], L"console") == 0)   return RunConsole();
        wprintf(L"Unknown argument: %s\n", argv[1]);
        Usage();
        return 1;
    }

    // No arguments → hand control to the SCM
    SERVICE_TABLE_ENTRYW table[] = {
        { const_cast<wchar_t*>(SERVICE_NAME), ServiceMain },
        { nullptr, nullptr }
    };
    if (!api.StartServiceCtrlDispatcherW(table))
    {
        Usage();
        return 1;
    }
    return 0;
}
