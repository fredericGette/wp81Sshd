# wp81Sshd

A minimal SSH-2 **server** running as a Win32 service on **Windows Phone 8.1**.  
It gives every SSH client an interactive `cmd.exe`, as an encrypted and key-authenticated replacement for the telnet server.

Built from the same self-contained crypto as the [wp81ssh](https://github.com/fredericGette/wp81ssh) client (no external libraries), with the service structure of [wp81TimerService](https://github.com/fredericGette/wp81TimerService).

---

### Supported Algorithms

| Layer | Algorithm |
|---|---|
| Key Exchange | `curve25519-sha256` (+ `@libssh.org` alias, OpenSSH strict KEX) |
| Host Key | `ssh-ed25519` |
| Cipher | `aes256-ctr` |
| MAC | `hmac-sha2-256` |
| User authentication | `publickey` with `ssh-ed25519` keys only (no passwords) |

Tested with the following SSH client:  
- OpenSSH_10.3p1 (Windows)

---

## Features

- Interactive shell (`cmd.exe` by default) with local echo and line editing (backspace, Ctrl-U, Ctrl-C, Ctrl-D)
- Several simultaneous sessions (default 4, configurable)
- Ed25519 host key generated on first start and stored in the registry
- `authorized_keys` file in OpenSSH format, re-read at each login (no restart needed)
- Commands started from a session are killed when the session ends (job object)
- 30 s pre-authentication timeout, at most 20 authentication requests per connection
- File-based logging (disabled by default; enabled via registry)

---

## Installation

**Install the service:**

```bat
wp81Sshd.exe install
```

**Authorize your key.** On the computer, create a key if you do not have one (`ssh-keygen -t ed25519`), then copy the content of `id_ed25519.pub` to the phone in:

```
C:\Data\USERS\Public\Documents\wp81Sshd\authorized_keys
```

> [!NOTE]
> This folder is the shared folder visible in the Explorer of your computer when the phone is connected with a USB cable (`Documents\wp81Sshd\authorized_keys`).  
> One key per line; only `ssh-ed25519` keys are used.

**Show the host key fingerprint** (creates the host key if needed) to compare it with what the SSH client displays at the first connection:

```bat
wp81Sshd.exe hostkey
```

**Start the service:**

```bat
sc start wp81Sshd
```

**Connect from the computer:**

```bat
ssh user@<phone-ip>
```

The user name is not checked (the phone has a single account); it is only written to the log.

**Uninstall:**

```bat
sc stop wp81Sshd
wp81Sshd.exe uninstall
```

### Connecting over USB

As for the telnet server, the port can be forwarded through *IP over USB*: add a key named `SSH` under `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IpOverUsb` on the computer, with the same values as the [Telnet entry](https://github.com/fredericGette/wp81documentation/tree/main/telnetOverUsb#readme) but with port `22` on the phone side (and a free local port, e.g. `2222`, on the computer side if the computer already runs an SSH server). Restart the *IP over USB* service, then:

```bat
ssh -p 2222 user@127.0.0.1
```

To accept only connections arriving over USB, set `ListenAddress` to `127.0.0.1` (see below).

---

## Configuration

All values live under `HKLM\SYSTEM\CurrentControlSet\Services\wp81Sshd\Parameters`. They are read when the service starts (restart it to apply a change), except `authorized_keys` whose content is read at every login.

| Setting | Default | Registry value |
|---|---|---|
| TCP port | `22` | `Port` (REG_DWORD) |
| Listen address | `0.0.0.0` (all interfaces) | `ListenAddress` (REG_SZ, IPv4) |
| Maximum simultaneous sessions | `4` (max 16) | `MaxSessions` (REG_DWORD) |
| authorized_keys file | `C:\Data\USERS\Public\Documents\wp81Sshd\authorized_keys` | `AuthorizedKeysFile` (REG_SZ) |
| Shell | `C:\Windows\System32\cmd.exe` | `ShellCommand` (REG_SZ) |
| Log file | *(disabled)* | `LogFile` (REG_SZ) |
| Host key | generated at first start | `HostKey` (REG_BINARY, 32-byte Ed25519 seed) |

Example:

```bat
reg add "HKLM\SYSTEM\CurrentControlSet\Services\wp81Sshd\Parameters" /v LogFile /t REG_SZ /d "C:\Data\USERS\Public\Documents\wp81Sshd\wp81Sshd.log" /f
```

> [!WARNING]
> `HostKey` is the server's private key: whoever reads it can impersonate the phone. Deleting it makes the service generate a new one (clients will then warn that the host key changed).

---

## Commands

```
wp81Sshd.exe install     install the service (automatic start)
wp81Sshd.exe uninstall   stop and remove the service
wp81Sshd.exe hostkey     show (and create if needed) the host key and its fingerprint
wp81Sshd.exe console     run the server in the foreground, logging to the console
wp81Sshd.exe selftest    run known-answer tests of the crypto (SHA-2, HMAC, AES-CTR, X25519, Ed25519)
```

`console` is convenient for a first test from a telnet session, before installing the service.

---

## Logging

When a `LogFile` registry value is set (or in `console` mode), the service writes UTF-8 lines in the format:

```
YYYY-MM-DD HH:MM:SS [LEVEL] [session] message
```

Log levels: `CRIT`, `ERROR`, `WARN`, `INFO`, `VERB`.

---

## Limitations

- Windows Phone 8.1 has no pseudo console: the shell runs on pipes. Line editing happens in the server (no command history, no tab completion), and full-screen programs do not work.
- Ctrl-C cannot interrupt a running command; it only discards the line being typed. Closing the session kills everything started from it.
- `cmd.exe` output is passed through as-is, in the phone's OEM code page.
- No `exec` requests (`ssh phone dir`), no SFTP/SCP, no port forwarding, no re-keying (irrelevant for interactive sessions).
- IPv4 only.
- The service runs as LocalSystem: anyone whose key is in `authorized_keys` has full control of the phone. Keep in mind that the default `authorized_keys` location is writable through the USB shared folder.

---

## Building

Same toolchain as wp81ssh: LLVM (`clang-cl`, `lld-link`), CMake, Ninja, and the Windows Phone 8.1 SDK.

```bat
cd wp81Sshd
cmake --preset arm32-windows
cmake --build build
```

---

## Deployment

- [Install a telnet server on the phone](https://github.com/fredericGette/wp81documentation/tree/main/telnetOverUsb#readme), in order to run the installation commands.  
- Manually copy the executable from the root of this GitHub repository to the shared folder of the phone.
> [!NOTE]
> When you connect your phone with a USB cable, this folder is visible in the Explorer of your computer. And in the phone, this folder is mounted in `C:\Data\USERS\Public\Documents`
