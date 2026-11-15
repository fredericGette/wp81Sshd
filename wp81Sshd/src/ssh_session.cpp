/*
 * ssh_session.cpp  -  One SSH connection: banner, KEX, auth, then a
 *                     "session" channel bridged to a shell process.
 *
 * Threads per connection:
 *   - session thread (ssh_session_run): reads packets from the socket and
 *     dispatches them; writes keystrokes to the shell's stdin.
 *   - output pump thread: reads the shell's stdout/stderr pipe and sends it
 *     as CHANNEL_DATA, honouring the client's window.
 *
 * Windows Phone 8.1 has no pseudo console, so the shell runs on plain pipes.
 * When the client requests a PTY, a small line discipline runs here:
 * local echo, backspace, Ctrl-U, Ctrl-C (discard line), Ctrl-D (EOF), and
 * escape sequences (arrow keys...) are swallowed.  cmd.exe echoes every line
 * it reads from a pipe, so that echo is filtered out of its output.
 */

#include "ssh_server.h"
#include "ssh_transport.h"
#include "ssh_kex_server.h"
#include "ssh_auth_server.h"
#include "base64.h"
#include "log.h"
#include "crypto/sha256.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define LOCAL_WINDOW_SIZE    (256 * 1024)
#define LOCAL_MAX_PACKET     32768
#define PREAUTH_TIMEOUT_MS   30000
#define LINE_MAX             1024
#define ECHO_FILTER_MAX      (LINE_MAX + 2)
#define ECHO_HOLD_MS         500
#define PUMP_POLL_MS         30
#define STDIN_PIPE_SIZE      (64 * 1024)

/* Serialises "create inheritable pipes + CreateProcess" across sessions,
 * so a child never inherits another session's pipe ends. */
static CRITICAL_SECTION g_spawnLock;
static volatile LONG    g_spawnLockState = 0;

static void spawn_lock_init()
{
	if (g_spawnLockState == 2) return;
	if (InterlockedCompareExchange(&g_spawnLockState, 1, 0) == 0) {
		InitializeCriticalSectionEx(&g_spawnLock, 0, 0);
		InterlockedExchange(&g_spawnLockState, 2);
	}
	while (g_spawnLockState != 2) api.Sleep(0);
}

/* ------------------------------------------------------------------ channel state */
typedef struct {
	SshSession *s;

	/* SSH channel */
	int        open;
	uint32_t   remote_id;
	uint32_t   remote_window;        /* protected by s->send_lock */
	uint32_t   remote_max_packet;
	uint32_t   local_consumed;       /* bytes received since last WINDOW_ADJUST */
	int        eof_sent;             /* protected by s->send_lock */
	int        close_sent;           /* protected by s->send_lock */
	HANDLE     window_event;         /* auto-reset: window grew or closing */

	/* terminal */
	int        pty;
	char       line[LINE_MAX];
	size_t     line_len;
	int        last_was_cr;
	int        esc_state;            /* 0 none, 1 after ESC, 2 in CSI, 3 in SS3 */

	/* shell process */
	int        shell_started;
	HANDLE     hProcess;
	HANDLE     hJob;                 /* kill-on-close job: ends the whole process tree */
	HANDLE     hStdinWr;             /* our end of the child's stdin */
	HANDLE     hStdoutRd;            /* our end of the child's stdout+stderr */
	HANDLE     hPump;

	/* echo filter (shared session thread <-> pump thread) */
	CRITICAL_SECTION echo_lock;
	char       echo_expect[ECHO_FILTER_MAX];
	size_t     echo_len;             /* bytes expected */
	size_t     echo_matched;         /* bytes already swallowed */
	ULONGLONG  echo_since;           /* when the first byte was swallowed */
	int        out_last_cr;          /* LF -> CRLF translation state */
} Channel;

/* ================================================================== helpers */

void ssh_ed25519_blob(const uint8_t pub[32], uint8_t out[SSH_ED25519_BLOB_LEN])
{
	size_t off = 0;
	buf_put_cstring(out, SSH_ED25519_BLOB_LEN, &off, "ssh-ed25519");
	buf_put_string(out, SSH_ED25519_BLOB_LEN, &off, pub, 32);
}

void ssh_fingerprint(const uint8_t pub[32], char *out, size_t out_size)
{
	uint8_t blob[SSH_ED25519_BLOB_LEN];
	uint8_t digest[32];
	char    b64[64];

	ssh_ed25519_blob(pub, blob);
	sha256(blob, sizeof(blob), digest);
	base64_encode(digest, sizeof(digest), b64, sizeof(b64), 0);
	_snprintf_s(out, out_size, _TRUNCATE, "SHA256:%s", b64);
}

SshSession *ssh_session_new(SOCKET sock, unsigned id, const char *peer_addr)
{
	SshSession *s = (SshSession *)calloc(1, sizeof(SshSession));
	if (!s) return NULL;
	s->sock = sock;
	s->id = id;
	strncpy_s(s->peer_addr, sizeof(s->peer_addr), peer_addr, _TRUNCATE);
	InitializeCriticalSectionEx(&s->send_lock, 0, 0);
	if (ssh_random((uint8_t *)&s->pad_rng, sizeof(s->pad_rng)) != 0 || s->pad_rng == 0)
		s->pad_rng = GetTickCount() | 1;
	return s;
}

void ssh_session_free(SshSession *s)
{
	if (!s) return;
	DeleteCriticalSection(&s->send_lock);
	free(s->own_kexinit);
	free(s->peer_kexinit);
	SecureZeroMemory(s, sizeof(*s));
	free(s);
}

/* ================================================================== channel output */

static int send_channel_simple(Channel *c, uint8_t msg)
{
	uint8_t pkt[5];
	pkt[0] = msg;
	buf_put_u32(pkt + 1, c->remote_id);
	return ssh_send_packet(c->s, pkt, 5);
}

/* Send EOF + CLOSE once.  Thread-safe. */
static void channel_send_close(Channel *c)
{
	EnterCriticalSection(&c->s->send_lock);
	if (!c->eof_sent) {
		c->eof_sent = 1;
		send_channel_simple(c, SSH_MSG_CHANNEL_EOF);
	}
	if (!c->close_sent) {
		c->close_sent = 1;
		send_channel_simple(c, SSH_MSG_CHANNEL_CLOSE);
	}
	LeaveCriticalSection(&c->s->send_lock);
}

/*
 * Send up to `len` bytes as CHANNEL_DATA without waiting for window space.
 * Returns bytes sent (possibly 0), or -1 on error.
 */
static int channel_send_some(Channel *c, const uint8_t *data, size_t len)
{
	uint8_t pkt[LOCAL_MAX_PACKET + 16];
	size_t  n, off = 0;
	int     rc;

	EnterCriticalSection(&c->s->send_lock);
	if (c->close_sent || c->eof_sent) {
		LeaveCriticalSection(&c->s->send_lock);
		return -1;
	}
	n = len;
	if (n > c->remote_window) n = c->remote_window;
	if (n > c->remote_max_packet) n = c->remote_max_packet;
	if (n > LOCAL_MAX_PACKET) n = LOCAL_MAX_PACKET;
	if (n == 0) {
		LeaveCriticalSection(&c->s->send_lock);
		return 0;
	}

	buf_put_byte(pkt, sizeof(pkt), &off, SSH_MSG_CHANNEL_DATA);
	buf_put_u32_at(pkt, sizeof(pkt), &off, c->remote_id);
	buf_put_string(pkt, sizeof(pkt), &off, data, n);
	rc = ssh_send_packet(c->s, pkt, off);
	if (rc == 0) c->remote_window -= (uint32_t)n;
	LeaveCriticalSection(&c->s->send_lock);
	return rc == 0 ? (int)n : -1;
}

/* Send all bytes, waiting for window adjustments.  Pump thread only.
 * Returns 0 on success, -1 if the session is closing or on error. */
static int channel_send_all(Channel *c, const uint8_t *data, size_t len)
{
	while (len > 0) {
		int n;
		if (c->s->closing) return -1;
		n = channel_send_some(c, data, len);
		if (n < 0) return -1;
		if (n == 0) {
			api.WaitForSingleObject(c->window_event, 250);
			continue;
		}
		data += n;
		len -= (size_t)n;
	}
	return 0;
}

/* Echo from the session thread: it cannot block waiting for window space
 * (it is the thread that processes WINDOW_ADJUST), so excess is dropped.
 * In practice the client's window (2 MB for OpenSSH) is never exhausted
 * by keystroke echo. */
static void channel_echo(Channel *c, const char *data, size_t len)
{
	if (c->pty && len > 0)
		channel_send_some(c, (const uint8_t *)data, len);
}

/* ================================================================== shell process */

static int shell_spawn(Channel *c)
{
	SECURITY_ATTRIBUTES sa = {};
	HANDLE  hInRd = NULL, hInWr = NULL, hOutRd = NULL, hOutWr = NULL;
	wchar_t cmdline[MAX_PATH];
	BOOL    launched;
	PROCESS_INFORMATION pi = {};
	STARTUPINFOW si = {};

	sa.nLength = sizeof(sa);
	sa.bInheritHandle = TRUE;
	wcscpy_s(cmdline, MAX_PATH, c->s->shell_command);

	spawn_lock_init();
	EnterCriticalSection(&g_spawnLock);

	if (!CreatePipe(&hInRd, &hInWr, &sa, STDIN_PIPE_SIZE) ||
		!CreatePipe(&hOutRd, &hOutWr, &sa, 0)) {
		LOGF(TRACE_LEVEL_ERROR, "[%u] CreatePipe failed: %lu", c->s->id, GetLastError());
		LeaveCriticalSection(&g_spawnLock);
		if (hInRd) CloseHandle(hInRd);
		if (hInWr) CloseHandle(hInWr);
		if (hOutRd) CloseHandle(hOutRd);
		if (hOutWr) CloseHandle(hOutWr);
		return -1;
	}

	/* Our ends must not be inherited */
	SetHandleInformation(hInWr, HANDLE_FLAG_INHERIT, 0);
	SetHandleInformation(hOutRd, HANDLE_FLAG_INHERIT, 0);

	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
	si.wShowWindow = SW_HIDE;
	si.hStdInput = hInRd;
	si.hStdOutput = hOutWr;
	si.hStdError = hOutWr;   /* stderr merged into stdout */

	launched = api.CreateProcessW(NULL, cmdline, NULL, NULL, TRUE, CREATE_NO_WINDOW,
		NULL, NULL, &si, &pi);

	/* Close the child's ends in this process (also on failure) */
	CloseHandle(hInRd);
	CloseHandle(hOutWr);
	LeaveCriticalSection(&g_spawnLock);

	if (!launched) {
		LOGF(TRACE_LEVEL_ERROR, "[%u] CreateProcess '%S' failed: %lu",
			c->s->id, c->s->shell_command, GetLastError());
		CloseHandle(hInWr);
		CloseHandle(hOutRd);
		return -1;
	}

	/* Put the shell in a job that kills every process in it when the job
	 * handle is closed, so commands started from the shell (ping, a script...)
	 * do not outlive the session.  Best effort: without it, only the shell
	 * itself is terminated at the end of the session. */
	c->hJob = api.CreateJobObjectW ? api.CreateJobObjectW(NULL, NULL) : NULL;
	if (c->hJob) {
		JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {};
		limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
		if (!api.SetInformationJobObject(c->hJob, JobObjectExtendedLimitInformation, &limits, sizeof(limits)) ||
			!api.AssignProcessToJobObject(c->hJob, pi.hProcess)) {
			LOGF(TRACE_LEVEL_WARNING, "[%u] cannot use a job object (%lu): child processes may outlive the session",
				c->s->id, GetLastError());
			CloseHandle(c->hJob);
			c->hJob = NULL;
		}
	}

	CloseHandle(pi.hThread);
	c->hProcess = pi.hProcess;
	c->hStdinWr = hInWr;
	c->hStdoutRd = hOutRd;
	c->shell_started = 1;
	LOGF(TRACE_LEVEL_INFORMATION, "[%u] shell started: %S (pid %lu)",
		c->s->id, c->s->shell_command, pi.dwProcessId);
	return 0;
}

static void shell_write(Channel *c, const char *data, size_t len)
{
	DWORD written;
	if (!c->hStdinWr || len == 0) return;
	if (!WriteFile(c->hStdinWr, data, (DWORD)len, &written, NULL)) {
		CloseHandle(c->hStdinWr);
		c->hStdinWr = NULL;
	}
}

static void shell_close_stdin(Channel *c)
{
	if (c->hStdinWr) {
		CloseHandle(c->hStdinWr);
		c->hStdinWr = NULL;
	}
}

/* ================================================================== output pump */

/*
 * Forward output bytes to the client, applying (PTY mode only) the echo
 * filter and LF -> CRLF translation.  Called by the pump thread.
 */
static int pump_forward(Channel *c, const char *in, size_t len)
{
	char   out[8192 + 8192 + ECHO_FILTER_MAX];
	size_t n = 0, i;

	EnterCriticalSection(&c->echo_lock);
	for (i = 0; i < len; i++) {
		char ch = in[i];

		if (c->echo_len > 0) {
			if (ch == c->echo_expect[c->echo_matched]) {
				if (c->echo_matched == 0) c->echo_since = GetTickCount64();
				if (++c->echo_matched == c->echo_len) {
					c->echo_len = c->echo_matched = 0;
					c->out_last_cr = 0;
				}
				continue;   /* swallowed */
			}
			/* Mismatch: what was swallowed was real output after all */
			memcpy(out + n, c->echo_expect, c->echo_matched);
			n += c->echo_matched;
			c->echo_len = c->echo_matched = 0;
		}

		if (c->pty && ch == '\n' && !c->out_last_cr) out[n++] = '\r';
		c->out_last_cr = (ch == '\r');
		out[n++] = ch;
	}
	LeaveCriticalSection(&c->echo_lock);

	return channel_send_all(c, (const uint8_t *)out, n);
}

/* Release swallowed echo bytes if the rest never came. */
static int pump_flush_stale_echo(Channel *c, int force)
{
	char   held[ECHO_FILTER_MAX];
	size_t n = 0;

	EnterCriticalSection(&c->echo_lock);
	if (c->echo_matched > 0 &&
		(force || GetTickCount64() - c->echo_since > ECHO_HOLD_MS)) {
		memcpy(held, c->echo_expect, c->echo_matched);
		n = c->echo_matched;
		c->echo_len = c->echo_matched = 0;
	}
	LeaveCriticalSection(&c->echo_lock);

	return n ? channel_send_all(c, (const uint8_t *)held, n) : 0;
}

/* Read whatever is available in the pipe (never blocks). 1 = data read,
 * 0 = nothing available, -1 = pipe broken (all writers gone). */
static int pump_read(Channel *c, char *buf, size_t size, DWORD *got)
{
	DWORD avail = 0;
	*got = 0;
	if (!api.PeekNamedPipe(c->hStdoutRd, NULL, 0, NULL, &avail, NULL)) return -1;
	if (avail == 0) return 0;
	if (avail > size) avail = (DWORD)size;
	if (!ReadFile(c->hStdoutRd, buf, avail, got, NULL) || *got == 0) return -1;
	return 1;
}

static DWORD WINAPI pump_thread(LPVOID param)
{
	Channel *c = (Channel *)param;
	char     buf[8192];
	DWORD    got;
	DWORD    exit_code = 0;
	int      exited = 0;

	for (;;) {
		int r;
		if (c->s->closing) return 0;

		r = pump_read(c, buf, sizeof(buf), &got);
		if (r > 0) {
			if (pump_forward(c, buf, got) != 0) return 0;
			continue;
		}
		if (pump_flush_stale_echo(c, 0) != 0) return 0;

		if (r < 0 || api.WaitForSingleObject(c->hProcess, PUMP_POLL_MS) == WAIT_OBJECT_0) {
			/* Process exited (or every writer closed the pipe): drain what is left.
			 * A grandchild may still hold the pipe open, so do not block. */
			while (pump_read(c, buf, sizeof(buf), &got) > 0)
				if (pump_forward(c, buf, got) != 0) return 0;
			if (pump_flush_stale_echo(c, 1) != 0) return 0;
			if (r < 0)
				api.WaitForSingleObject(c->hProcess, 2000);
			exited = GetExitCodeProcess(c->hProcess, &exit_code) && exit_code != STILL_ACTIVE;
			break;
		}
	}

	if (c->s->closing) return 0;
	LOGF(TRACE_LEVEL_INFORMATION, "[%u] shell exited with code %lu", c->s->id, exit_code);

	/* exit-status, then EOF + CLOSE */
	if (exited) {
		uint8_t pkt[64];
		size_t  off = 0;
		buf_put_byte(pkt, sizeof(pkt), &off, SSH_MSG_CHANNEL_REQUEST);
		buf_put_u32_at(pkt, sizeof(pkt), &off, c->remote_id);
		buf_put_cstring(pkt, sizeof(pkt), &off, "exit-status");
		buf_put_byte(pkt, sizeof(pkt), &off, 0);
		buf_put_u32_at(pkt, sizeof(pkt), &off, exit_code);
		EnterCriticalSection(&c->s->send_lock);
		if (!c->close_sent) ssh_send_packet(c->s, pkt, off);
		LeaveCriticalSection(&c->s->send_lock);
	}
	channel_send_close(c);
	return 0;
}

/* ================================================================== input (line discipline) */

/* Queue the expected echo of a submitted line, then send it to the shell. */
static void submit_line(Channel *c)
{
	EnterCriticalSection(&c->echo_lock);
	/* If an earlier echo is still pending, typing ahead broke the pattern:
	 * give up on filtering rather than mismatching. */
	if (c->echo_len == 0) {
		memcpy(c->echo_expect, c->line, c->line_len);
		c->echo_expect[c->line_len] = '\r';
		c->echo_expect[c->line_len + 1] = '\n';
		c->echo_len = c->line_len + 2;
		c->echo_matched = 0;
	}
	LeaveCriticalSection(&c->echo_lock);

	channel_echo(c, "\r\n", 2);
	c->line[c->line_len++] = '\r';
	c->line[c->line_len++] = '\n';
	shell_write(c, c->line, c->line_len);
	c->line_len = 0;
}

static void erase_last_char(Channel *c)
{
	if (c->line_len == 0) return;
	/* Remove a whole UTF-8 sequence (continuation bytes are 10xxxxxx) */
	do {
		c->line_len--;
	} while (c->line_len > 0 && ((unsigned char)c->line[c->line_len] & 0xC0) == 0x80);
	channel_echo(c, "\b \b", 3);
}

static void handle_input(Channel *c, const uint8_t *data, size_t len)
{
	size_t i;

	if (!c->shell_started) return;

	if (!c->pty) {
		shell_write(c, (const char *)data, len);
		return;
	}

	for (i = 0; i < len; i++) {
		unsigned char ch = data[i];
		int           was_cr = c->last_was_cr;
		c->last_was_cr = 0;

		/* Swallow terminal escape sequences (arrows, function keys...) */
		if (c->esc_state == 1) {
			c->esc_state = (ch == '[') ? 2 : (ch == 'O') ? 3 : 0;
			continue;
		}
		if (c->esc_state == 2) {
			if (ch >= 0x40 && ch <= 0x7e) c->esc_state = 0;
			continue;
		}
		if (c->esc_state == 3) {
			c->esc_state = 0;
			continue;
		}

		switch (ch) {
		case 0x1b:                  /* ESC */
			c->esc_state = 1;
			break;
		case '\r':
			submit_line(c);
			c->last_was_cr = 1;
			break;
		case '\n':
			if (!was_cr) submit_line(c);   /* CR LF counts once */
			break;
		case 0x7f:                  /* DEL (usual backspace key) */
		case 0x08:                  /* BS */
			erase_last_char(c);
			break;
		case 0x15:                  /* Ctrl-U: erase line */
			while (c->line_len > 0) erase_last_char(c);
			break;
		case 0x03:                  /* Ctrl-C: discard line, ask for a new prompt */
			c->line_len = 0;
			channel_echo(c, "^C", 2);
			submit_line(c);
			break;
		case 0x04:                  /* Ctrl-D on empty line: EOF */
			if (c->line_len == 0) {
				shell_close_stdin(c);
			}
			break;
		case '\t':
			ch = ' ';
			/* fall through */
		default:
			if (ch < 0x20) break;   /* other control characters: ignore */
			if (c->line_len < LINE_MAX - 2) {
				c->line[c->line_len++] = (char)ch;
				channel_echo(c, (const char *)&ch, 1);
			}
			break;
		}
	}
}

/* ================================================================== connection protocol */

static int send_request_reply(Channel *c, int ok)
{
	return send_channel_simple(c, ok ? SSH_MSG_CHANNEL_SUCCESS : SSH_MSG_CHANNEL_FAILURE);
}

static int handle_channel_open(Channel *c, const uint8_t *buf, size_t len)
{
	size_t         off = 1;
	const uint8_t *type;
	size_t         type_len;
	uint32_t       sender, window, max_packet;
	uint8_t        pkt[128];
	size_t         poff = 0;

	if (buf_get_string(buf, len, &off, &type, &type_len) != 0 ||
		buf_get_u32_at(buf, len, &off, &sender) != 0 ||
		buf_get_u32_at(buf, len, &off, &window) != 0 ||
		buf_get_u32_at(buf, len, &off, &max_packet) != 0)
		return -1;

	if (!buf_eq(type, type_len, "session") || c->open) {
		uint32_t    reason = c->open ? SSH_OPEN_RESOURCE_SHORTAGE : SSH_OPEN_UNKNOWN_CHANNEL_TYPE;
		const char *desc = c->open ? "only one session channel per connection" : "unsupported channel type";
		LOGF(TRACE_LEVEL_INFORMATION, "[%u] refusing channel '%.*s'", c->s->id,
			(int)(type_len > 64 ? 64 : type_len), (const char *)type);
		buf_put_byte(pkt, sizeof(pkt), &poff, SSH_MSG_CHANNEL_OPEN_FAILURE);
		buf_put_u32_at(pkt, sizeof(pkt), &poff, sender);
		buf_put_u32_at(pkt, sizeof(pkt), &poff, reason);
		buf_put_cstring(pkt, sizeof(pkt), &poff, desc);
		buf_put_cstring(pkt, sizeof(pkt), &poff, "");
		return ssh_send_packet(c->s, pkt, poff);
	}

	EnterCriticalSection(&c->s->send_lock);
	c->open = 1;
	c->remote_id = sender;
	c->remote_window = window;
	c->remote_max_packet = max_packet ? max_packet : 1;
	LeaveCriticalSection(&c->s->send_lock);

	buf_put_byte(pkt, sizeof(pkt), &poff, SSH_MSG_CHANNEL_OPEN_CONFIRM);
	buf_put_u32_at(pkt, sizeof(pkt), &poff, sender);              /* recipient */
	buf_put_u32_at(pkt, sizeof(pkt), &poff, 0);                   /* our channel id */
	buf_put_u32_at(pkt, sizeof(pkt), &poff, LOCAL_WINDOW_SIZE);
	buf_put_u32_at(pkt, sizeof(pkt), &poff, LOCAL_MAX_PACKET);
	return ssh_send_packet(c->s, pkt, poff);
}

static int handle_channel_request(Channel *c, const uint8_t *buf, size_t len)
{
	size_t         off = 1;
	uint32_t       recipient;
	const uint8_t *type;
	size_t         type_len;
	uint8_t        want_reply = 0;

	if (buf_get_u32_at(buf, len, &off, &recipient) != 0 ||
		buf_get_string(buf, len, &off, &type, &type_len) != 0 ||
		buf_get_byte(buf, len, &off, &want_reply) != 0)
		return -1;
	if (!c->open) return -1;

	if (buf_eq(type, type_len, "pty-req")) {
		c->pty = 1;
		return want_reply ? send_request_reply(c, 1) : 0;
	}

	if (buf_eq(type, type_len, "shell")) {
		int ok = !c->shell_started && shell_spawn(c) == 0;
		if (want_reply && send_request_reply(c, ok) != 0) return -1;
		if (ok) {
			c->hPump = CreateThread(NULL, 0, pump_thread, c, 0, NULL);
			if (!c->hPump) {
				LOGF(TRACE_LEVEL_ERROR, "[%u] CreateThread (pump) failed: %lu", c->s->id, GetLastError());
				return -1;
			}
		}
		return 0;
	}

	/* window-change, env, signal, exec, subsystem, x11-req, agent forwarding... */
	LOGF(TRACE_LEVEL_VERBOSE, "[%u] declined channel request '%.*s'", c->s->id,
		(int)(type_len > 64 ? 64 : type_len), (const char *)type);
	return want_reply ? send_request_reply(c, 0) : 0;
}

static int handle_channel_data(Channel *c, const uint8_t *buf, size_t len, int extended)
{
	size_t         off = 1;
	uint32_t       recipient, data_type;
	const uint8_t *data;
	size_t         data_len;

	if (buf_get_u32_at(buf, len, &off, &recipient) != 0) return -1;
	if (extended && buf_get_u32_at(buf, len, &off, &data_type) != 0) return -1;
	if (buf_get_string(buf, len, &off, &data, &data_len) != 0) return -1;
	if (!c->open) return -1;

	if (!extended) handle_input(c, data, data_len);

	/* Re-open our receive window once half of it is used */
	c->local_consumed += (uint32_t)data_len;
	if (c->local_consumed >= LOCAL_WINDOW_SIZE / 2) {
		uint8_t pkt[9];
		size_t  poff = 0;
		buf_put_byte(pkt, sizeof(pkt), &poff, SSH_MSG_CHANNEL_WINDOW_ADJUST);
		buf_put_u32_at(pkt, sizeof(pkt), &poff, c->remote_id);
		buf_put_u32_at(pkt, sizeof(pkt), &poff, c->local_consumed);
		c->local_consumed = 0;
		return ssh_send_packet(c->s, pkt, poff);
	}
	return 0;
}

/* Main dispatch loop after authentication. */
static void connection_loop(Channel *c, uint8_t *buf, size_t buf_size)
{
	SshSession *s = c->s;

	for (;;) {
		size_t len = 0;
		int    rc = 0;

		if (ssh_recv_packet(s, buf, buf_size, &len) != 0 || len < 1) break;

		switch (buf[0]) {
		case SSH_MSG_GLOBAL_REQUEST: {
			/* keepalive@openssh.com, hostkeys-00@openssh.com, tcpip-forward... */
			size_t         off = 1;
			const uint8_t *name;
			size_t         name_len;
			uint8_t        want_reply = 0;
			if (buf_get_string(buf, len, &off, &name, &name_len) == 0 &&
				buf_get_byte(buf, len, &off, &want_reply) == 0 && want_reply) {
				uint8_t m = SSH_MSG_REQUEST_FAILURE;
				rc = ssh_send_packet(s, &m, 1);
			}
			break;
		}

		case SSH_MSG_CHANNEL_OPEN:
			rc = handle_channel_open(c, buf, len);
			break;

		case SSH_MSG_CHANNEL_REQUEST:
			rc = handle_channel_request(c, buf, len);
			break;

		case SSH_MSG_CHANNEL_DATA:
			rc = handle_channel_data(c, buf, len, 0);
			break;

		case SSH_MSG_CHANNEL_EXTENDED_DATA:
			rc = handle_channel_data(c, buf, len, 1);
			break;

		case SSH_MSG_CHANNEL_WINDOW_ADJUST:
			if (len >= 9) {
				uint32_t add = buf_get_u32(buf + 5);
				EnterCriticalSection(&s->send_lock);
				if ((uint64_t)c->remote_window + add > 0xFFFFFFFFULL)
					c->remote_window = 0xFFFFFFFFUL;
				else
					c->remote_window += add;
				LeaveCriticalSection(&s->send_lock);
				SetEvent(c->window_event);
			}
			break;

		case SSH_MSG_CHANNEL_EOF:
			shell_close_stdin(c);
			break;

		case SSH_MSG_CHANNEL_CLOSE:
			channel_send_close(c);
			LOGF(TRACE_LEVEL_VERBOSE, "[%u] channel closed", s->id);
			return;

		case SSH_MSG_CHANNEL_SUCCESS:
		case SSH_MSG_CHANNEL_FAILURE:
		case SSH_MSG_REQUEST_SUCCESS:
		case SSH_MSG_REQUEST_FAILURE:
		case SSH_MSG_USERAUTH_REQUEST:   /* must be ignored after success (RFC 4252 §5.1) */
		case SSH_MSG_UNIMPLEMENTED:
			break;

		case SSH_MSG_KEXINIT:
			LOGF(TRACE_LEVEL_WARNING, "[%u] client requested re-keying, which is not supported", s->id);
			ssh_send_disconnect(s, SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "re-keying not supported");
			return;

		default: {
			uint8_t pkt[5];
			pkt[0] = SSH_MSG_UNIMPLEMENTED;
			buf_put_u32(pkt + 1, s->dec.seq - 1);
			rc = ssh_send_packet(s, pkt, 5);
			break;
		}
		}

		if (rc != 0) {
			LOGF(TRACE_LEVEL_WARNING, "[%u] protocol error handling message %u", s->id, buf[0]);
			ssh_send_disconnect(s, SSH_DISCONNECT_PROTOCOL_ERROR, "protocol error");
			break;
		}
	}
}

/* ================================================================== session entry */

static void set_recv_timeout(SOCKET sock, DWORD ms)
{
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&ms, sizeof(ms));
}

void ssh_session_run(SshSession *s)
{
	uint8_t *buf = (uint8_t *)malloc(SSH_MAX_PACKET);
	Channel *c = (Channel *)calloc(1, sizeof(Channel));

	if (!buf || !c) {
		LOGF(TRACE_LEVEL_ERROR, "[%u] out of memory", s->id);
		free(buf);
		free(c);
		return;
	}

	c->s = s;
	c->window_event = CreateEventW(NULL, FALSE, FALSE, NULL);
	InitializeCriticalSectionEx(&c->echo_lock, 0, 0);

	/* Pre-authentication: every read must complete within the timeout */
	set_recv_timeout(s->sock, PREAUTH_TIMEOUT_MS);

	if (ssh_banner_exchange_server(s) != 0) goto done;
	if (ssh_kex_server(s, buf, SSH_MAX_PACKET) != 0) {
		ssh_send_disconnect(s, SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "key exchange failed");
		goto done;
	}
	if (ssh_auth_server(s, buf, SSH_MAX_PACKET) != 0) goto done;

	set_recv_timeout(s->sock, 0);   /* authenticated: no idle limit */

	connection_loop(c, buf, SSH_MAX_PACKET);

done:
	/* Stop the pump and the shell */
	InterlockedExchange(&s->closing, 1);
	if (c->window_event) SetEvent(c->window_event);

	if (c->hProcess && api.WaitForSingleObject(c->hProcess, 0) == WAIT_TIMEOUT) {
		LOGF(TRACE_LEVEL_INFORMATION, "[%u] terminating shell", s->id);
		api.TerminateProcess(c->hProcess, 1);
	}
	if (c->hJob) {
		CloseHandle(c->hJob);   /* JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: ends any remaining children */
		c->hJob = NULL;
	}
	if (c->hPump) {
		api.WaitForSingleObject(c->hPump, 5000);
		CloseHandle(c->hPump);
	}
	shell_close_stdin(c);
	if (c->hStdoutRd) CloseHandle(c->hStdoutRd);
	if (c->hProcess) CloseHandle(c->hProcess);
	if (c->window_event) CloseHandle(c->window_event);
	DeleteCriticalSection(&c->echo_lock);

	SecureZeroMemory(c, sizeof(*c));
	free(c);
	free(buf);
}
