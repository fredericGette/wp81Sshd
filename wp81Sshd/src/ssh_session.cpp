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
 * local echo, cursor movement (Left/Right/Home/End, Ctrl-A/Ctrl-E),
 * Backspace/Delete, Ctrl-U, Ctrl-C (discard line), Ctrl-D (EOF), command
 * history (Up/Down) and cmd.exe-style Tab / Shift-Tab file name completion.
 * cmd.exe echoes every line it reads from a pipe, so that echo is filtered
 * out of its output.  The current directory used for completion is taken
 * from the last prompt cmd printed ("C:\Data>").
 *
 * Instead of a shell, the channel can carry a file transfer (ssh_files.cpp):
 * the "sftp" subsystem, or an "scp -t/-f" exec request.  Its data is queued
 * by the session thread and consumed by a worker thread, which re-opens the
 * receive window only once the data is processed (so the queue never holds
 * more than LOCAL_WINDOW_SIZE bytes) and can block on the send window.
 */

#include "ssh_server.h"
#include "ssh_transport.h"
#include "ssh_kex_server.h"
#include "ssh_auth_server.h"
#include "ssh_files.h"
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
#define HIST_MAX             32
#define COMP_MAX             256           /* completion candidates kept */
#define COMP_ARENA           (16 * 1024)   /* bytes for their UTF-8 names */
#define OUT_LINE_MAX         (MAX_PATH + 8)
#define EXEC_CMD_MAX         2048
#define XFER_STACK_SIZE      (4 * 1024 * 1024)
#ifndef STACK_SIZE_PARAM_IS_A_RESERVATION
#define STACK_SIZE_PARAM_IS_A_RESERVATION 0x00010000
#endif

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
	size_t     cursor;               /* byte offset in line, on a UTF-8 boundary */
	int        last_was_cr;
	int        esc_state;            /* 0 none, 1 after ESC, 2 in CSI, 3 in SS3 */
	int        esc_param;            /* first numeric CSI parameter */
	int        esc_param_done;       /* a ';' was seen: ignore further digits */
	char       utf8_pend[4];         /* partial UTF-8 sequence being typed */
	int        utf8_have, utf8_need;

	/* history (hist[0] is the oldest) */
	char      *hist[HIST_MAX];
	int        hist_count;
	int        hist_pos;             /* == hist_count: editing a new line */
	char       hist_saved[LINE_MAX]; /* new line put aside while browsing */
	size_t     hist_saved_len;

	/* Tab completion (cycling through matches) */
	int        comp_active;
	int        comp_count, comp_index;
	int        comp_quote;           /* surround the replacement with quotes */
	size_t     comp_start, comp_end; /* replaced range in line (comp_end == cursor) */
	char       comp_dir[LINE_MAX];   /* directory part of the word, unquoted */
	char      *comp_names[COMP_MAX];
	char       comp_arena[COMP_ARENA];

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
	char       out_line[OUT_LINE_MAX]; /* last (partial) output line: the prompt */
	size_t     out_line_len;
	int        out_line_overflow;

	/* file transfer (sftp subsystem / scp exec) */
	int        xfer;                 /* 1 sftp, 2 scp; 0: shell or nothing yet */
	char      *xfer_cmd;             /* scp command line */
	HANDLE     hWorker;
	CRITICAL_SECTION q_lock;
	HANDLE     q_event;              /* auto-reset: data, EOF or closing */
	uint8_t   *q_buf;                /* ring buffer of LOCAL_WINDOW_SIZE bytes */
	size_t     q_head, q_len;
	int        q_eof;
	uint32_t   q_consumed;           /* bytes processed since last WINDOW_ADJUST (worker) */
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

static void channel_send_exit_status(Channel *c, uint32_t code)
{
	uint8_t pkt[64];
	size_t  off = 0;
	buf_put_byte(pkt, sizeof(pkt), &off, SSH_MSG_CHANNEL_REQUEST);
	buf_put_u32_at(pkt, sizeof(pkt), &off, c->remote_id);
	buf_put_cstring(pkt, sizeof(pkt), &off, "exit-status");
	buf_put_byte(pkt, sizeof(pkt), &off, 0);
	buf_put_u32_at(pkt, sizeof(pkt), &off, code);
	EnterCriticalSection(&c->s->send_lock);
	if (!c->close_sent) ssh_send_packet(c->s, pkt, off);
	LeaveCriticalSection(&c->s->send_lock);
}

/* ================================================================== file transfer */

/* Session thread: queue received data for the worker.  -1 if the client
 * overran the window it was given. */
static int xfer_queue_push(Channel *c, const uint8_t *data, size_t len)
{
	int rc = 0;
	EnterCriticalSection(&c->q_lock);
	if (c->q_len + len > LOCAL_WINDOW_SIZE) {
		rc = -1;
	} else {
		size_t tail = (c->q_head + c->q_len) % LOCAL_WINDOW_SIZE;
		size_t first = LOCAL_WINDOW_SIZE - tail;
		if (first > len) first = len;
		memcpy(c->q_buf + tail, data, first);
		memcpy(c->q_buf, data + first, len - first);
		c->q_len += len;
	}
	LeaveCriticalSection(&c->q_lock);
	SetEvent(c->q_event);
	return rc;
}

static void xfer_queue_eof(Channel *c)
{
	EnterCriticalSection(&c->q_lock);
	c->q_eof = 1;
	LeaveCriticalSection(&c->q_lock);
	SetEvent(c->q_event);
}

/* XferIO.recv (worker thread) */
static int xfer_recv(void *ctx, uint8_t *buf, size_t len)
{
	Channel *c = (Channel *)ctx;
	size_t   n, first;
	int      rc = 0;

	for (;;) {
		if (c->s->closing) return -1;
		EnterCriticalSection(&c->q_lock);
		if (c->q_len > 0) break;
		if (c->q_eof) {
			LeaveCriticalSection(&c->q_lock);
			return 0;
		}
		LeaveCriticalSection(&c->q_lock);
		api.WaitForSingleObject(c->q_event, 1000);
	}
	n = len < c->q_len ? len : c->q_len;
	first = LOCAL_WINDOW_SIZE - c->q_head;
	if (first > n) first = n;
	memcpy(buf, c->q_buf + c->q_head, first);
	memcpy(buf + first, c->q_buf, n - first);
	c->q_head = (c->q_head + n) % LOCAL_WINDOW_SIZE;
	c->q_len -= n;
	LeaveCriticalSection(&c->q_lock);

	/* Give the client room again once half of the window is processed */
	c->q_consumed += (uint32_t)n;
	if (c->q_consumed >= LOCAL_WINDOW_SIZE / 2) {
		uint8_t pkt[9];
		size_t  off = 0;
		buf_put_byte(pkt, sizeof(pkt), &off, SSH_MSG_CHANNEL_WINDOW_ADJUST);
		buf_put_u32_at(pkt, sizeof(pkt), &off, c->remote_id);
		buf_put_u32_at(pkt, sizeof(pkt), &off, c->q_consumed);
		c->q_consumed = 0;
		EnterCriticalSection(&c->s->send_lock);
		if (!c->close_sent) rc = ssh_send_packet(c->s, pkt, off);
		LeaveCriticalSection(&c->s->send_lock);
		if (rc != 0) return -1;
	}
	return (int)n;
}

/* XferIO.send (worker thread) */
static int xfer_send(void *ctx, const uint8_t *buf, size_t len)
{
	return channel_send_all((Channel *)ctx, buf, len);
}

static DWORD WINAPI xfer_thread(LPVOID param)
{
	Channel *c = (Channel *)param;
	XferIO   io;
	int      status;

	io.ctx = c;
	io.session_id = c->s->id;
	io.recv = xfer_recv;
	io.send = xfer_send;

	if (c->xfer == 1) status = sftp_server_run(&io, c->s->home_dir);
	else status = scp_server_run(&io, c->xfer_cmd, c->s->home_dir);

	if (c->s->closing) return 0;
	channel_send_exit_status(c, (uint32_t)status);
	channel_send_close(c);
	return 0;
}

/* Allocate the input queue; from now on channel data goes to it. */
static int xfer_prepare(Channel *c, int kind, const char *cmd)
{
	if (!c->q_buf) c->q_buf = (uint8_t *)malloc(LOCAL_WINDOW_SIZE);
	if (!c->q_event) c->q_event = CreateEventW(NULL, FALSE, FALSE, NULL);
	if (cmd && !c->xfer_cmd) c->xfer_cmd = _strdup(cmd);
	if (!c->q_buf || !c->q_event || (cmd && !c->xfer_cmd)) return -1;
	c->xfer = kind;
	return 0;
}

/* Start the worker (after the request was answered).  The stack is a large
 * reservation because "scp -r" recurses once per directory level. */
static int xfer_launch(Channel *c)
{
	c->hWorker = CreateThread(NULL, XFER_STACK_SIZE, xfer_thread, c, STACK_SIZE_PARAM_IS_A_RESERVATION, NULL);
	if (!c->hWorker) {
		LOGF(TRACE_LEVEL_ERROR, "[%u] CreateThread (transfer) failed: %lu", c->s->id, GetLastError());
		return -1;
	}
	return 0;
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

/* Remember the last output line (normally cmd's prompt).  Caller holds echo_lock. */
static void track_out_line(Channel *c, const char *data, size_t len)
{
	size_t i;
	for (i = 0; i < len; i++) {
		char ch = data[i];
		if (ch == '\r' || ch == '\n') {
			c->out_line_len = 0;
			c->out_line_overflow = 0;
		} else if (c->out_line_len < OUT_LINE_MAX - 1) {
			c->out_line[c->out_line_len++] = ch;
		} else {
			c->out_line_overflow = 1;
		}
	}
}

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
	track_out_line(c, out, n);
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
		track_out_line(c, held, n);
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
	if (exited) channel_send_exit_status(c, exit_code);
	channel_send_close(c);
	return 0;
}

/* ================================================================== input (line discipline) */

/*
 * Terminal model: the client's cursor sits at column cols(0, cursor) after
 * the prompt.  Columns are counted as one per code point (UTF-8 lead byte).
 * Lines longer than the terminal width are not handled specially.
 */

static size_t line_cols(Channel *c, size_t from, size_t to)
{
	size_t n = 0;
	for (; from < to; from++)
		if (((unsigned char)c->line[from] & 0xC0) != 0x80) n++;
	return n;
}

static size_t line_prev(Channel *c, size_t pos)
{
	if (pos == 0) return 0;
	do {
		pos--;
	} while (pos > 0 && ((unsigned char)c->line[pos] & 0xC0) == 0x80);
	return pos;
}

static size_t line_next(Channel *c, size_t pos)
{
	if (pos >= c->line_len) return c->line_len;
	do {
		pos++;
	} while (pos < c->line_len && ((unsigned char)c->line[pos] & 0xC0) == 0x80);
	return pos;
}

static void bell(Channel *c)
{
	channel_echo(c, "\a", 1);
}

/* Move the terminal cursor n columns (negative: left). */
static void term_move(Channel *c, int n)
{
	char seq[16];
	int  len;
	if (n == 0) return;
	len = _snprintf_s(seq, sizeof(seq), _TRUNCATE, "\x1b[%d%c", n < 0 ? -n : n, n < 0 ? 'D' : 'C');
	if (len > 0) channel_echo(c, seq, (size_t)len);
}

/*
 * Redraw line[from..] after a change.  The terminal cursor must be at the
 * column of `from`; old_cols is the width the text from `from` had before the
 * change, so leftovers get blanked.  Leaves the terminal cursor at c->cursor
 * (which must be >= from).
 */
static void refresh_tail(Channel *c, size_t from, size_t old_cols)
{
	static const char spaces[] = "                                ";
	size_t new_cols = line_cols(c, from, c->line_len);
	size_t pad = old_cols > new_cols ? old_cols - new_cols : 0;
	size_t p;

	channel_echo(c, c->line + from, c->line_len - from);
	for (p = pad; p > 0; ) {
		size_t k = p < sizeof(spaces) - 1 ? p : sizeof(spaces) - 1;
		channel_echo(c, spaces, k);
		p -= k;
	}
	term_move(c, -(int)(pad + line_cols(c, c->cursor, c->line_len)));
}

/* Replace the whole line (history recall), cursor at the end. */
static void line_set(Channel *c, const char *text, size_t len)
{
	size_t old_cols;
	if (len > LINE_MAX - 2) len = LINE_MAX - 2;
	term_move(c, -(int)line_cols(c, 0, c->cursor));
	old_cols = line_cols(c, 0, c->line_len);
	memcpy(c->line, text, len);
	c->line_len = len;
	c->cursor = len;
	refresh_tail(c, 0, old_cols);
}

static void line_insert(Channel *c, const char *s, size_t n)
{
	size_t from = c->cursor;
	size_t old_cols = line_cols(c, from, c->line_len);

	if (c->line_len + n > LINE_MAX - 2) {
		bell(c);
		return;
	}
	memmove(c->line + from + n, c->line + from, c->line_len - from);
	memcpy(c->line + from, s, n);
	c->line_len += n;
	c->cursor += n;
	refresh_tail(c, from, old_cols);
}

static void delete_before_cursor(Channel *c)
{
	size_t prev, old_cols;
	if (c->cursor == 0) return;
	prev = line_prev(c, c->cursor);
	old_cols = line_cols(c, prev, c->line_len);
	term_move(c, -(int)line_cols(c, prev, c->cursor));
	memmove(c->line + prev, c->line + c->cursor, c->line_len - c->cursor);
	c->line_len -= c->cursor - prev;
	c->cursor = prev;
	refresh_tail(c, prev, old_cols);
}

static void delete_at_cursor(Channel *c)
{
	size_t next, old_cols;
	if (c->cursor >= c->line_len) return;
	next = line_next(c, c->cursor);
	old_cols = line_cols(c, c->cursor, c->line_len);
	memmove(c->line + c->cursor, c->line + next, c->line_len - next);
	c->line_len -= next - c->cursor;
	refresh_tail(c, c->cursor, old_cols);
}

static void cursor_left(Channel *c)
{
	size_t prev = line_prev(c, c->cursor);
	term_move(c, -(int)line_cols(c, prev, c->cursor));
	c->cursor = prev;
}

static void cursor_right(Channel *c)
{
	size_t next = line_next(c, c->cursor);
	term_move(c, (int)line_cols(c, c->cursor, next));
	c->cursor = next;
}

static void cursor_home(Channel *c)
{
	term_move(c, -(int)line_cols(c, 0, c->cursor));
	c->cursor = 0;
}

static void cursor_end(Channel *c)
{
	term_move(c, (int)line_cols(c, c->cursor, c->line_len));
	c->cursor = c->line_len;
}

/* ------------------------------------------------------------------ history */

static void history_add(Channel *c)
{
	char *entry;

	if (c->line_len == 0) return;
	if (c->hist_count > 0) {
		const char *last = c->hist[c->hist_count - 1];
		if (strlen(last) == c->line_len && memcmp(last, c->line, c->line_len) == 0)
			return;
	}
	entry = (char *)malloc(c->line_len + 1);
	if (!entry) return;
	memcpy(entry, c->line, c->line_len);
	entry[c->line_len] = '\0';

	if (c->hist_count == HIST_MAX) {
		free(c->hist[0]);
		memmove(c->hist, c->hist + 1, (HIST_MAX - 1) * sizeof(c->hist[0]));
		c->hist_count--;
	}
	c->hist[c->hist_count++] = entry;
}

static void history_up(Channel *c)
{
	if (c->hist_pos == 0) {
		bell(c);
		return;
	}
	if (c->hist_pos == c->hist_count) {
		memcpy(c->hist_saved, c->line, c->line_len);
		c->hist_saved_len = c->line_len;
	}
	c->hist_pos--;
	line_set(c, c->hist[c->hist_pos], strlen(c->hist[c->hist_pos]));
}

static void history_down(Channel *c)
{
	if (c->hist_pos >= c->hist_count) {
		bell(c);
		return;
	}
	c->hist_pos++;
	if (c->hist_pos == c->hist_count)
		line_set(c, c->hist_saved, c->hist_saved_len);
	else
		line_set(c, c->hist[c->hist_pos], strlen(c->hist[c->hist_pos]));
}

static void history_free(Channel *c)
{
	int i;
	for (i = 0; i < c->hist_count; i++) {
		SecureZeroMemory(c->hist[i], strlen(c->hist[i]));
		free(c->hist[i]);
		c->hist[i] = NULL;
	}
	c->hist_count = 0;
}

/* ------------------------------------------------------------------ Tab completion */

/* Characters that force cmd.exe to need quotes around a file name. */
static int needs_quotes(const char *s)
{
	return strpbrk(s, " &()[]{}^=;!'+,`~") != NULL;
}

static int __cdecl comp_cmp(const void *a, const void *b)
{
	return _stricmp(*(char * const *)a, *(char * const *)b);
}

/* Current directory from the last prompt ("C:\Data\Users>"), or 0. */
static int prompt_cwd(Channel *c, char *out, size_t out_size)
{
	size_t n;
	int    ok = 0;

	EnterCriticalSection(&c->echo_lock);
	n = c->out_line_len;
	if (!c->out_line_overflow && n >= 4 && n - 1 < out_size &&
		((c->out_line[0] | 0x20) >= 'a' && (c->out_line[0] | 0x20) <= 'z') &&
		c->out_line[1] == ':' && c->out_line[2] == '\\' && c->out_line[n - 1] == '>') {
		memcpy(out, c->out_line, n - 1);
		out[n - 1] = '\0';
		ok = 1;
	}
	LeaveCriticalSection(&c->echo_lock);
	return ok;
}

/*
 * Find the word before the cursor and collect the matching file names.
 * Returns the number of matches.
 */
static int comp_begin(Channel *c)
{
	char     word[LINE_MAX];
	char     cwd[OUT_LINE_MAX];
	char     pattern[LINE_MAX + OUT_LINE_MAX + 4];
	wchar_t  wpattern[LINE_MAX + OUT_LINE_MAX + 4];
	wchar_t  wprefix[LINE_MAX];
	const char *prefix;
	size_t   i, start = 0, wn = 0, dir_len = 0, prefix_wlen, arena_used = 0;
	int      in_quote = 0, quoted = 0, have_cwd;
	HANDLE   hFind;
	WIN32_FIND_DATAW fd;

	/* Word start: after the last space outside quotes */
	for (i = 0; i < c->cursor; i++) {
		if (c->line[i] == '"') in_quote = !in_quote;
		else if (c->line[i] == ' ' && !in_quote) start = i + 1;
	}
	/* Unquoted copy of the word */
	for (i = start; i < c->cursor; i++) {
		if (c->line[i] == '"') quoted = 1;
		else word[wn++] = c->line[i];
	}
	word[wn] = '\0';

	/* Split into directory part and name prefix */
	for (i = 0; i < wn; i++)
		if (word[i] == '\\' || word[i] == '/' || word[i] == ':') dir_len = i + 1;
	memcpy(c->comp_dir, word, dir_len);
	c->comp_dir[dir_len] = '\0';
	prefix = word + dir_len;

	/* Base directory for relative words */
	have_cwd = prompt_cwd(c, cwd, sizeof(cwd));
	if (wn >= 2 && word[1] == ':') {
		pattern[0] = '\0';                          /* C:\... absolute */
	} else if (wn >= 2 && word[0] == '\\' && word[1] == '\\') {
		pattern[0] = '\0';                          /* \\server\share */
	} else if (!have_cwd) {
		return 0;
	} else if (wn >= 1 && (word[0] == '\\' || word[0] == '/')) {
		_snprintf_s(pattern, sizeof(pattern), _TRUNCATE, "%.2s", cwd);   /* root of the drive */
	} else {
		size_t cl = strlen(cwd);
		_snprintf_s(pattern, sizeof(pattern), _TRUNCATE, "%s%s", cwd,
			(cl > 0 && cwd[cl - 1] == '\\') ? "" : "\\");
	}
	strncat_s(pattern, sizeof(pattern), word, _TRUNCATE);
	strncat_s(pattern, sizeof(pattern), "*", _TRUNCATE);

	if (MultiByteToWideChar(CP_UTF8, 0, pattern, -1, wpattern, _countof(wpattern)) == 0)
		return 0;
	if (MultiByteToWideChar(CP_UTF8, 0, prefix, -1, wprefix, _countof(wprefix)) == 0)
		return 0;
	prefix_wlen = wcslen(wprefix);

	c->comp_count = 0;
	hFind = FindFirstFileExW(wpattern, FindExInfoBasic, &fd, FindExSearchNameMatch, NULL, 0);
	if (hFind == INVALID_HANDLE_VALUE) return 0;
	do {
		char name[MAX_PATH * 3 + 1];
		int  nl;
		if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
		/* "x*" also matches 8.3 short names: keep long names with the prefix only */
		if (_wcsnicmp(fd.cFileName, wprefix, prefix_wlen) != 0) continue;
		nl = WideCharToMultiByte(CP_UTF8, 0, fd.cFileName, -1, name, sizeof(name), NULL, NULL);
		if (nl <= 0 || arena_used + (size_t)nl > COMP_ARENA) continue;
		memcpy(c->comp_arena + arena_used, name, (size_t)nl);
		c->comp_names[c->comp_count++] = c->comp_arena + arena_used;
		arena_used += (size_t)nl;
	} while (c->comp_count < COMP_MAX && FindNextFileW(hFind, &fd));
	FindClose(hFind);

	qsort(c->comp_names, (size_t)c->comp_count, sizeof(c->comp_names[0]), comp_cmp);
	c->comp_quote = quoted;
	c->comp_start = start;
	c->comp_end = c->cursor;
	return c->comp_count;
}

/* Replace the word with the current match. */
static void comp_apply(Channel *c)
{
	char   text[LINE_MAX + MAX_PATH * 3 + 4];
	size_t tn, tail, old_cols;
	int    quote;

	_snprintf_s(text, sizeof(text), _TRUNCATE, "%s%s", c->comp_dir, c->comp_names[c->comp_index]);
	quote = c->comp_quote || needs_quotes(text);
	_snprintf_s(text, sizeof(text), _TRUNCATE, "%s%s%s%s", quote ? "\"" : "",
		c->comp_dir, c->comp_names[c->comp_index], quote ? "\"" : "");
	tn = strlen(text);

	tail = c->line_len - c->comp_end;
	if (c->comp_start + tn + tail > LINE_MAX - 2) {
		bell(c);
		return;
	}
	term_move(c, -(int)line_cols(c, c->comp_start, c->cursor));
	old_cols = line_cols(c, c->comp_start, c->line_len);
	memmove(c->line + c->comp_start + tn, c->line + c->comp_end, tail);
	memcpy(c->line + c->comp_start, text, tn);
	c->line_len = c->comp_start + tn + tail;
	c->comp_end = c->comp_start + tn;
	c->cursor = c->comp_end;
	refresh_tail(c, c->comp_start, old_cols);
}

/* Tab (dir = +1) / Shift-Tab (dir = -1) */
static void complete(Channel *c, int dir)
{
	if (!c->comp_active) {
		if (comp_begin(c) == 0) {
			bell(c);
			return;
		}
		c->comp_active = 1;
		c->comp_index = dir > 0 ? 0 : c->comp_count - 1;
	} else {
		c->comp_index = (c->comp_index + dir + c->comp_count) % c->comp_count;
	}
	comp_apply(c);
}

/* ------------------------------------------------------------------ submit */

/* Queue the expected echo of a submitted line, then send it to the shell. */
static void submit_line(Channel *c)
{
	history_add(c);
	c->hist_pos = c->hist_count;

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
	c->cursor = 0;
}

/* ------------------------------------------------------------------ keys */

/* Final byte of "ESC [ <param> <final>" or "ESC O <final>". */
static void handle_escape(Channel *c, unsigned char final, int param)
{
	if (final != 'Z') c->comp_active = 0;

	switch (final) {
	case 'A': history_up(c);     break;
	case 'B': history_down(c);   break;
	case 'C': cursor_right(c);   break;
	case 'D': cursor_left(c);    break;
	case 'H': cursor_home(c);    break;
	case 'F': cursor_end(c);     break;
	case 'Z': complete(c, -1);   break;   /* Shift-Tab */
	case '~':
		switch (param) {
		case 1: case 7: cursor_home(c);      break;
		case 4: case 8: cursor_end(c);       break;
		case 3:         delete_at_cursor(c); break;
		}
		break;
	}
}

/* Printable byte: complete UTF-8 sequences before inserting them. */
static void handle_printable(Channel *c, unsigned char ch)
{
	if (ch < 0x80) {
		c->utf8_need = 0;
		line_insert(c, (const char *)&ch, 1);
		return;
	}
	if ((ch & 0xC0) == 0x80) {                 /* continuation byte */
		if (c->utf8_need == 0) return;
		c->utf8_pend[c->utf8_have++] = (char)ch;
		if (c->utf8_have == c->utf8_need) {
			c->utf8_need = 0;
			line_insert(c, c->utf8_pend, (size_t)c->utf8_have);
		}
		return;
	}
	if (ch >= 0xF8) {                          /* invalid lead byte */
		c->utf8_need = 0;
		return;
	}
	c->utf8_pend[0] = (char)ch;
	c->utf8_have = 1;
	c->utf8_need = ch >= 0xF0 ? 4 : ch >= 0xE0 ? 3 : 2;
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

		/* Terminal escape sequences (arrows, Home/End, Delete, Shift-Tab...) */
		if (c->esc_state == 1) {
			c->esc_param = 0;
			c->esc_param_done = 0;
			c->esc_state = (ch == '[') ? 2 : (ch == 'O') ? 3 : 0;
			continue;
		}
		if (c->esc_state == 2) {
			if (ch >= '0' && ch <= '9') {
				if (!c->esc_param_done && c->esc_param < 1000)
					c->esc_param = c->esc_param * 10 + (ch - '0');
			} else if (ch == ';') {
				c->esc_param_done = 1;
			} else if (ch >= 0x40 && ch <= 0x7e) {
				c->esc_state = 0;
				handle_escape(c, ch, c->esc_param);
			}
			continue;
		}
		if (c->esc_state == 3) {
			c->esc_state = 0;
			handle_escape(c, ch, 0);
			continue;
		}

		if (ch != '\t' && ch != 0x1b) c->comp_active = 0;
		if (ch < 0x80) c->utf8_need = 0;

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
			delete_before_cursor(c);
			break;
		case 0x01:                  /* Ctrl-A: start of line */
			cursor_home(c);
			break;
		case 0x05:                  /* Ctrl-E: end of line */
			cursor_end(c);
			break;
		case 0x15:                  /* Ctrl-U: erase line */
			line_set(c, "", 0);
			break;
		case '\t':
			complete(c, +1);
			break;
		case 0x03:                  /* Ctrl-C: discard line, ask for a new prompt */
			cursor_end(c);
			c->line_len = 0;
			c->cursor = 0;
			channel_echo(c, "^C", 2);
			submit_line(c);
			break;
		case 0x04:                  /* Ctrl-D on empty line: EOF */
			if (c->line_len == 0) {
				shell_close_stdin(c);
			}
			break;
		default:
			if (ch < 0x20) break;   /* other control characters: ignore */
			handle_printable(c, ch);
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

	if (buf_eq(type, type_len, "subsystem") || buf_eq(type, type_len, "exec")) {
		const uint8_t *arg;
		size_t         arg_len;
		char           cmd[EXEC_CMD_MAX];
		int            ok = 0, is_exec = buf_eq(type, type_len, "exec");

		if (buf_get_string(buf, len, &off, &arg, &arg_len) != 0) return -1;
		if (arg_len >= sizeof(cmd) || memchr(arg, 0, arg_len)) arg_len = 0;
		memcpy(cmd, arg, arg_len);
		cmd[arg_len] = '\0';

		if (!c->shell_started && !c->xfer) {
			if (!is_exec && strcmp(cmd, "sftp") == 0)
				ok = xfer_prepare(c, 1, NULL) == 0;
			else if (is_exec && scp_is_command(cmd))
				ok = xfer_prepare(c, 2, cmd) == 0;
			if (!ok) c->xfer = 0;
		}
		if (!ok)
			LOGF(TRACE_LEVEL_INFORMATION, "[%u] declined %s '%s'", c->s->id, is_exec ? "exec" : "subsystem", cmd);
		if (want_reply && send_request_reply(c, ok) != 0) return -1;
		if (ok && xfer_launch(c) != 0) {
			channel_send_close(c);
			return 0;
		}
		return 0;
	}

	if (buf_eq(type, type_len, "shell")) {
		int ok = !c->shell_started && !c->xfer && shell_spawn(c) == 0;
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

	if (c->xfer) {
		/* The worker re-opens the window as it consumes the data */
		if (extended) return 0;
		if (xfer_queue_push(c, data, data_len) != 0) {
			LOGF(TRACE_LEVEL_WARNING, "[%u] client exceeded the channel window", c->s->id);
			return -1;
		}
		return 0;
	}

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
			if (c->xfer) xfer_queue_eof(c);
			else shell_close_stdin(c);
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
	InitializeCriticalSectionEx(&c->q_lock, 0, 0);

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
	if (c->q_event) SetEvent(c->q_event);

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
	if (c->hWorker) {
		if (api.WaitForSingleObject(c->hWorker, 10000) == WAIT_TIMEOUT) {
			/* Still inside a file operation and using c: leave c allocated */
			LOGF(TRACE_LEVEL_ERROR, "[%u] transfer thread does not stop; leaking its state", s->id);
			CloseHandle(c->hWorker);
			free(buf);
			return;
		}
		CloseHandle(c->hWorker);
	}
	if (c->q_event) CloseHandle(c->q_event);
	free(c->q_buf);
	free(c->xfer_cmd);
	DeleteCriticalSection(&c->q_lock);
	shell_close_stdin(c);
	if (c->hStdoutRd) CloseHandle(c->hStdoutRd);
	if (c->hProcess) CloseHandle(c->hProcess);
	if (c->window_event) CloseHandle(c->window_event);
	DeleteCriticalSection(&c->echo_lock);
	history_free(c);

	SecureZeroMemory(c, sizeof(*c));
	free(c);
	free(buf);
}
