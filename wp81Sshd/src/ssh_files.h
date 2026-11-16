#pragma once

/*
 * ssh_files.h  -  File transfer over a session channel:
 *   - the "sftp" subsystem (SFTP version 3), used by OpenSSH scp >= 9.0
 *     by default, and by sftp;
 *   - the legacy SCP protocol ("scp -t" / "scp -f" exec requests), used by
 *     "scp -O" and older clients.
 *
 * Both run on a worker thread and talk to the client through an XferIO.
 *
 * Remote paths may be written "C:/Data/x", "/C:/Data/x", "C:\Data\x",
 * "/Data/x" (drive of the home directory) or relative to the home directory.
 */

#include "Win32Api.h"
#include <stdint.h>
#include <stddef.h>

typedef struct XferIO {
	void    *ctx;
	unsigned session_id;   /* for log lines */

	/* Read up to len bytes, blocking until at least one is available.
	 * Returns the byte count, 0 at end of input, -1 if the session ends. */
	int (*recv)(void *ctx, uint8_t *buf, size_t len);

	/* Send all bytes.  0 on success, -1 if the session ends. */
	int (*send)(void *ctx, const uint8_t *buf, size_t len);
} XferIO;

/* Serve SFTP requests until the client closes its side.  Returns the exit status. */
int sftp_server_run(XferIO *io, const wchar_t *home);

/* 1 if an exec command line is a legacy scp server invocation. */
int scp_is_command(const char *command);

/* Run "scp [-r] [-d] [-p] [-v] -t|-f path".  Returns the exit status. */
int scp_server_run(XferIO *io, const char *command, const wchar_t *home);
