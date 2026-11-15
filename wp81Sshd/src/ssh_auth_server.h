#pragma once

/*
 * ssh_auth_server.h  -  SSH-2 user authentication, server side (RFC 4252)
 *
 * Service "ssh-userauth", method "publickey" with ssh-ed25519 keys listed
 * in an OpenSSH-format authorized_keys file.  Nothing else is accepted.
 */

#include "ssh_server.h"

/* buf: scratch buffer of SSH_MAX_PACKET bytes.
 * Returns 0 once USERAUTH_SUCCESS has been sent (s->user is set),
 * -1 on failure (caller disconnects). */
int ssh_auth_server(SshSession *s, uint8_t *buf, size_t buf_size);

/* Is this raw 32-byte Ed25519 key listed in the authorized_keys file?
 * The file is re-read on every call. */
int ssh_key_is_authorized(const wchar_t *path, const uint8_t pub[32], unsigned session_id);
