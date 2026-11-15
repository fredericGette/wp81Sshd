#pragma once

/*
 * ssh_kex_server.h  -  SSH-2 key exchange, server side
 *                      (RFC 4253 §7, RFC 8731 curve25519-sha256, RFC 8709 ssh-ed25519)
 *
 * After ssh_kex_server() returns 0:
 *   s->enc is active for server->client, s->dec for client->server,
 *   s->session_id holds H of the (first and only) key exchange.
 */

#include "ssh_server.h"

/* buf: scratch buffer of SSH_MAX_PACKET bytes.  Returns 0 on success. */
int ssh_kex_server(SshSession *s, uint8_t *buf, size_t buf_size);
