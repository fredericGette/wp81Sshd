#pragma once

/*
 * ssh_transport.h  -  SSH-2 binary packet protocol (RFC 4253 §6), server side.
 *
 * Derived from wp81ssh/src/ssh_transport.h.
 *
 * Cipher   : AES-256-CTR
 * MAC      : HMAC-SHA-256 (mac-then-encrypt, seq prepended)
 * Block sz : 16 bytes  ->  minimum padding 4, aligned to 16
 *
 * The socket is blocking.  ssh_send_packet may be called from several
 * threads (it takes s->send_lock); ssh_recv_packet from one thread only.
 */

#include "ssh_server.h"

/* Send our banner, read the client's (skipping pre-banner lines).
 * Returns 0 on success, -1 on error. */
int  ssh_banner_exchange_server(SshSession *s);

/* Send one packet; encrypts + MACs if s->enc_active.  Thread-safe. */
int  ssh_send_packet(SshSession *s, const uint8_t *payload, size_t payload_len);

/* Receive one packet; decrypts + verifies MAC if s->dec_active.
 * Skips IGNORE / DEBUG (outside strict initial KEX); a DISCONNECT from
 * the peer is logged and returned as an error.
 * buf must hold SSH_MAX_PACKET bytes.  Returns 0 on success, -1 on error. */
int  ssh_recv_packet(SshSession *s, uint8_t *buf, size_t buf_size, size_t *out_len);

/* Send SSH_MSG_DISCONNECT (best effort; does not close the socket). */
void ssh_send_disconnect(SshSession *s, uint32_t reason_code, const char *reason);

/* Cryptographically secure random bytes (CryptGenRandom). 0 on success. */
int  ssh_random(uint8_t *buf, size_t len);

/* ---- Buffer helpers ------------------------------------------------------ */
void     buf_put_u32(uint8_t *b, uint32_t v);
uint32_t buf_get_u32(const uint8_t *b);

/* Append uint32 length + data at *off.  0 on success, -1 if b too small. */
int buf_put_string(uint8_t *b, size_t b_size, size_t *off,
                   const uint8_t *data, size_t data_len);
int buf_put_cstring(uint8_t *b, size_t b_size, size_t *off, const char *str);
int buf_put_u32_at(uint8_t *b, size_t b_size, size_t *off, uint32_t v);
int buf_put_byte(uint8_t *b, size_t b_size, size_t *off, uint8_t v);

/* Parse helpers: 0 on success, -1 on malformed input.  Advance *off. */
int buf_get_string(const uint8_t *b, size_t b_size, size_t *off,
                   const uint8_t **out_ptr, size_t *out_len);
int buf_get_u32_at(const uint8_t *b, size_t b_size, size_t *off, uint32_t *out);
int buf_get_byte(const uint8_t *b, size_t b_size, size_t *off, uint8_t *out);

/* Compare a length-delimited SSH string with a C string. */
int buf_eq(const uint8_t *p, size_t len, const char *str);
