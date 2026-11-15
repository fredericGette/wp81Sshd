/*
 * ssh_kex_server.cpp  -  SSH-2 key exchange, server side.
 *
 * curve25519-sha256 + ssh-ed25519 + SHA-256 KDF.
 * Derived from wp81ssh/src/ssh_kex.cpp (client side): same mpint encoding,
 * KDF and name-list matching; roles and key directions swapped, and the
 * exchange hash is signed with the host key instead of verified.
 *
 * Also implements OpenSSH "strict KEX" (kex-strict-s-v00@openssh.com):
 * sequence numbers are reset after NEWKEYS and no other message is
 * accepted during the initial exchange.
 */

#include "ssh_kex_server.h"
#include "ssh_transport.h"
#include "log.h"
#include "crypto/sha256.h"
#include "crypto/curve25519.h"
#include "crypto/ed25519.h"
#include "crypto/aes256.h"

#include <string.h>
#include <stdlib.h>

#define COOKIE_LEN       16
#define KEX_PAYLOAD_MAX  1024

/* What we advertise */
static const char OFFER_KEX[]      = "curve25519-sha256,curve25519-sha256@libssh.org,kex-strict-s-v00@openssh.com";
static const char OFFER_HOSTKEY[]  = "ssh-ed25519";
static const char OFFER_CIPHER[]   = "aes256-ctr";
static const char OFFER_MAC[]      = "hmac-sha2-256";
static const char OFFER_COMPRESS[] = "none";

static const char STRICT_KEX_CLIENT[] = "kex-strict-c-v00@openssh.com";

/* ---- helpers ------------------------------------------------------------- */

/* Is `name` an element of the comma-separated name-list (p, len)? */
static int namelist_has(const uint8_t *p, size_t len, const char *name)
{
	size_t nlen = strlen(name);
	while (len > 0) {
		const uint8_t *comma = (const uint8_t *)memchr(p, ',', len);
		size_t         tok = comma ? (size_t)(comma - p) : len;
		if (tok == nlen && memcmp(p, name, nlen) == 0) return 1;
		if (!comma) break;
		p = comma + 1;
		len -= tok + 1;
	}
	return 0;
}

/* Is the first element of the name-list equal to one of our names (a or b)? */
static int namelist_first_is(const uint8_t *p, size_t len, const char *a, const char *b)
{
	const uint8_t *comma = (const uint8_t *)memchr(p, ',', len);
	size_t         tok = comma ? (size_t)(comma - p) : len;
	return buf_eq(p, tok, a) || (b && buf_eq(p, tok, b));
}

/*
 * Encode the 32-byte X25519 shared secret as an SSH mpint (RFC 8731 §3.1:
 * the octets are interpreted as an unsigned big-endian integer).
 * Returns total bytes written (4 + 0or1 + up to 32 = max 37).
 */
static size_t encode_mpint(const uint8_t k32[32], uint8_t mpint_buf[37])
{
	int    start = 0;
	int    needs_pad;
	size_t data_len, off;

	while (start < 32 && k32[start] == 0) start++;
	if (start == 32) {
		buf_put_u32(mpint_buf, 0);
		return 4;
	}

	needs_pad = (k32[start] & 0x80) ? 1 : 0;
	data_len = (size_t)(32 - start) + (size_t)needs_pad;
	buf_put_u32(mpint_buf, (uint32_t)data_len);
	off = 4;
	if (needs_pad) mpint_buf[off++] = 0x00;
	memcpy(mpint_buf + off, k32 + start, (size_t)(32 - start));
	off += (size_t)(32 - start);
	return off;
}

/* Derive one block of key material (RFC 4253 §7.2). need <= 64. */
static void derive_key(const uint8_t *k_mpint, size_t k_mpint_len,
	const uint8_t H[32], char X, const uint8_t session_id[32],
	uint8_t *out, size_t need)
{
	Sha256Ctx ctx;
	uint8_t   block[32];
	size_t    have, copy;

	sha256_init(&ctx);
	sha256_update(&ctx, k_mpint, k_mpint_len);
	sha256_update(&ctx, H, 32);
	sha256_update(&ctx, (const uint8_t *)&X, 1);
	sha256_update(&ctx, session_id, 32);
	sha256_final(&ctx, block);

	have = need < 32 ? need : 32;
	memcpy(out, block, have);

	while (have < need) {
		sha256_init(&ctx);
		sha256_update(&ctx, k_mpint, k_mpint_len);
		sha256_update(&ctx, H, 32);
		sha256_update(&ctx, out, have);
		sha256_final(&ctx, block);
		copy = (need - have < 32) ? (need - have) : 32;
		memcpy(out + have, block, copy);
		have += copy;
	}
	memset(block, 0, sizeof(block));
}

static void hash_string(Sha256Ctx *ctx, const uint8_t *data, size_t len)
{
	uint8_t tmp4[4];
	buf_put_u32(tmp4, (uint32_t)len);
	sha256_update(ctx, tmp4, 4);
	sha256_update(ctx, data, len);
}

/* ---- Step 1: send our KEXINIT -------------------------------------------- */

static int send_kexinit(SshSession *s)
{
	uint8_t pkt[KEX_PAYLOAD_MAX];
	size_t  off = 0;
	int     rc = 0;

	pkt[off++] = SSH_MSG_KEXINIT;
	if (ssh_random(pkt + off, COOKIE_LEN) != 0) return -1;
	off += COOKIE_LEN;

	rc |= buf_put_cstring(pkt, sizeof(pkt), &off, OFFER_KEX);
	rc |= buf_put_cstring(pkt, sizeof(pkt), &off, OFFER_HOSTKEY);
	rc |= buf_put_cstring(pkt, sizeof(pkt), &off, OFFER_CIPHER);
	rc |= buf_put_cstring(pkt, sizeof(pkt), &off, OFFER_CIPHER);
	rc |= buf_put_cstring(pkt, sizeof(pkt), &off, OFFER_MAC);
	rc |= buf_put_cstring(pkt, sizeof(pkt), &off, OFFER_MAC);
	rc |= buf_put_cstring(pkt, sizeof(pkt), &off, OFFER_COMPRESS);
	rc |= buf_put_cstring(pkt, sizeof(pkt), &off, OFFER_COMPRESS);
	rc |= buf_put_cstring(pkt, sizeof(pkt), &off, "");   /* languages c->s */
	rc |= buf_put_cstring(pkt, sizeof(pkt), &off, "");   /* languages s->c */
	rc |= buf_put_byte(pkt, sizeof(pkt), &off, 0);       /* first_kex_packet_follows */
	rc |= buf_put_u32_at(pkt, sizeof(pkt), &off, 0);     /* reserved */
	if (rc) return -1;

	s->own_kexinit = (uint8_t *)malloc(off);
	if (!s->own_kexinit) return -1;
	memcpy(s->own_kexinit, pkt, off);
	s->own_kexinit_len = off;

	return ssh_send_packet(s, pkt, off);
}

/* ---- Step 2: receive + validate the client's KEXINIT --------------------- */

/* Returns 0 on success; *skip_guess set if a wrongly guessed KEX packet follows. */
static int recv_kexinit(SshSession *s, uint8_t *buf, size_t buf_size, int *skip_guess)
{
	/* Field index -> one algorithm we require in the client's list */
	static const char *const required[8] = {
		NULL /* kex: special-cased */, "ssh-ed25519",
		"aes256-ctr", "aes256-ctr",
		"hmac-sha2-256", "hmac-sha2-256",
		"none", "none"
	};
	size_t         len = 0, off;
	const uint8_t *lists[10];
	size_t         list_len[10];
	uint8_t        follows = 0;
	int            i;

	if (ssh_recv_packet(s, buf, buf_size, &len) != 0) return -1;
	if (len < 1 || buf[0] != SSH_MSG_KEXINIT) {
		LOGF(TRACE_LEVEL_WARNING, "[%u] expected KEXINIT, got %u", s->id, len ? buf[0] : 0);
		return -1;
	}

	s->peer_kexinit = (uint8_t *)malloc(len);
	if (!s->peer_kexinit) return -1;
	memcpy(s->peer_kexinit, buf, len);
	s->peer_kexinit_len = len;

	off = 1 + COOKIE_LEN;
	for (i = 0; i < 10; i++)
		if (buf_get_string(buf, len, &off, &lists[i], &list_len[i]) != 0) return -1;
	if (buf_get_byte(buf, len, &off, &follows) != 0) return -1;

	if (!namelist_has(lists[0], list_len[0], "curve25519-sha256") &&
		!namelist_has(lists[0], list_len[0], "curve25519-sha256@libssh.org")) {
		LOGF(TRACE_LEVEL_WARNING, "[%u] client does not offer curve25519-sha256: %.*s",
			s->id, (int)(list_len[0] > 300 ? 300 : list_len[0]), (const char *)lists[0]);
		return -1;
	}
	for (i = 1; i < 8; i++) {
		if (!namelist_has(lists[i], list_len[i], required[i])) {
			LOGF(TRACE_LEVEL_WARNING, "[%u] client does not offer '%s' (field %d): %.*s",
				s->id, required[i], i, (int)(list_len[i] > 300 ? 300 : list_len[i]),
				(const char *)lists[i]);
			return -1;
		}
	}

	s->strict_kex = namelist_has(lists[0], list_len[0], STRICT_KEX_CLIENT);

	/* RFC 4253 §7: a guessed KEX packet must be ignored if the guess
	 * (client's first kex + host key algorithm) is not what was agreed. */
	*skip_guess = follows &&
		!(namelist_first_is(lists[0], list_len[0], "curve25519-sha256", "curve25519-sha256@libssh.org") &&
		  namelist_first_is(lists[1], list_len[1], "ssh-ed25519", NULL));
	return 0;
}

/* ---- Steps 3-5: ECDH_INIT -> compute -> sign -> ECDH_REPLY --------------- */

static int do_ecdh(SshSession *s, uint8_t *buf, size_t buf_size,
	uint8_t k_mpint[37], size_t *k_mpint_len, uint8_t H[32])
{
	size_t         len = 0, off;
	const uint8_t *q_c;
	size_t         q_c_len;
	uint8_t        rand32[32], priv[32], q_s[32], shared[32];
	uint8_t        hostkey_blob[SSH_ED25519_BLOB_LEN];
	uint8_t        sig[ED25519_SIG_LEN];
	uint8_t        reply[256];
	size_t         roff = 0;
	int            rc = 0;

	if (ssh_recv_packet(s, buf, buf_size, &len) != 0) return -1;
	if (len < 1 || buf[0] != SSH_MSG_KEX_ECDH_INIT) {
		LOGF(TRACE_LEVEL_WARNING, "[%u] expected KEX_ECDH_INIT, got %u", s->id, len ? buf[0] : 0);
		return -1;
	}
	off = 1;
	if (buf_get_string(buf, len, &off, &q_c, &q_c_len) != 0 || q_c_len != CURVE25519_KEY_LEN) {
		LOGF(TRACE_LEVEL_WARNING, "[%u] bad client ECDH public key", s->id);
		return -1;
	}

	/* Ephemeral key pair + shared secret */
	if (ssh_random(rand32, 32) != 0) return -1;
	curve25519_keygen(rand32, priv, q_s);
	if (curve25519_scalarmult(shared, priv, q_c) != 0) {
		LOGF(TRACE_LEVEL_WARNING, "[%u] X25519 low-order client key", s->id);
		return -1;
	}
	*k_mpint_len = encode_mpint(shared, k_mpint);

	ssh_ed25519_blob(s->host_key->pub, hostkey_blob);

	/*
	 * H = SHA-256( string V_C || string V_S || string I_C || string I_S ||
	 *              string K_S || string Q_C || string Q_S || mpint K )
	 */
	{
		Sha256Ctx ctx;
		sha256_init(&ctx);
		hash_string(&ctx, (const uint8_t *)s->peer_version, strlen(s->peer_version));
		hash_string(&ctx, (const uint8_t *)s->own_version, strlen(s->own_version));
		hash_string(&ctx, s->peer_kexinit, s->peer_kexinit_len);
		hash_string(&ctx, s->own_kexinit, s->own_kexinit_len);
		hash_string(&ctx, hostkey_blob, sizeof(hostkey_blob));
		hash_string(&ctx, q_c, q_c_len);
		hash_string(&ctx, q_s, sizeof(q_s));
		sha256_update(&ctx, k_mpint, *k_mpint_len);
		sha256_final(&ctx, H);
	}

	ed25519_sign(sig, H, SHA256_LEN, s->host_key->seed, s->host_key->pub);

	/* byte 31 || string K_S || string Q_S || string(string "ssh-ed25519" || string sig) */
	rc |= buf_put_byte(reply, sizeof(reply), &roff, SSH_MSG_KEX_ECDH_REPLY);
	rc |= buf_put_string(reply, sizeof(reply), &roff, hostkey_blob, sizeof(hostkey_blob));
	rc |= buf_put_string(reply, sizeof(reply), &roff, q_s, sizeof(q_s));
	rc |= buf_put_u32_at(reply, sizeof(reply), &roff, 4 + 11 + 4 + ED25519_SIG_LEN);
	rc |= buf_put_cstring(reply, sizeof(reply), &roff, "ssh-ed25519");
	rc |= buf_put_string(reply, sizeof(reply), &roff, sig, sizeof(sig));

	memset(rand32, 0, sizeof(rand32));
	memset(priv, 0, sizeof(priv));
	memset(shared, 0, sizeof(shared));

	if (rc) return -1;
	return ssh_send_packet(s, reply, roff);
}

/* ---- Public entry point -------------------------------------------------- */

int ssh_kex_server(SshSession *s, uint8_t *buf, size_t buf_size)
{
	uint8_t k_mpint[37];
	size_t  k_mpint_len = 0;
	uint8_t H[32];
	size_t  len = 0;
	int     skip_guess = 0;
	int     rc = -1;

	s->in_initial_kex = 1;

	if (send_kexinit(s) != 0) {
		LOGF(TRACE_LEVEL_WARNING, "[%u] send KEXINIT failed", s->id);
		goto out;
	}
	if (recv_kexinit(s, buf, buf_size, &skip_guess) != 0) goto out;

	if (skip_guess && ssh_recv_packet(s, buf, buf_size, &len) != 0) goto out;

	if (do_ecdh(s, buf, buf_size, k_mpint, &k_mpint_len, H) != 0) goto out;

	memcpy(s->session_id, H, 32);   /* first (and only) KEX: session id = H */

	/* server->client uses B/D/F, client->server uses A/C/E */
	derive_key(k_mpint, k_mpint_len, H, 'B', s->session_id, s->enc.iv, AES256_IV_LEN);
	derive_key(k_mpint, k_mpint_len, H, 'D', s->session_id, s->enc.key, AES256_KEY_LEN);
	derive_key(k_mpint, k_mpint_len, H, 'F', s->session_id, s->enc.mac_key, SHA256_LEN);
	derive_key(k_mpint, k_mpint_len, H, 'A', s->session_id, s->dec.iv, AES256_IV_LEN);
	derive_key(k_mpint, k_mpint_len, H, 'C', s->session_id, s->dec.key, AES256_KEY_LEN);
	derive_key(k_mpint, k_mpint_len, H, 'E', s->session_id, s->dec.mac_key, SHA256_LEN);
	aes256_key_expand(&s->enc.aes, s->enc.key);
	aes256_key_expand(&s->dec.aes, s->dec.key);

	/* Our NEWKEYS: everything we send afterwards uses the new keys */
	{
		uint8_t m = SSH_MSG_NEWKEYS;
		if (ssh_send_packet(s, &m, 1) != 0) goto out;
		EnterCriticalSection(&s->send_lock);
		s->enc_active = 1;
		if (s->strict_kex) s->enc.seq = 0;
		LeaveCriticalSection(&s->send_lock);
	}

	/* Client's NEWKEYS: everything it sends afterwards uses the new keys */
	if (ssh_recv_packet(s, buf, buf_size, &len) != 0) goto out;
	if (len < 1 || buf[0] != SSH_MSG_NEWKEYS) {
		LOGF(TRACE_LEVEL_WARNING, "[%u] expected NEWKEYS, got %u", s->id, len ? buf[0] : 0);
		goto out;
	}
	s->dec_active = 1;
	if (s->strict_kex) s->dec.seq = 0;
	s->in_initial_kex = 0;

	LOGF(TRACE_LEVEL_VERBOSE, "[%u] key exchange complete%s", s->id, s->strict_kex ? " (strict)" : "");
	rc = 0;

out:
	memset(k_mpint, 0, sizeof(k_mpint));
	free(s->own_kexinit);  s->own_kexinit = NULL;  s->own_kexinit_len = 0;
	free(s->peer_kexinit); s->peer_kexinit = NULL; s->peer_kexinit_len = 0;
	return rc;
}
