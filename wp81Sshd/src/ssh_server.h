#pragma once

/*
 * ssh_server.h  -  Minimal SSH-2 server: shared definitions.
 *
 * Supported algorithms (exactly, as in the wp81ssh client):
 *   KEX        : curve25519-sha256 (+ curve25519-sha256@libssh.org alias)
 *   Host key   : ssh-ed25519
 *   Cipher     : aes256-ctr  (both directions)
 *   MAC        : hmac-sha2-256 (both directions)
 *   Compression: none
 *   User auth  : publickey (ssh-ed25519) only
 */

#include "Win32Api.h"
#include <stdint.h>
#include <stddef.h>

#include "crypto/aes256.h"

/* ------------------------------------------------------------------ sizes */
#define SSH_MAX_PACKET      35000
#define SSH_BANNER_MAX      256
#define SSH_ID_STRING       "SSH-2.0-wp81Sshd_0.1"

/* ------------------------------------------------------------------ message numbers (RFC 4253 / 4252 / 4254) */
#define SSH_MSG_DISCONNECT              1
#define SSH_MSG_IGNORE                  2
#define SSH_MSG_UNIMPLEMENTED           3
#define SSH_MSG_DEBUG                   4
#define SSH_MSG_SERVICE_REQUEST         5
#define SSH_MSG_SERVICE_ACCEPT          6
#define SSH_MSG_KEXINIT                 20
#define SSH_MSG_NEWKEYS                 21
#define SSH_MSG_KEX_ECDH_INIT           30
#define SSH_MSG_KEX_ECDH_REPLY          31
#define SSH_MSG_USERAUTH_REQUEST        50
#define SSH_MSG_USERAUTH_FAILURE        51
#define SSH_MSG_USERAUTH_SUCCESS        52
#define SSH_MSG_USERAUTH_BANNER         53
#define SSH_MSG_USERAUTH_PK_OK          60
#define SSH_MSG_GLOBAL_REQUEST          80
#define SSH_MSG_REQUEST_SUCCESS         81
#define SSH_MSG_REQUEST_FAILURE         82
#define SSH_MSG_CHANNEL_OPEN            90
#define SSH_MSG_CHANNEL_OPEN_CONFIRM    91
#define SSH_MSG_CHANNEL_OPEN_FAILURE    92
#define SSH_MSG_CHANNEL_WINDOW_ADJUST   93
#define SSH_MSG_CHANNEL_DATA            94
#define SSH_MSG_CHANNEL_EXTENDED_DATA   95
#define SSH_MSG_CHANNEL_EOF             96
#define SSH_MSG_CHANNEL_CLOSE           97
#define SSH_MSG_CHANNEL_REQUEST         98
#define SSH_MSG_CHANNEL_SUCCESS         99
#define SSH_MSG_CHANNEL_FAILURE         100

/* ------------------------------------------------------------------ disconnect reasons (RFC 4253 §11.1) */
#define SSH_DISCONNECT_PROTOCOL_ERROR               2
#define SSH_DISCONNECT_KEY_EXCHANGE_FAILED          3
#define SSH_DISCONNECT_SERVICE_NOT_AVAILABLE        7
#define SSH_DISCONNECT_BY_APPLICATION               11
#define SSH_DISCONNECT_TOO_MANY_CONNECTIONS         12
#define SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE 14

/* ------------------------------------------------------------------ channel open failure reasons (RFC 4254 §5.1) */
#define SSH_OPEN_ADMINISTRATIVELY_PROHIBITED  1
#define SSH_OPEN_UNKNOWN_CHANNEL_TYPE         3
#define SSH_OPEN_RESOURCE_SHORTAGE            4

/* ------------------------------------------------------------------ key sizes */
#define CURVE25519_KEY_LEN  32
#define ED25519_KEY_LEN     32
#define ED25519_SIG_LEN     64
#define AES256_KEY_LEN      32
#define AES256_IV_LEN       16
#define SHA256_LEN          32

/* string "ssh-ed25519" + string pub[32] */
#define SSH_ED25519_BLOB_LEN  (4 + 11 + 4 + 32)

/* ------------------------------------------------------------------ host key */
typedef struct {
    uint8_t seed[32];   /* Ed25519 secret seed */
    uint8_t pub[32];    /* Ed25519 public key  */
} HostKey;

/* ------------------------------------------------------------------ crypto state (one direction) */
typedef struct {
    uint8_t   key[AES256_KEY_LEN];
    uint8_t   iv[AES256_IV_LEN];     /* running CTR */
    uint8_t   mac_key[SHA256_LEN];
    Aes256Ctx aes;                   /* expanded key schedule */
    uint32_t  seq;                   /* packet sequence number (wraps mod 2^32) */
} CryptoDir;

/* ------------------------------------------------------------------ session state */
typedef struct SshSession {
    SOCKET   sock;
    unsigned id;                     /* for log lines */
    char     peer_addr[64];

    /* version strings (no CRLF) */
    char     own_version[SSH_BANNER_MAX];
    char     peer_version[SSH_BANNER_MAX];

    /* raw KEXINIT payloads, kept for the exchange hash */
    uint8_t *own_kexinit;
    size_t   own_kexinit_len;
    uint8_t *peer_kexinit;
    size_t   peer_kexinit_len;

    uint8_t  session_id[SHA256_LEN];
    int      strict_kex;             /* kex-strict-c-v00@openssh.com negotiated */
    int      in_initial_kex;         /* 1 until the first NEWKEYS is received  */

    CryptoDir enc;                   /* server -> client */
    CryptoDir dec;                   /* client -> server */
    int       enc_active;
    int       dec_active;
    uint32_t  pad_rng;               /* xorshift state for packet padding */

    CRITICAL_SECTION send_lock;      /* serialises ssh_send_packet across threads */

    /* configuration (copied in by the listener) */
    const HostKey *host_key;
    wchar_t  authorized_keys_path[MAX_PATH];
    wchar_t  shell_command[MAX_PATH];

    char     user[64];               /* authenticated user name */

    volatile LONG closing;           /* set when the session must end */
} SshSession;

/* ------------------------------------------------------------------ entry points */

/* Allocate / free a session around an accepted socket. */
SshSession *ssh_session_new(SOCKET sock, unsigned id, const char *peer_addr);
void        ssh_session_free(SshSession *s);

/* Run a complete connection (banner, KEX, auth, shell) on the calling thread.
 * Returns when the connection is over.  Does not close s->sock. */
void        ssh_session_run(SshSession *s);

/* Build the wire blob of an Ed25519 public key (SSH_ED25519_BLOB_LEN bytes). */
void        ssh_ed25519_blob(const uint8_t pub[32], uint8_t out[SSH_ED25519_BLOB_LEN]);

/* "SHA256:<base64>" fingerprint, as printed by ssh-keygen -l. */
void        ssh_fingerprint(const uint8_t pub[32], char *out, size_t out_size);
