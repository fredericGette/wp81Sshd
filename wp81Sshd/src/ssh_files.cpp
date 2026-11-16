/*
 * ssh_files.cpp  -  File transfer: SFTP v3 subsystem and legacy SCP.
 *
 * SFTP (draft-ietf-secsh-filexfer-02, as implemented by OpenSSH):
 *   INIT, OPEN, CLOSE, READ, WRITE, STAT, LSTAT, FSTAT, SETSTAT, FSETSTAT,
 *   OPENDIR, READDIR, REMOVE, MKDIR, RMDIR, REALPATH, RENAME.
 *   Symbolic links and extensions are not supported.  Permissions are
 *   reported as 0644 / 0755 (0444 for read-only files) and ignored when set;
 *   sizes and modification times are honoured.
 *
 * Legacy SCP (the rcp protocol): "scp -t" (sink: the client uploads) and
 * "scp -f" (source: the client downloads), with -r (recursive), -d (target
 * must be a directory) and -p (preserve times).
 *
 * Paths are UTF-8 on the wire.  They are presented to SFTP clients as
 * "/C:/Data/..." so the client sees them as absolute.
 */

#include "ssh_files.h"
#include "ssh_transport.h"
#include "log.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

#define XPATH            1024                  /* wide chars in a resolved path */
#define XPATH_U8         (XPATH * 3)           /* the same in UTF-8 */
#define FT_UNIX_EPOCH    116444736000000000ULL /* 1970-01-01 in FILETIME units */

/* ================================================================== common helpers */

static int is_alpha(wchar_t ch)
{
	return (ch >= L'a' && ch <= L'z') || (ch >= L'A' && ch <= L'Z');
}

/* UTF-8 (not NUL-terminated) -> wide, NUL-terminated.  -1 on error. */
static int u8_to_w(const char *s, size_t len, wchar_t *out, size_t out_chars)
{
	int n = 0;
	if (memchr(s, 0, len) != NULL) return -1;
	if (len > 0) {
		n = MultiByteToWideChar(CP_UTF8, 0, s, (int)len, out, (int)out_chars - 1);
		if (n <= 0) return -1;
	}
	out[n] = 0;
	return n;
}

/* Wide -> UTF-8, NUL-terminated.  Returns the length, or -1. */
static int w_to_u8(const wchar_t *w, char *out, size_t out_size)
{
	int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, out, (int)out_size, NULL, NULL);
	if (n <= 0) {
		out[0] = 0;
		return -1;
	}
	return n - 1;
}

/*
 * Turn a client path into an absolute "X:\a\b" path.
 *  - '/' and '\' are both separators;
 *  - the last "X:" component wins, so "/C:/Data", "C:/Data" and even
 *    "/C:/Data/USERS/Public/Documents/D:/x" (a relative "D:/x" joined to the
 *    remote directory by the client) all work;
 *  - "/x" without a drive is on the drive of the home directory;
 *  - anything else is relative to the home directory;
 *  - "." and ".." components are resolved.
 */
static int path_resolve(const wchar_t *home, const wchar_t *in, wchar_t *out, size_t out_chars)
{
	wchar_t  tmp[XPATH];
	wchar_t  full[XPATH * 2];
	wchar_t *comp[XPATH / 2];
	size_t   i, n, start = (size_t)-1, len;
	int      nc = 0;
	wchar_t *p;

	n = wcslen(in);
	if (n >= XPATH) return -1;
	for (i = 0; i <= n; i++) tmp[i] = (in[i] == L'/') ? L'\\' : in[i];

	for (i = 0; i + 1 < n; i++) {
		if (is_alpha(tmp[i]) && tmp[i + 1] == L':' &&
			(i == 0 || tmp[i - 1] == L'\\') && (i + 2 == n || tmp[i + 2] == L'\\'))
			start = i;
	}

	if (start != (size_t)-1)
		_snwprintf_s(full, _countof(full), _TRUNCATE, L"%s", tmp + start);
	else if (tmp[0] == L'\\')
		_snwprintf_s(full, _countof(full), _TRUNCATE, L"%.2s%s", home, tmp);
	else
		_snwprintf_s(full, _countof(full), _TRUNCATE, L"%s\\%s", home, tmp);

	if (!is_alpha(full[0]) || full[1] != L':') return -1;

	/* Split after "X:" and resolve . / .. */
	p = full + 2;
	while (*p) {
		wchar_t *seg;
		while (*p == L'\\') p++;
		if (!*p) break;
		seg = p;
		while (*p && *p != L'\\') p++;
		if (*p) *p++ = 0;
		if (wcscmp(seg, L".") == 0) continue;
		if (wcscmp(seg, L"..") == 0) {
			if (nc > 0) nc--;
			continue;
		}
		if (nc == (int)_countof(comp)) return -1;
		comp[nc++] = seg;
	}

	if (out_chars < 4) return -1;
	out[0] = (full[0] >= L'a') ? (wchar_t)(full[0] - 32) : full[0];
	out[1] = L':';
	len = 2;
	for (i = 0; i < (size_t)nc; i++) {
		size_t cl = wcslen(comp[i]);
		if (len + 1 + cl + 1 > out_chars || len + 1 + cl + 1 > MAX_PATH) return -1;
		out[len++] = L'\\';
		memcpy(out + len, comp[i], cl * sizeof(wchar_t));
		len += cl;
	}
	if (nc == 0) out[len++] = L'\\';
	out[len] = 0;
	return 0;
}

static int path_resolve_u8(const wchar_t *home, const char *s, size_t len, wchar_t *out, size_t out_chars)
{
	wchar_t w[XPATH];
	if (len >= XPATH || u8_to_w(s, len, w, XPATH) < 0) return -1;
	if (w[0] == 0) wcscpy_s(w, XPATH, L".");
	return path_resolve(home, w, out, out_chars);
}

/* "C:\Data\x" -> "/C:/Data/x" (UTF-8) */
static void path_display(const wchar_t *path, char *out, size_t out_size)
{
	char   u8[XPATH_U8];
	size_t i, n;
	if (w_to_u8(path, u8, sizeof(u8)) < 0) u8[0] = 0;
	n = strlen(u8);
	if (n + 2 > out_size) n = out_size - 2;
	out[0] = '/';
	for (i = 0; i < n; i++) out[i + 1] = (u8[i] == '\\') ? '/' : u8[i];
	out[n + 1] = 0;
}

/* Join a directory and a name ("C:\" + "x" -> "C:\x"). */
static int path_join(const wchar_t *dir, const wchar_t *name, wchar_t *out, size_t out_chars)
{
	size_t dl = wcslen(dir);
	int    n = _snwprintf_s(out, out_chars, _TRUNCATE, L"%s%s%s", dir,
		(dl > 0 && dir[dl - 1] == L'\\') ? L"" : L"\\", name);
	return (n < 0 || wcslen(out) >= MAX_PATH) ? -1 : 0;
}

static const char *err_text(DWORD e)
{
	switch (e) {
	case ERROR_FILE_NOT_FOUND:
	case ERROR_PATH_NOT_FOUND:
	case ERROR_INVALID_NAME:
	case ERROR_BAD_PATHNAME:
	case ERROR_INVALID_DRIVE:    return "No such file or directory";
	case ERROR_ACCESS_DENIED:    return "Permission denied";
	case ERROR_SHARING_VIOLATION:
	case ERROR_LOCK_VIOLATION:   return "File is in use";
	case ERROR_FILE_EXISTS:
	case ERROR_ALREADY_EXISTS:   return "File exists";
	case ERROR_DIR_NOT_EMPTY:    return "Directory not empty";
	case ERROR_DIRECTORY:        return "Not a directory";
	case ERROR_DISK_FULL:
	case ERROR_HANDLE_DISK_FULL: return "No space left on device";
	case ERROR_FILENAME_EXCED_RANGE: return "File name too long";
	default:                     return "Failure";
	}
}

/* ------------------------------------------------------------------ file information */

typedef struct {
	DWORD    attr;
	uint64_t size;
	FILETIME atime, mtime;
} FInfo;

static int finfo_path(const wchar_t *path, FInfo *fi)
{
	WIN32_FILE_ATTRIBUTE_DATA d;
	if (!GetFileAttributesExW(path, GetFileExInfoStandard, &d)) return -1;
	fi->attr = d.dwFileAttributes;
	fi->size = ((uint64_t)d.nFileSizeHigh << 32) | d.nFileSizeLow;
	fi->atime = d.ftLastAccessTime;
	fi->mtime = d.ftLastWriteTime;
	return 0;
}

static int finfo_handle(HANDLE h, FInfo *fi)
{
	BY_HANDLE_FILE_INFORMATION d;
	if (!GetFileInformationByHandle(h, &d)) return -1;
	fi->attr = d.dwFileAttributes;
	fi->size = ((uint64_t)d.nFileSizeHigh << 32) | d.nFileSizeLow;
	fi->atime = d.ftLastAccessTime;
	fi->mtime = d.ftLastWriteTime;
	return 0;
}

static void finfo_find(const WIN32_FIND_DATAW *fd, FInfo *fi)
{
	fi->attr = fd->dwFileAttributes;
	fi->size = ((uint64_t)fd->nFileSizeHigh << 32) | fd->nFileSizeLow;
	fi->atime = fd->ftLastAccessTime;
	fi->mtime = fd->ftLastWriteTime;
}

static int is_dir(const FInfo *fi)
{
	return (fi->attr & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

static uint32_t unix_mode(const FInfo *fi)
{
	if (is_dir(fi)) return 040755;
	return (fi->attr & FILE_ATTRIBUTE_READONLY) ? 0100444 : 0100644;
}

static uint32_t ft_to_unix(FILETIME ft)
{
	uint64_t v = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
	if (v < FT_UNIX_EPOCH) return 0;
	v = (v - FT_UNIX_EPOCH) / 10000000ULL;
	return v > 0xFFFFFFFFULL ? 0xFFFFFFFFUL : (uint32_t)v;
}

static FILETIME unix_to_ft(uint32_t t)
{
	FILETIME ft;
	uint64_t v = (uint64_t)t * 10000000ULL + FT_UNIX_EPOCH;
	ft.dwLowDateTime = (DWORD)v;
	ft.dwHighDateTime = (DWORD)(v >> 32);
	return ft;
}

/* Set access/modification times on a handle (if it allows it) or a path. */
static int set_times(const wchar_t *path, HANDLE h, uint32_t atime, uint32_t mtime)
{
	FILETIME at = unix_to_ft(atime), mt = unix_to_ft(mtime);
	BOOL     ok;
	if (h && h != INVALID_HANDLE_VALUE && SetFileTime(h, NULL, &at, &mt)) return 0;
	if (!path) return -1;
	h = CreateFileW(path, FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
	if (h == INVALID_HANDLE_VALUE) return -1;
	ok = SetFileTime(h, NULL, &at, &mt);
	CloseHandle(h);
	return ok ? 0 : -1;
}

static int set_size(const wchar_t *path, HANDLE h, uint64_t size)
{
	LARGE_INTEGER li;
	int           opened = 0, rc = -1;
	li.QuadPart = (LONGLONG)size;
	if (!h || h == INVALID_HANDLE_VALUE) {
		if (!path) return -1;
		h = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
			OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (h == INVALID_HANDLE_VALUE) return -1;
		opened = 1;
	}
	if (SetFilePointerEx(h, li, NULL, FILE_BEGIN) && SetEndOfFile(h)) rc = 0;
	if (opened) CloseHandle(h);
	return rc;
}

/* ------------------------------------------------------------------ I/O */

/* Read exactly len bytes: 1 = done, 0 = end of input before the first byte, -1 = error. */
static int io_read_exact(XferIO *io, uint8_t *buf, size_t len)
{
	size_t got = 0;
	while (got < len) {
		int n = io->recv(io->ctx, buf + got, len - got);
		if (n <= 0) return (n == 0 && got == 0) ? 0 : -1;
		got += (size_t)n;
	}
	return 1;
}

/* ================================================================== SFTP */

#define SFTP_MAX_MSG     (256 * 1024 + 1024)
#define SFTP_OUT_MAX     (64 * 1024)
#define SFTP_READ_MAX    32768
#define SFTP_HANDLES     32
#define SFTP_READDIR_MAX 64

/* packet types */
#define SSH_FXP_INIT       1
#define SSH_FXP_VERSION    2
#define SSH_FXP_OPEN       3
#define SSH_FXP_CLOSE      4
#define SSH_FXP_READ       5
#define SSH_FXP_WRITE      6
#define SSH_FXP_LSTAT      7
#define SSH_FXP_FSTAT      8
#define SSH_FXP_SETSTAT    9
#define SSH_FXP_FSETSTAT   10
#define SSH_FXP_OPENDIR    11
#define SSH_FXP_READDIR    12
#define SSH_FXP_REMOVE     13
#define SSH_FXP_MKDIR      14
#define SSH_FXP_RMDIR      15
#define SSH_FXP_REALPATH   16
#define SSH_FXP_STAT       17
#define SSH_FXP_RENAME     18
#define SSH_FXP_READLINK   19
#define SSH_FXP_SYMLINK    20
#define SSH_FXP_STATUS     101
#define SSH_FXP_HANDLE     102
#define SSH_FXP_DATA       103
#define SSH_FXP_NAME       104
#define SSH_FXP_ATTRS      105

/* status codes */
#define SSH_FX_OK                 0
#define SSH_FX_EOF                1
#define SSH_FX_NO_SUCH_FILE       2
#define SSH_FX_PERMISSION_DENIED  3
#define SSH_FX_FAILURE            4
#define SSH_FX_BAD_MESSAGE        5
#define SSH_FX_OP_UNSUPPORTED     8

/* attribute flags */
#define SSH_FILEXFER_ATTR_SIZE        0x00000001
#define SSH_FILEXFER_ATTR_UIDGID      0x00000002
#define SSH_FILEXFER_ATTR_PERMISSIONS 0x00000004
#define SSH_FILEXFER_ATTR_ACMODTIME   0x00000008
#define SSH_FILEXFER_ATTR_EXTENDED    0x80000000

/* open flags */
#define SSH_FXF_READ    0x01
#define SSH_FXF_WRITE   0x02
#define SSH_FXF_APPEND  0x04
#define SSH_FXF_CREAT   0x08
#define SSH_FXF_TRUNC   0x10
#define SSH_FXF_EXCL    0x20

typedef struct {
	int      kind;                 /* 0 free, 1 file, 2 directory */
	HANDLE   h;                    /* file handle, or find handle */
	int      writable;
	int      append;
	int      have;                 /* directory: fd holds an entry not returned yet */
	WIN32_FIND_DATAW fd;
	wchar_t  path[MAX_PATH];
} SftpHandle;

typedef struct {
	uint32_t flags;
	uint64_t size;
	uint32_t perm;
	uint32_t atime, mtime;
} SftpAttrs;

typedef struct {
	XferIO        *io;
	const wchar_t *home;
	uint8_t       *in;
	size_t         in_len;
	uint8_t       *out;
	size_t         out_len;
	int            out_overflow;
	SftpHandle     h[SFTP_HANDLES];
} Sftp;

/* ------------------------------------------------------------------ response building */

static void o_bytes(Sftp *f, const void *data, size_t len)
{
	if (f->out_len + len > SFTP_OUT_MAX) {
		f->out_overflow = 1;
		return;
	}
	memcpy(f->out + f->out_len, data, len);
	f->out_len += len;
}

static void o_u8(Sftp *f, uint8_t v)
{
	o_bytes(f, &v, 1);
}

static void o_u32(Sftp *f, uint32_t v)
{
	uint8_t b[4];
	buf_put_u32(b, v);
	o_bytes(f, b, 4);
}

static void o_u64(Sftp *f, uint64_t v)
{
	o_u32(f, (uint32_t)(v >> 32));
	o_u32(f, (uint32_t)v);
}

static void o_str(Sftp *f, const void *data, size_t len)
{
	o_u32(f, (uint32_t)len);
	o_bytes(f, data, len);
}

static void o_cstr(Sftp *f, const char *s)
{
	o_str(f, s, strlen(s));
}

static void o_begin(Sftp *f, uint8_t type, uint32_t id)
{
	f->out_len = 4;   /* length, patched by o_send */
	f->out_overflow = 0;
	o_u8(f, type);
	o_u32(f, id);
}

static int o_send(Sftp *f)
{
	if (f->out_overflow) {
		LOGF(TRACE_LEVEL_ERROR, "[%u] sftp: response too large", f->io->session_id);
		return -1;
	}
	buf_put_u32(f->out, (uint32_t)(f->out_len - 4));
	return f->io->send(f->io->ctx, f->out, f->out_len);
}

static int send_status(Sftp *f, uint32_t id, uint32_t code, const char *msg)
{
	o_begin(f, SSH_FXP_STATUS, id);
	o_u32(f, code);
	o_cstr(f, msg);
	o_cstr(f, "");
	return o_send(f);
}

static int send_ok(Sftp *f, uint32_t id)
{
	return send_status(f, id, SSH_FX_OK, "Success");
}

static int send_error(Sftp *f, uint32_t id, DWORD e)
{
	uint32_t code;
	switch (e) {
	case ERROR_FILE_NOT_FOUND:
	case ERROR_PATH_NOT_FOUND:
	case ERROR_INVALID_NAME:
	case ERROR_BAD_PATHNAME:
	case ERROR_INVALID_DRIVE:  code = SSH_FX_NO_SUCH_FILE; break;
	case ERROR_ACCESS_DENIED:  code = SSH_FX_PERMISSION_DENIED; break;
	default:                   code = SSH_FX_FAILURE; break;
	}
	return send_status(f, id, code, err_text(e));
}

static void o_attrs(Sftp *f, const FInfo *fi)
{
	o_u32(f, SSH_FILEXFER_ATTR_SIZE | SSH_FILEXFER_ATTR_PERMISSIONS | SSH_FILEXFER_ATTR_ACMODTIME);
	o_u64(f, is_dir(fi) ? 0 : fi->size);
	o_u32(f, unix_mode(fi));
	o_u32(f, ft_to_unix(fi->atime));
	o_u32(f, ft_to_unix(fi->mtime));
}

/* "ls -l" style line, as displayed by "sftp> ls -l". */
static void o_longname(Sftp *f, const char *name, const FInfo *fi)
{
	static const char *months[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
		"Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
	char       line[XPATH_U8 + 128];
	SYSTEMTIME st = {};
	const char *perm = is_dir(fi) ? "drwxr-xr-x" :
		(fi->attr & FILE_ATTRIBUTE_READONLY) ? "-r--r--r--" : "-rw-r--r--";

	FileTimeToSystemTime(&fi->mtime, &st);
	if (st.wMonth < 1 || st.wMonth > 12) st.wMonth = 1;
	_snprintf_s(line, sizeof(line), _TRUNCATE, "%s    1 owner    group    %10llu %s %2u %02u:%02u %s",
		perm, (unsigned long long)(is_dir(fi) ? 0 : fi->size), months[st.wMonth - 1],
		st.wDay, st.wHour, st.wMinute, name);
	o_cstr(f, line);
}

/* ------------------------------------------------------------------ request parsing */

static int get_u64(const uint8_t *b, size_t len, size_t *off, uint64_t *v)
{
	uint32_t hi, lo;
	if (buf_get_u32_at(b, len, off, &hi) != 0 || buf_get_u32_at(b, len, off, &lo) != 0) return -1;
	*v = ((uint64_t)hi << 32) | lo;
	return 0;
}

static int get_attrs(Sftp *f, size_t *off, SftpAttrs *a)
{
	uint32_t dummy, count, i;
	memset(a, 0, sizeof(*a));
	if (buf_get_u32_at(f->in, f->in_len, off, &a->flags) != 0) return -1;
	if ((a->flags & SSH_FILEXFER_ATTR_SIZE) && get_u64(f->in, f->in_len, off, &a->size) != 0) return -1;
	if ((a->flags & SSH_FILEXFER_ATTR_UIDGID) &&
		(buf_get_u32_at(f->in, f->in_len, off, &dummy) != 0 ||
		 buf_get_u32_at(f->in, f->in_len, off, &dummy) != 0)) return -1;
	if ((a->flags & SSH_FILEXFER_ATTR_PERMISSIONS) &&
		buf_get_u32_at(f->in, f->in_len, off, &a->perm) != 0) return -1;
	if ((a->flags & SSH_FILEXFER_ATTR_ACMODTIME) &&
		(buf_get_u32_at(f->in, f->in_len, off, &a->atime) != 0 ||
		 buf_get_u32_at(f->in, f->in_len, off, &a->mtime) != 0)) return -1;
	if (a->flags & SSH_FILEXFER_ATTR_EXTENDED) {
		if (buf_get_u32_at(f->in, f->in_len, off, &count) != 0) return -1;
		for (i = 0; i < count; i++) {
			const uint8_t *p;
			size_t         l;
			if (buf_get_string(f->in, f->in_len, off, &p, &l) != 0 ||
				buf_get_string(f->in, f->in_len, off, &p, &l) != 0) return -1;
		}
	}
	return 0;
}

static int get_path(Sftp *f, size_t *off, wchar_t *out)
{
	const uint8_t *p;
	size_t         l;
	if (buf_get_string(f->in, f->in_len, off, &p, &l) != 0) return -2;   /* malformed */
	return path_resolve_u8(f->home, (const char *)p, l, out, MAX_PATH) == 0 ? 0 : -1;
}

static SftpHandle *get_handle(Sftp *f, size_t *off, int kind)
{
	const uint8_t *p;
	size_t         l;
	uint32_t       idx;
	if (buf_get_string(f->in, f->in_len, off, &p, &l) != 0 || l != 4) return NULL;
	idx = buf_get_u32(p);
	if (idx >= SFTP_HANDLES || f->h[idx].kind != kind) return NULL;
	return &f->h[idx];
}

static SftpHandle *alloc_handle(Sftp *f, uint32_t *idx)
{
	uint32_t i;
	for (i = 0; i < SFTP_HANDLES; i++) {
		if (f->h[i].kind == 0) {
			memset(&f->h[i], 0, sizeof(f->h[i]));
			*idx = i;
			return &f->h[i];
		}
	}
	return NULL;
}

static void free_handle(SftpHandle *h)
{
	if (h->kind == 1) CloseHandle(h->h);
	else if (h->kind == 2 && h->h != INVALID_HANDLE_VALUE) FindClose(h->h);
	h->kind = 0;
	h->h = NULL;
}

static int send_handle(Sftp *f, uint32_t id, uint32_t idx)
{
	uint8_t b[4];
	buf_put_u32(b, idx);
	o_begin(f, SSH_FXP_HANDLE, id);
	o_str(f, b, 4);
	return o_send(f);
}

static int apply_attrs(const wchar_t *path, HANDLE h, const SftpAttrs *a)
{
	if ((a->flags & SSH_FILEXFER_ATTR_SIZE) && set_size(path, h, a->size) != 0) return -1;
	if ((a->flags & SSH_FILEXFER_ATTR_ACMODTIME) && set_times(path, h, a->atime, a->mtime) != 0) return -1;
	/* permissions: not mapped */
	return 0;
}

/* ------------------------------------------------------------------ requests */

static int sftp_open(Sftp *f, uint32_t id, size_t off)
{
	wchar_t    path[MAX_PATH];
	uint32_t   pflags, idx;
	SftpAttrs  a;
	DWORD      access = 0, disp;
	HANDLE     h;
	SftpHandle *sh;
	int        r = get_path(f, &off, path);

	if (r == -2 || buf_get_u32_at(f->in, f->in_len, &off, &pflags) != 0 || get_attrs(f, &off, &a) != 0)
		return send_status(f, id, SSH_FX_BAD_MESSAGE, "Bad message");
	if (r != 0) return send_error(f, id, ERROR_BAD_PATHNAME);

	if (pflags & SSH_FXF_READ) access |= GENERIC_READ;
	if (pflags & (SSH_FXF_WRITE | SSH_FXF_APPEND)) access |= GENERIC_WRITE;
	if (access == 0) access = GENERIC_READ;

	if ((pflags & SSH_FXF_CREAT) && (pflags & SSH_FXF_EXCL)) disp = CREATE_NEW;
	else if ((pflags & SSH_FXF_CREAT) && (pflags & SSH_FXF_TRUNC)) disp = CREATE_ALWAYS;
	else if (pflags & SSH_FXF_CREAT) disp = OPEN_ALWAYS;
	else if (pflags & SSH_FXF_TRUNC) disp = TRUNCATE_EXISTING;
	else disp = OPEN_EXISTING;

	h = CreateFileW(path, access, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, disp, FILE_ATTRIBUTE_NORMAL, NULL);
	if (h == INVALID_HANDLE_VALUE) {
		DWORD e = GetLastError();
		LOGF(TRACE_LEVEL_VERBOSE, "[%u] sftp: open '%S' failed: %lu", f->io->session_id, path, e);
		return send_error(f, id, e);
	}
	sh = alloc_handle(f, &idx);
	if (!sh) {
		CloseHandle(h);
		return send_status(f, id, SSH_FX_FAILURE, "Too many open handles");
	}
	sh->kind = 1;
	sh->h = h;
	sh->writable = (access & GENERIC_WRITE) != 0;
	sh->append = (pflags & SSH_FXF_APPEND) != 0;
	wcscpy_s(sh->path, MAX_PATH, path);
	LOGF(TRACE_LEVEL_INFORMATION, "[%u] sftp: %s '%S'", f->io->session_id,
		sh->writable ? "writing" : "reading", path);
	return send_handle(f, id, idx);
}

static int sftp_read(Sftp *f, uint32_t id, size_t off)
{
	SftpHandle *sh = get_handle(f, &off, 1);
	uint64_t    pos;
	uint32_t    len;
	OVERLAPPED  ov = {};
	DWORD       got = 0;
	size_t      lenpos;

	if (!sh) return send_status(f, id, SSH_FX_FAILURE, "Invalid handle");
	if (get_u64(f->in, f->in_len, &off, &pos) != 0 || buf_get_u32_at(f->in, f->in_len, &off, &len) != 0)
		return send_status(f, id, SSH_FX_BAD_MESSAGE, "Bad message");
	if (len > SFTP_READ_MAX) len = SFTP_READ_MAX;

	o_begin(f, SSH_FXP_DATA, id);
	lenpos = f->out_len;
	o_u32(f, 0);
	ov.Offset = (DWORD)pos;
	ov.OffsetHigh = (DWORD)(pos >> 32);
	if (!ReadFile(sh->h, f->out + f->out_len, len, &got, &ov)) {
		DWORD e = GetLastError();
		if (e == ERROR_HANDLE_EOF) return send_status(f, id, SSH_FX_EOF, "End of file");
		return send_error(f, id, e);
	}
	if (got == 0) return send_status(f, id, SSH_FX_EOF, "End of file");
	buf_put_u32(f->out + lenpos, got);
	f->out_len += got;
	return o_send(f);
}

static int sftp_write(Sftp *f, uint32_t id, size_t off)
{
	SftpHandle    *sh = get_handle(f, &off, 1);
	uint64_t       pos;
	const uint8_t *data;
	size_t         len;
	OVERLAPPED     ov = {};
	DWORD          written = 0;

	if (!sh) return send_status(f, id, SSH_FX_FAILURE, "Invalid handle");
	if (get_u64(f->in, f->in_len, &off, &pos) != 0 || buf_get_string(f->in, f->in_len, &off, &data, &len) != 0)
		return send_status(f, id, SSH_FX_BAD_MESSAGE, "Bad message");
	if (sh->append) {
		ov.Offset = 0xFFFFFFFF;      /* write at the end of the file */
		ov.OffsetHigh = 0xFFFFFFFF;
	} else {
		ov.Offset = (DWORD)pos;
		ov.OffsetHigh = (DWORD)(pos >> 32);
	}
	if (!WriteFile(sh->h, data, (DWORD)len, &written, &ov)) return send_error(f, id, GetLastError());
	if (written != len) return send_error(f, id, ERROR_HANDLE_DISK_FULL);
	return send_ok(f, id);
}

static int sftp_close(Sftp *f, uint32_t id, size_t off)
{
	const uint8_t *p;
	size_t         l;
	uint32_t       idx;
	if (buf_get_string(f->in, f->in_len, &off, &p, &l) != 0 || l != 4 ||
		(idx = buf_get_u32(p)) >= SFTP_HANDLES || f->h[idx].kind == 0)
		return send_status(f, id, SSH_FX_FAILURE, "Invalid handle");
	free_handle(&f->h[idx]);
	return send_ok(f, id);
}

static int send_attrs(Sftp *f, uint32_t id, const FInfo *fi)
{
	o_begin(f, SSH_FXP_ATTRS, id);
	o_attrs(f, fi);
	return o_send(f);
}

static int sftp_stat(Sftp *f, uint32_t id, size_t off)
{
	wchar_t path[MAX_PATH];
	FInfo   fi;
	int     r = get_path(f, &off, path);
	if (r == -2) return send_status(f, id, SSH_FX_BAD_MESSAGE, "Bad message");
	if (r != 0) return send_error(f, id, ERROR_BAD_PATHNAME);
	if (finfo_path(path, &fi) != 0) return send_error(f, id, GetLastError());
	return send_attrs(f, id, &fi);
}

static int sftp_fstat(Sftp *f, uint32_t id, size_t off)
{
	SftpHandle *sh = get_handle(f, &off, 1);
	FInfo       fi;
	if (!sh) return send_status(f, id, SSH_FX_FAILURE, "Invalid handle");
	if (finfo_handle(sh->h, &fi) != 0) return send_error(f, id, GetLastError());
	return send_attrs(f, id, &fi);
}

static int sftp_setstat(Sftp *f, uint32_t id, size_t off)
{
	wchar_t   path[MAX_PATH];
	SftpAttrs a;
	int       r = get_path(f, &off, path);
	if (r == -2 || get_attrs(f, &off, &a) != 0) return send_status(f, id, SSH_FX_BAD_MESSAGE, "Bad message");
	if (r != 0) return send_error(f, id, ERROR_BAD_PATHNAME);
	if (apply_attrs(path, NULL, &a) != 0) return send_error(f, id, GetLastError());
	return send_ok(f, id);
}

static int sftp_fsetstat(Sftp *f, uint32_t id, size_t off)
{
	SftpHandle *sh = get_handle(f, &off, 1);
	SftpAttrs   a;
	if (!sh) return send_status(f, id, SSH_FX_FAILURE, "Invalid handle");
	if (get_attrs(f, &off, &a) != 0) return send_status(f, id, SSH_FX_BAD_MESSAGE, "Bad message");
	if (apply_attrs(sh->path, sh->writable ? sh->h : NULL, &a) != 0) return send_error(f, id, GetLastError());
	return send_ok(f, id);
}

static int sftp_opendir(Sftp *f, uint32_t id, size_t off)
{
	wchar_t     path[MAX_PATH], pattern[MAX_PATH + 4];
	FInfo       fi;
	uint32_t    idx;
	SftpHandle *sh;
	int         r = get_path(f, &off, path);

	if (r == -2) return send_status(f, id, SSH_FX_BAD_MESSAGE, "Bad message");
	if (r != 0) return send_error(f, id, ERROR_BAD_PATHNAME);
	if (finfo_path(path, &fi) != 0) return send_error(f, id, GetLastError());
	if (!is_dir(&fi)) return send_error(f, id, ERROR_DIRECTORY);
	if (path_join(path, L"*", pattern, _countof(pattern)) != 0) return send_error(f, id, ERROR_FILENAME_EXCED_RANGE);

	sh = alloc_handle(f, &idx);
	if (!sh) return send_status(f, id, SSH_FX_FAILURE, "Too many open handles");
	sh->h = FindFirstFileExW(pattern, FindExInfoBasic, &sh->fd, FindExSearchNameMatch, NULL, 0);
	if (sh->h == INVALID_HANDLE_VALUE) {
		DWORD e = GetLastError();
		if (e != ERROR_FILE_NOT_FOUND && e != ERROR_NO_MORE_FILES) return send_error(f, id, e);
		sh->have = 0;   /* empty (drive root) */
	} else {
		sh->have = 1;
	}
	sh->kind = 2;
	wcscpy_s(sh->path, MAX_PATH, path);
	return send_handle(f, id, idx);
}

static int sftp_readdir(Sftp *f, uint32_t id, size_t off)
{
	SftpHandle *sh = get_handle(f, &off, 2);
	size_t      countpos;
	uint32_t    count = 0;

	if (!sh) return send_status(f, id, SSH_FX_FAILURE, "Invalid handle");

	o_begin(f, SSH_FXP_NAME, id);
	countpos = f->out_len;
	o_u32(f, 0);
	while (sh->have && count < SFTP_READDIR_MAX && f->out_len < SFTP_OUT_MAX - 4096) {
		if (wcscmp(sh->fd.cFileName, L".") != 0 && wcscmp(sh->fd.cFileName, L"..") != 0) {
			char  name[XPATH_U8];
			FInfo fi;
			if (w_to_u8(sh->fd.cFileName, name, sizeof(name)) >= 0) {
				finfo_find(&sh->fd, &fi);
				o_cstr(f, name);
				o_longname(f, name, &fi);
				o_attrs(f, &fi);
				count++;
			}
		}
		if (!FindNextFileW(sh->h, &sh->fd)) sh->have = 0;
	}
	if (count == 0) return send_status(f, id, SSH_FX_EOF, "End of directory");
	buf_put_u32(f->out + countpos, count);
	return o_send(f);
}

/* REMOVE, MKDIR, RMDIR */
static int sftp_path_op(Sftp *f, uint32_t id, size_t off, uint8_t type)
{
	wchar_t   path[MAX_PATH];
	SftpAttrs a;
	BOOL      ok;
	int       r = get_path(f, &off, path);

	if (r == -2 || (type == SSH_FXP_MKDIR && get_attrs(f, &off, &a) != 0))
		return send_status(f, id, SSH_FX_BAD_MESSAGE, "Bad message");
	if (r != 0) return send_error(f, id, ERROR_BAD_PATHNAME);

	switch (type) {
	case SSH_FXP_REMOVE: ok = DeleteFileW(path);           break;
	case SSH_FXP_MKDIR:  ok = CreateDirectoryW(path, NULL); break;
	default:             ok = RemoveDirectoryW(path);      break;
	}
	if (!ok) return send_error(f, id, GetLastError());
	LOGF(TRACE_LEVEL_INFORMATION, "[%u] sftp: %s '%S'", f->io->session_id,
		type == SSH_FXP_REMOVE ? "removed" : type == SSH_FXP_MKDIR ? "created directory" : "removed directory", path);
	return send_ok(f, id);
}

static int sftp_rename(Sftp *f, uint32_t id, size_t off)
{
	wchar_t from[MAX_PATH], to[MAX_PATH];
	int     r1 = get_path(f, &off, from);
	int     r2 = r1 == -2 ? -2 : get_path(f, &off, to);
	if (r1 == -2 || r2 == -2) return send_status(f, id, SSH_FX_BAD_MESSAGE, "Bad message");
	if (r1 != 0 || r2 != 0) return send_error(f, id, ERROR_BAD_PATHNAME);
	if (!MoveFileExW(from, to, MOVEFILE_COPY_ALLOWED)) return send_error(f, id, GetLastError());
	LOGF(TRACE_LEVEL_INFORMATION, "[%u] sftp: renamed '%S' to '%S'", f->io->session_id, from, to);
	return send_ok(f, id);
}

static int sftp_realpath(Sftp *f, uint32_t id, size_t off)
{
	wchar_t path[MAX_PATH];
	char    disp[XPATH_U8 + 2];
	int     r = get_path(f, &off, path);

	if (r == -2) return send_status(f, id, SSH_FX_BAD_MESSAGE, "Bad message");
	if (r != 0) return send_error(f, id, ERROR_BAD_PATHNAME);
	path_display(path, disp, sizeof(disp));

	o_begin(f, SSH_FXP_NAME, id);
	o_u32(f, 1);
	o_cstr(f, disp);
	o_cstr(f, disp);
	o_u32(f, 0);   /* no attributes */
	return o_send(f);
}

/* Handle one request in f->in.  Returns -1 to end the session. */
static int sftp_dispatch(Sftp *f)
{
	uint8_t  type = f->in[0];
	uint32_t id;
	size_t   off = 1;

	if (type == SSH_FXP_INIT) {
		uint32_t version = 0;
		buf_get_u32_at(f->in, f->in_len, &off, &version);
		LOGF(TRACE_LEVEL_VERBOSE, "[%u] sftp: client version %u", f->io->session_id, version);
		f->out_len = 4;
		f->out_overflow = 0;
		o_u8(f, SSH_FXP_VERSION);
		o_u32(f, 3);
		return o_send(f);
	}
	if (buf_get_u32_at(f->in, f->in_len, &off, &id) != 0) return -1;

	switch (type) {
	case SSH_FXP_OPEN:      return sftp_open(f, id, off);
	case SSH_FXP_CLOSE:     return sftp_close(f, id, off);
	case SSH_FXP_READ:      return sftp_read(f, id, off);
	case SSH_FXP_WRITE:     return sftp_write(f, id, off);
	case SSH_FXP_LSTAT:
	case SSH_FXP_STAT:      return sftp_stat(f, id, off);
	case SSH_FXP_FSTAT:     return sftp_fstat(f, id, off);
	case SSH_FXP_SETSTAT:   return sftp_setstat(f, id, off);
	case SSH_FXP_FSETSTAT:  return sftp_fsetstat(f, id, off);
	case SSH_FXP_OPENDIR:   return sftp_opendir(f, id, off);
	case SSH_FXP_READDIR:   return sftp_readdir(f, id, off);
	case SSH_FXP_REMOVE:
	case SSH_FXP_MKDIR:
	case SSH_FXP_RMDIR:     return sftp_path_op(f, id, off, type);
	case SSH_FXP_REALPATH:  return sftp_realpath(f, id, off);
	case SSH_FXP_RENAME:    return sftp_rename(f, id, off);
	default:                /* READLINK, SYMLINK, EXTENDED... */
		LOGF(TRACE_LEVEL_VERBOSE, "[%u] sftp: unsupported request %u", f->io->session_id, type);
		return send_status(f, id, SSH_FX_OP_UNSUPPORTED, "Operation unsupported");
	}
}

int sftp_server_run(XferIO *io, const wchar_t *home)
{
	Sftp *f = (Sftp *)calloc(1, sizeof(Sftp));
	int   status = 0, i;

	if (!f || !(f->in = (uint8_t *)malloc(SFTP_MAX_MSG)) || !(f->out = (uint8_t *)malloc(SFTP_OUT_MAX))) {
		LOGF(TRACE_LEVEL_ERROR, "[%u] sftp: out of memory", io->session_id);
		if (f) {
			free(f->in);
			free(f);
		}
		return 1;
	}
	f->io = io;
	f->home = home;
	LOGF(TRACE_LEVEL_INFORMATION, "[%u] sftp session started", io->session_id);

	for (;;) {
		uint8_t  hdr[4];
		uint32_t len;
		int      r = io_read_exact(io, hdr, 4);
		if (r == 0) break;                         /* client closed its side */
		if (r < 0) {
			status = 1;
			break;
		}
		len = buf_get_u32(hdr);
		if (len < 1 || len > SFTP_MAX_MSG) {
			LOGF(TRACE_LEVEL_WARNING, "[%u] sftp: bad message length %u", io->session_id, len);
			status = 1;
			break;
		}
		if (io_read_exact(io, f->in, len) != 1) {
			status = 1;
			break;
		}
		f->in_len = len;
		if (sftp_dispatch(f) != 0) {
			status = 1;
			break;
		}
	}

	for (i = 0; i < SFTP_HANDLES; i++)
		if (f->h[i].kind) free_handle(&f->h[i]);
	LOGF(TRACE_LEVEL_INFORMATION, "[%u] sftp session ended", io->session_id);
	free(f->in);
	free(f->out);
	free(f);
	return status;
}

/* ================================================================== legacy SCP */

#define SCP_BUF       32768
#define SCP_LINE_MAX  (XPATH_U8 + 64)

typedef struct {
	XferIO        *io;
	const wchar_t *home;
	int            recursive, dir_required, preserve;
	int            errs;
	int            fatal;            /* connection unusable or protocol broken */
	uint8_t        rbuf[8192];
	size_t         rpos, rlen;
	uint8_t        data[SCP_BUF];
} Scp;

static int scp_getc(Scp *p)
{
	if (p->rpos == p->rlen) {
		int n = p->io->recv(p->io->ctx, p->rbuf, sizeof(p->rbuf));
		if (n <= 0) return -1;
		p->rpos = 0;
		p->rlen = (size_t)n;
	}
	return p->rbuf[p->rpos++];
}

static int scp_read(Scp *p, uint8_t *buf, size_t len)
{
	size_t n = p->rlen - p->rpos;
	if (n > len) n = len;
	memcpy(buf, p->rbuf + p->rpos, n);
	p->rpos += n;
	return io_read_exact(p->io, buf + n, len - n) == 1 ? 0 : -1;   /* len - n == 0 gives 1 */
}

/* Read up to '\n' (not stored).  Over-long lines are truncated.  -1 at EOF. */
static int scp_read_line(Scp *p, char *buf, size_t size)
{
	size_t n = 0;
	for (;;) {
		int ch = scp_getc(p);
		if (ch < 0) return -1;
		if (ch == '\n') break;
		if (n + 1 < size) buf[n++] = (char)ch;
	}
	buf[n] = 0;
	return (int)n;
}

static int scp_send(Scp *p, const void *data, size_t len)
{
	if (p->fatal) return -1;
	if (p->io->send(p->io->ctx, (const uint8_t *)data, len) != 0) {
		p->fatal = 1;
		return -1;
	}
	return 0;
}

static int scp_ack(Scp *p)
{
	return scp_send(p, "", 1);
}

/* Report a (non-fatal) error to the client: "\1scp: message\n". */
static void scp_err(Scp *p, const char *fmt, ...)
{
	char    msg[SCP_LINE_MAX];
	char    line[SCP_LINE_MAX + 8];
	va_list ap;
	int     n;

	va_start(ap, fmt);
	_vsnprintf_s(msg, sizeof(msg), _TRUNCATE, fmt, ap);
	va_end(ap);
	p->errs++;
	LOGF(TRACE_LEVEL_WARNING, "[%u] scp: %s", p->io->session_id, msg);
	n = _snprintf_s(line, sizeof(line), _TRUNCATE, "\x01scp: %s\n", msg);
	if (n < 0) n = (int)strlen(line);
	scp_send(p, line, (size_t)n);
}

/* Read the client's answer: 0 OK, -1 error (reported by the client). */
static int scp_response(Scp *p)
{
	char line[SCP_LINE_MAX];
	int  ch = scp_getc(p);
	if (ch == 0) return 0;
	if (ch == 1 || ch == 2) {
		if (scp_read_line(p, line, sizeof(line)) < 0) p->fatal = 1;
		else LOGF(TRACE_LEVEL_WARNING, "[%u] scp: client: %s", p->io->session_id, line);
		if (ch == 2) p->fatal = 1;
		return -1;
	}
	p->fatal = 1;   /* EOF or garbage */
	return -1;
}

/* Parse "C0644 1234 name" / "D0755 0 name" (without the letter). */
static int scp_parse_header(const char *s, uint64_t *size, const char **name)
{
	int i;
	for (i = 0; i < 4; i++)
		if (s[i] < '0' || s[i] > '7') return -1;
	if (s[4] != ' ') return -1;
	s += 5;
	if (*s < '0' || *s > '9') return -1;
	*size = 0;
	while (*s >= '0' && *s <= '9') {
		if (*size > (0xFFFFFFFFFFFFFFFFULL - 9) / 10) return -1;
		*size = *size * 10 + (uint64_t)(*s++ - '0');
	}
	if (*s++ != ' ') return -1;
	*name = s;
	return 0;
}

static int scp_valid_name(const char *name)
{
	if (!*name || strcmp(name, ".") == 0 || strcmp(name, "..") == 0) return 0;
	for (; *name; name++)
		if (*name == '/' || *name == '\\' || *name == ':' || (unsigned char)*name < 0x20) return 0;
	return 1;
}

typedef struct {
	wchar_t path[MAX_PATH];
	wchar_t wname[MAX_PATH];
	char    line[SCP_LINE_MAX];
} SinkFrame;

/* Receive files into target (an absolute path).  Returns -1 when fatal. */
static int scp_sink(Scp *p, const wchar_t *target, int top)
{
	SinkFrame *fr = (SinkFrame *)malloc(sizeof(SinkFrame));
	FInfo      fi;
	int        targetisdir, have_times = 0, rc = 0;
	uint32_t   mtime = 0, atime = 0;

	if (!fr) {
		scp_err(p, "out of memory");
		p->fatal = 1;
		return -1;
	}
	targetisdir = finfo_path(target, &fi) == 0 && is_dir(&fi);
	if (top && p->dir_required && !targetisdir) {
		char u8[XPATH_U8];
		w_to_u8(target, u8, sizeof(u8));
		scp_err(p, "%s: Not a directory", u8);
		p->fatal = 1;
		free(fr);
		return -1;
	}
	if (scp_ack(p) != 0) {
		free(fr);
		return -1;
	}

	for (;;) {
		const char *name;
		uint64_t    size;
		int         ch = scp_getc(p);

		if (ch < 0) {                              /* end of input */
			if (!top) p->fatal = 1;
			break;
		}
		if (ch == 1 || ch == 2) {                  /* error from the client */
			if (scp_read_line(p, fr->line, sizeof(fr->line)) < 0 || ch == 2) p->fatal = 1;
			else LOGF(TRACE_LEVEL_WARNING, "[%u] scp: client: %s", p->io->session_id, fr->line);
			if (p->fatal) break;
			continue;
		}
		if (scp_read_line(p, fr->line, sizeof(fr->line)) < 0) {
			p->fatal = 1;
			break;
		}
		if (ch == 'E') {                           /* end of directory */
			scp_ack(p);
			break;
		}
		if (ch == 'T') {
			unsigned long m, mu, a, au;
			if (sscanf_s(fr->line, "%lu %lu %lu %lu", &m, &mu, &a, &au) != 4) {
				scp_err(p, "protocol error: bad time record");
				p->fatal = 1;
				break;
			}
			mtime = (uint32_t)m;
			atime = (uint32_t)a;
			have_times = 1;
			scp_ack(p);
			continue;
		}
		if ((ch != 'C' && ch != 'D') || scp_parse_header(fr->line, &size, &name) != 0) {
			scp_err(p, "protocol error: expected control record");
			p->fatal = 1;
			break;
		}
		if (!scp_valid_name(name) || u8_to_w(name, strlen(name), fr->wname, MAX_PATH) < 0) {
			scp_err(p, "%s: unexpected filename", name);
			p->fatal = 1;
			break;
		}
		if (targetisdir) {
			if (path_join(target, fr->wname, fr->path, MAX_PATH) != 0) {
				scp_err(p, "%s: File name too long", name);
				p->fatal = 1;   /* the client would send the data anyway */
				break;
			}
		} else {
			wcscpy_s(fr->path, MAX_PATH, target);
		}

		if (ch == 'D') {
			if (!p->recursive) {
				scp_err(p, "received directory without -r");
				p->fatal = 1;
				break;
			}
			if (finfo_path(fr->path, &fi) == 0) {
				if (!is_dir(&fi)) {
					scp_err(p, "%s: Not a directory", name);
					have_times = 0;
					continue;
				}
			} else if (!CreateDirectoryW(fr->path, NULL)) {
				scp_err(p, "%s: %s", name, err_text(GetLastError()));
				have_times = 0;
				continue;
			} else {
				LOGF(TRACE_LEVEL_INFORMATION, "[%u] scp: created directory '%S'", p->io->session_id, fr->path);
			}
			if (scp_sink(p, fr->path, 0) != 0) break;
			if (have_times) set_times(fr->path, NULL, atime, mtime);
			have_times = 0;
			continue;
		}

		/* 'C': a file */
		{
			HANDLE   h = CreateFileW(fr->path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS,
				FILE_ATTRIBUTE_NORMAL, NULL);
			DWORD    write_err = 0;
			uint64_t left = size;

			if (h == INVALID_HANDLE_VALUE) {
				scp_err(p, "%s: %s", name, err_text(GetLastError()));   /* the client skips the data */
				have_times = 0;
				continue;
			}
			if (scp_ack(p) != 0) {
				CloseHandle(h);
				break;
			}
			while (left > 0) {
				DWORD n = left > SCP_BUF ? SCP_BUF : (DWORD)left, written;
				if (scp_read(p, p->data, n) != 0) {
					p->fatal = 1;
					break;
				}
				if (!write_err && (!WriteFile(h, p->data, n, &written, NULL) || written != n))
					write_err = GetLastError() ? GetLastError() : ERROR_HANDLE_DISK_FULL;
				left -= n;
			}
			if (p->fatal) {
				CloseHandle(h);
				DeleteFileW(fr->path);   /* incomplete */
				break;
			}
			if (have_times && !write_err) set_times(NULL, h, atime, mtime);
			CloseHandle(h);
			have_times = 0;

			scp_response(p);                    /* the client's status after the data */
			if (p->fatal) break;
			if (write_err) {
				scp_err(p, "%s: %s", name, err_text(write_err));
			} else {
				scp_ack(p);
				LOGF(TRACE_LEVEL_INFORMATION, "[%u] scp: received '%S' (%llu bytes)",
					p->io->session_id, fr->path, (unsigned long long)size);
			}
		}
	}

	if (p->fatal) rc = -1;
	free(fr);
	return rc;
}

static void scp_send_path(Scp *p, const wchar_t *path, const wchar_t *name);

typedef struct {
	WIN32_FIND_DATAW fd;
	wchar_t          path[MAX_PATH + 4];
	char             line[SCP_LINE_MAX];
} SourceFrame;

/* Send a directory and its content (recursive mode). */
static void scp_rsource(Scp *p, const wchar_t *dir, const char *name, const FInfo *fi)
{
	SourceFrame *fr = (SourceFrame *)malloc(sizeof(SourceFrame));
	HANDLE       hFind;
	int          n;

	if (!fr) {
		scp_err(p, "out of memory");
		return;
	}
	if (p->preserve) {
		n = _snprintf_s(fr->line, sizeof(fr->line), _TRUNCATE, "T%lu 0 %lu 0\n",
			(unsigned long)ft_to_unix(fi->mtime), (unsigned long)ft_to_unix(fi->atime));
		if (scp_send(p, fr->line, (size_t)n) != 0 || scp_response(p) != 0) goto out;
	}
	n = _snprintf_s(fr->line, sizeof(fr->line), _TRUNCATE, "D0755 0 %s\n", name);
	if (n < 0 || scp_send(p, fr->line, (size_t)n) != 0 || scp_response(p) != 0) goto out;

	if (path_join(dir, L"*", fr->path, _countof(fr->path)) == 0) {
		hFind = FindFirstFileExW(fr->path, FindExInfoBasic, &fr->fd, FindExSearchNameMatch, NULL, 0);
		if (hFind != INVALID_HANDLE_VALUE) {
			do {
				if (wcscmp(fr->fd.cFileName, L".") == 0 || wcscmp(fr->fd.cFileName, L"..") == 0) continue;
				if (path_join(dir, fr->fd.cFileName, fr->path, MAX_PATH) != 0) {
					char u8[XPATH_U8];
					w_to_u8(fr->fd.cFileName, u8, sizeof(u8));
					scp_err(p, "%s: File name too long", u8);
					continue;
				}
				scp_send_path(p, fr->path, fr->fd.cFileName);
			} while (!p->fatal && FindNextFileW(hFind, &fr->fd));
			FindClose(hFind);
		}
	}
	if (scp_send(p, "E\n", 2) == 0) scp_response(p);
out:
	free(fr);
}

/* Send one file, or a directory if recursive. */
static void scp_send_path(Scp *p, const wchar_t *path, const wchar_t *wname)
{
	char     name[XPATH_U8], disp[XPATH_U8];
	char     line[SCP_LINE_MAX];
	FInfo    fi;
	HANDLE   h;
	uint64_t left;
	DWORD    read_err = 0;
	int      n;

	if (p->fatal) return;
	if (w_to_u8(path, disp, sizeof(disp)) < 0 || w_to_u8(wname, name, sizeof(name)) < 0) {
		scp_err(p, "invalid file name");
		return;
	}
	if (finfo_path(path, &fi) != 0) {
		scp_err(p, "%s: %s", disp, err_text(GetLastError()));
		return;
	}
	if (is_dir(&fi)) {
		if (p->recursive) scp_rsource(p, path, name, &fi);
		else scp_err(p, "%s: not a regular file", disp);
		return;
	}

	h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL, NULL);
	if (h == INVALID_HANDLE_VALUE) {
		scp_err(p, "%s: %s", disp, err_text(GetLastError()));
		return;
	}
	finfo_handle(h, &fi);

	if (p->preserve) {
		n = _snprintf_s(line, sizeof(line), _TRUNCATE, "T%lu 0 %lu 0\n",
			(unsigned long)ft_to_unix(fi.mtime), (unsigned long)ft_to_unix(fi.atime));
		if (scp_send(p, line, (size_t)n) != 0 || scp_response(p) != 0) {
			CloseHandle(h);
			return;
		}
	}
	n = _snprintf_s(line, sizeof(line), _TRUNCATE, "C%04o %llu %s\n",
		(unsigned)(unix_mode(&fi) & 0777), (unsigned long long)fi.size, name);
	if (n < 0 || scp_send(p, line, (size_t)n) != 0 || scp_response(p) != 0) {
		CloseHandle(h);
		return;
	}

	for (left = fi.size; left > 0; ) {
		DWORD chunk = left > SCP_BUF ? SCP_BUF : (DWORD)left, got = 0;
		if (!read_err && (!ReadFile(h, p->data, chunk, &got, NULL) || got != chunk)) {
			read_err = GetLastError() ? GetLastError() : ERROR_HANDLE_EOF;
			if (got > chunk) got = 0;
		}
		if (read_err) memset(p->data + got, 0, chunk - got);   /* keep the stream in sync */
		if (scp_send(p, p->data, chunk) != 0) break;
		left -= chunk;
	}
	CloseHandle(h);
	if (p->fatal) return;

	if (read_err) {
		scp_err(p, "%s: read error (%lu)", disp, read_err);
	} else {
		scp_ack(p);
		LOGF(TRACE_LEVEL_INFORMATION, "[%u] scp: sent '%S' (%llu bytes)",
			p->io->session_id, path, (unsigned long long)fi.size);
	}
	scp_response(p);
}

/* Source mode: send the file(s) named by arg (the last component may contain * and ?). */
static void scp_source(Scp *p, const char *arg)
{
	wchar_t          path[MAX_PATH], dir[MAX_PATH], full[MAX_PATH];
	const wchar_t   *last;
	WIN32_FIND_DATAW fd;
	HANDLE           hFind;
	int              found = 0;

	if (path_resolve_u8(p->home, arg, strlen(arg), path, MAX_PATH) != 0) {
		scp_err(p, "%s: No such file or directory", arg);
		return;
	}
	last = wcsrchr(path, L'\\');
	last = last ? last + 1 : path;

	if (!wcspbrk(last, L"*?")) {
		if (*last == 0) {
			scp_err(p, "%s: not a regular file", arg);   /* a drive root */
			return;
		}
		scp_send_path(p, path, last);
		return;
	}

	wcsncpy_s(dir, MAX_PATH, path, (size_t)(last - path));
	hFind = FindFirstFileExW(path, FindExInfoBasic, &fd, FindExSearchNameMatch, NULL, 0);
	if (hFind != INVALID_HANDLE_VALUE) {
		do {
			if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
			if (path_join(dir, fd.cFileName, full, MAX_PATH) != 0) continue;
			found = 1;
			scp_send_path(p, full, fd.cFileName);
		} while (!p->fatal && FindNextFileW(hFind, &fd));
		FindClose(hFind);
	}
	if (!found && !p->fatal) scp_err(p, "%s: No such file or directory", arg);
}

int scp_is_command(const char *command)
{
	size_t n = 0;
	while (*command == ' ' || *command == '\t') command++;
	while (command[n] && command[n] != ' ' && command[n] != '\t') n++;
	if (n == 3 && _strnicmp(command, "scp", 3) == 0) return 1;
	if (n == 7 && _strnicmp(command, "scp.exe", 7) == 0) return 1;
	if (n > 4 && _strnicmp(command + n - 4, "/scp", 4) == 0) return 1;
	if (n > 4 && _strnicmp(command + n - 4, "\\scp", 4) == 0) return 1;
	return 0;
}

int scp_server_run(XferIO *io, const char *command, const wchar_t *home)
{
	Scp        *p = (Scp *)calloc(1, sizeof(Scp));
	const char *s = command;
	char        arg[XPATH_U8];
	size_t      an = 0;
	int         sink = 0, source = 0, status;

	if (!p) return 1;
	p->io = io;
	p->home = home;

	/* program name */
	while (*s == ' ' || *s == '\t') s++;
	while (*s && *s != ' ' && *s != '\t') s++;

	/* options */
	for (;;) {
		while (*s == ' ' || *s == '\t') s++;
		if (s[0] != '-') break;
		if (s[1] == '-' && (s[2] == 0 || s[2] == ' ' || s[2] == '\t')) {
			s += 2;
			while (*s == ' ' || *s == '\t') s++;
			break;
		}
		for (s++; *s && *s != ' ' && *s != '\t'; s++) {
			switch (*s) {
			case 't': sink = 1;            break;
			case 'f': source = 1;          break;
			case 'r': p->recursive = 1;    break;
			case 'd': p->dir_required = 1; break;
			case 'p': p->preserve = 1;     break;
			default:                       break;   /* -v, -q, ... */
			}
		}
	}

	/* The rest is the path, spaces included (OpenSSH does not quote it);
	 * one pair of surrounding quotes is removed */
	for (; *s && an + 1 < sizeof(arg); s++) arg[an++] = *s;
	while (an > 0 && (arg[an - 1] == ' ' || arg[an - 1] == '\t' || arg[an - 1] == '\r' || arg[an - 1] == '\n')) an--;
	arg[an] = 0;
	if (an >= 2 && (arg[0] == '"' || arg[0] == '\'') && arg[an - 1] == arg[0]) {
		memmove(arg, arg + 1, an - 2);
		an -= 2;
		arg[an] = 0;
	}
	if (an == 0) strcpy_s(arg, sizeof(arg), ".");

	LOGF(TRACE_LEVEL_INFORMATION, "[%u] scp %s%s%s '%s'", io->session_id,
		sink ? "upload to" : source ? "download of" : "?",
		p->recursive ? " (recursive)" : "", p->preserve ? " (preserve times)" : "", arg);

	if (sink == source) {
		scp_err(p, "expected exactly one of -t and -f");
	} else if (sink) {
		wchar_t target[MAX_PATH];
		if (path_resolve_u8(home, arg, an, target, MAX_PATH) != 0) {
			scp_err(p, "%s: No such file or directory", arg);
		} else {
			scp_sink(p, target, 1);
		}
	} else {
		if (scp_response(p) == 0) scp_source(p, arg);   /* the client starts with "\0" */
	}

	status = (p->errs || p->fatal) ? 1 : 0;
	free(p);
	return status;
}
