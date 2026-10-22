#ifndef HELIOS_UNIX_TLS_FD_H
#define HELIOS_UNIX_TLS_FD_H
#include <sys/types.h>
#include <sys/time.h>
#include <helios/unix/tls.h>
/* Legacy select/fd application adapter. Application descriptors are keys for
 * TLS objects, NOT encrypted OS descriptors. Route read/write/select/close
 * through this adapter; ordinary files and plaintext sockets pass through.
 * Do not dup, fdopen, send/recv or transfer an attached fd to another task.
 * Per-task, single event loop; close removes its entry before fd reuse. */
int hu_tls_fd_attach(int fd,struct hu_tls *); /* takes TLS+fd on success only */
struct hu_tls *hu_tls_fd_get(int fd); /* borrowed, NULL for plaintext */
/* Takes fd on entry. Setup failures close it; handshake failures leave a
 * failed TLS entry for close(). An already attached fd is left intact. */
int hu_tls_fd_start(int fd,const char *peer,unsigned timeout_ms);
int hu_tls_fd_handshake(int fd,struct hu_tls_info *);
int hu_tls_fd_connect(int fd,const char *peer,unsigned timeout_ms,struct hu_tls_info *);
int hu_tls_fd_read(int fd,void *,unsigned);
int hu_tls_fd_write(int fd,const void *,unsigned);
/* Established sessions drain TLS shutdown for at most five seconds, then
 * release the fd even on error; do not retry close. Negotiation is cancelled. */
int hu_tls_fd_close(int fd);
int hu_tls_fd_select(int,fd_set *,fd_set *,fd_set *,struct timeval *);
#endif
