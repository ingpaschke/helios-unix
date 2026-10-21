#ifndef HELIOS_UNIX_POLL_H
#define HELIOS_UNIX_POLL_H
/* Restricted native API: sockets, native channel FIFOs and regular files.
 * Uses native readiness subscriptions rather than periodic network RPCs.
 * Other object classes
 * fail with EOPNOTSUPP until their hangup/error protocols are qualified. */
struct hu_pollfd {int fd;short events,revents;};
#define HU_POLLIN 1
#define HU_POLLOUT 2
#define HU_POLLPRI 4
#define HU_POLLERR 8
#define HU_POLLHUP 16
#define HU_POLLNVAL 32
int hu_poll(struct hu_pollfd *,unsigned,int);
#endif
