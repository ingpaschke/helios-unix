#ifndef HELIOS_UNIX_CHANNEL_H
#define HELIOS_UNIX_CHANNEL_H
/* Unidirectional byte stream backed by Helios's native /fifo message service.
 * fds[0] reads, fds[1] writes. No PIPE_BUF atomicity or POSIX pipe claim.
 * Bounded 16 KiB buffering; endpoint references survive native spawn.
 * One producer and one consumer; no TCP stack or io-server socket involved. */
int hu_channel(int fds[2]);
#endif
