#ifndef HELIOS_UNIX_PIPE_H
#define HELIOS_UNIX_PIPE_H
/* Eagerly connected native Helios pipe, using the existing 2 KiB buffer.
 * Single producer/consumer profile; not a claim of full POSIX pipe semantics. */
int hu_pipe(int [2]);
#endif
