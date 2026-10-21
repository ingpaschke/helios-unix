#ifndef HELIOS_UNIX_API_H
#define HELIOS_UNIX_API_H
/* Native Helios ABI. Include this consistently in an opted-in application. */
#include <sys/types.h>
struct termios;
#define HU_ABI_VERSION 1
#define HU_VERSION "0.1-dev"
int hu_set_nonblock(int fd, int enabled);
int hu_terminal_size(int fd, unsigned *rows, unsigned *columns);
int hu_terminal_raw(int fd, struct termios *saved);
int hu_terminal_restore(int fd, const struct termios *saved);
/* Explicit input profile. Raw reads elsewhere never translate bytes. */
struct hu_terminal_decoder {unsigned utf8_remaining;int helios_c1;};
int hu_terminal_read(int fd,struct hu_terminal_decoder *,char *,int);
#endif
