#ifndef HELIOS_UNIX_RESOLVE_H
#define HELIOS_UNIX_RESOLVE_H
#include <helios/unix/spawn.h>
#define HU_RESOLVE_WIRE_SIZE 392
struct hu_resolve_result {int error,count;unsigned char addresses[32][4];char canonical[256];};
/* Spawn helper with fd as stdout. Caller owns fd and reaps/cancels the PID
 * using native waitpid/kill. The helper receives values, never pointers. */
int hu_resolve_launch(pid_t *,int,const char *,int,const struct hu_spawn_attr *);
int hu_resolve_send(int,const char *,int);
/* Call after readiness. Bounds a fragmented reply to two seconds. */
int hu_resolve_receive(int,struct hu_resolve_result *);
#endif
