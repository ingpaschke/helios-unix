#ifndef HELIOS_UNIX_SSH_BACKEND_H
#define HELIOS_UNIX_SSH_BACKEND_H
#include <helios/unix/ssh.h>
/* Byte transports need not be sockets. control is optional for a native
 * engine; the supplied offload provider uses it for its private wire ABI. */
struct hu_ssh_transport_ops {
    int (*read)(void *, void *, unsigned);
    int (*write)(void *, const void *, unsigned);
    int (*wait_fd)(void *);
    int (*control)(void *, int, void *, unsigned *);
    void (*close)(void *);
};
struct hu_ssh_transport { const struct hu_ssh_transport_ops *ops; void *context; };
struct hu_ssh_backend {
    unsigned version;
    const char *name;
    void *(*open)(const struct hu_ssh_options *, const struct hu_ssh_transport *);
    int (*status)(void *, struct hu_ssh_info *);
    int (*trust)(void *, int);
    int (*authenticate)(void *, const struct hu_ssh_auth *);
    int (*resize)(void *, unsigned, unsigned);
    int (*read)(void *, void *, unsigned);
    int (*write)(void *, const void *, unsigned);
    int (*eof)(void *);
    int (*interest)(void *, int, struct hu_ssh_wait *);
    /* Free engine state only; the core closes the owned transport. */
    void (*destroy)(void *);
};
extern const struct hu_ssh_backend hu_ssh_offload_backend;
#endif
