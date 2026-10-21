#ifndef HELIOS_UNIX_TLS_BACKEND_H
#define HELIOS_UNIX_TLS_BACKEND_H
#include <helios/unix/tls.h>
/* Provider interface, not required by applications. Byte callbacks are
 * nonblocking, returning -1/EAGAIN when unavailable. wait_fd supplies one
 * select-compatible descriptor (socket, FIFO, etc.), never an IP requirement.
 * control is optional: native TLS must work without it. close owns context.
 * A transport is copied into the TLS object; context must remain valid. */
struct hu_tls_transport_ops {
    int (*read)(void *,void *,unsigned);
    int (*write)(void *,const void *,unsigned);
    int (*wait_fd)(void *);
    int (*control)(void *,int,void *,unsigned);
    void (*close)(void *);
};
struct hu_tls_transport { const struct hu_tls_transport_ops *ops;void *context; };
struct hu_tls_options { const char *peer;unsigned timeout_ms;const void *configuration; };
/* version must be 1. create must not send bytes. handshake returns 1 only
 * after authenticating peer and validating the chain. read/write follow the
 * public API; on EAGAIN set *want to READ, WRITE or both. handshake/shutdown
 * return 0 pending and set *want; timer_ms supplies protocol timer wakeups
 * (including offload status polling), -1 if none. pending counts plaintext.
 * destroy frees engine state but must NOT close the borrowed transport.
 * Backend configuration carries trust, entropy, clock and engine policy;
 * native implementations must reject missing required services, not weaken
 * verification. The core copies options/transport; both outlive engine. */
struct hu_tls_backend {
    unsigned version;
    const char *name;
    void *(*create)(const struct hu_tls_options *,const struct hu_tls_transport *);
    int (*handshake)(void *,int *want);
    int (*read)(void *,void *,unsigned,int *want);
    int (*write)(void *,const void *,unsigned,int *want);
    unsigned (*pending)(void *);
    int (*shutdown)(void *,int *want);
    int (*timer_ms)(void *,int operation);
    void (*info)(void *,struct hu_tls_info *);
    void (*destroy)(void *);
};
extern const struct hu_tls_backend hu_tls_offload_backend;
/* Optional transport controls used solely by host offload. No native engine
 * is required to implement these. The socket transport encodes HTL1 privately. */
#define HU_TLS_CTL_START 1
#define HU_TLS_CTL_STATUS 2
#define HU_TLS_CTL_SHUTDOWN 3
struct hu_tls_offload_start { const char *peer;unsigned timeout_ms; };
#endif
