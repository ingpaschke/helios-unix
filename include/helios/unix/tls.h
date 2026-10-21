#ifndef HELIOS_UNIX_TLS_H
#define HELIOS_UNIX_TLS_H
/* Backend-independent client TLS. No /internet or socket upgrade contract.
 * All application data must pass through this object, including on hosts
 * which offload encryption. Calls are nonblocking; errno EAGAIN means retry
 * when hu_tls_interest says so (a read can need WRITE, and vice versa).
 * Objects are single-owner/event-loop objects, not concurrently callable. */
#define HU_TLS_NEGOTIATING 1
#define HU_TLS_READY 2
#define HU_TLS_FAILED 3
#define HU_TLS_CLOSED 4
#define HU_TLS_READ 1
#define HU_TLS_WRITE 2
#define HU_TLS_HANDSHAKE 3
#define HU_TLS_SHUTDOWN 4
#define HU_TLS_WAIT_READ 1
#define HU_TLS_WAIT_WRITE 2
struct hu_tls_info {
    unsigned state,error;
    char protocol[16],cipher[64],message[128];
};
struct hu_tls;
struct hu_tls_backend;
struct hu_tls_transport;
struct hu_tls_wait { int fd,events,timeout_ms; }; /* timeout -1: no timer */
/* NULL backend selects the build's default, currently host offload. Native
 * engines can be supplied explicitly; selection never falls back to plaintext.
 * peer is copied; backend and configuration must outlive the object. */
struct hu_tls *hu_tls_create(const struct hu_tls_backend *backend,
    const void *configuration,const char *peer,unsigned timeout_ms);
/* Transfer transport ownership on success only; attach once. A native engine
 * uses its byte I/O callbacks. Only the offload backend needs optional control. */
int hu_tls_attach(struct hu_tls *,const struct hu_tls_transport *);
/* Convenience transport for a connected fd. Takes ownership on success,
 * makes it nonblocking, and does not register a legacy fd adapter entry. */
int hu_tls_attach_fd(struct hu_tls *,int fd);
int hu_tls_handshake(struct hu_tls *); /* 1 ready, 0 pending, -1 failed */
int hu_tls_read(struct hu_tls *,void *,unsigned);
int hu_tls_write(struct hu_tls *,const void *,unsigned);
unsigned hu_tls_pending(struct hu_tls *); /* decrypted bytes, not wire bytes */
int hu_tls_info(struct hu_tls *,struct hu_tls_info *);
int hu_tls_interest(struct hu_tls *,int operation,struct hu_tls_wait *);
int hu_tls_wait(struct hu_tls *,int operation,int timeout_ms);
int hu_tls_handshake_wait(struct hu_tls *);
/* Shutdown sends accepted data and close_notify; retry while pending.
 * destroy cancels immediately and releases the owned transport exactly once. */
int hu_tls_shutdown(struct hu_tls *); /* 1 complete, 0 pending, -1 failed */
void hu_tls_destroy(struct hu_tls *);
#endif
