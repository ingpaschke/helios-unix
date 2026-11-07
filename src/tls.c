#include <helios/unix/tls_backend.h>
#include <sys/types.h>
#include <sys/time.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#ifndef HU_TLS_DEFAULT_BACKEND
#define HU_TLS_DEFAULT_BACKEND hu_tls_offload_backend
#endif
extern const struct hu_tls_backend HU_TLS_DEFAULT_BACKEND;

struct hu_tls {
    const struct hu_tls_backend *backend;
    struct hu_tls_options options;
    struct hu_tls_transport transport;
    void *engine;
    char peer[256];
    unsigned state;
    int want[5], failure, closing;
    struct timeval started;
};

static int remaining(struct hu_tls *tls)
{
    struct timeval now;
    long elapsed;
    gettimeofday(&now, 0);
    elapsed = (now.tv_sec - tls->started.tv_sec) * 1000 +
              (now.tv_usec - tls->started.tv_usec) / 1000;
    if (elapsed < 0) {
        elapsed = 0;
    }
    return elapsed >= (long)tls->options.timeout_ms ? 0
                                                    : tls->options.timeout_ms - elapsed;
}

static int failed(struct hu_tls *tls, int error)
{
    tls->state = HU_TLS_FAILED;
    tls->failure = error ? error : EIO;
    errno = tls->failure;
    return -1;
}

struct hu_tls *hu_tls_create(const struct hu_tls_backend *backend, const void *config,
                             const char *peer, unsigned timeout)
{
    struct hu_tls *tls;
    if (!backend) {
        backend = &HU_TLS_DEFAULT_BACKEND;
    }
    if (!peer || !*peer || strlen(peer) > 255 || timeout < 100 || timeout > 120000 ||
        backend->version != 1 || !backend->create || !backend->handshake ||
        !backend->read || !backend->write || !backend->pending || !backend->shutdown ||
        !backend->timer_ms || !backend->info || !backend->destroy) {
        errno = EINVAL;
        return NULL;
    }
    tls = calloc(1, sizeof(*tls));
    if (!tls) {
        errno = ENOMEM;
        return NULL;
    }
    strcpy(tls->peer, peer);
    tls->options.peer = tls->peer;
    tls->options.timeout_ms = timeout;
    tls->options.configuration = config;
    tls->backend = backend;
    tls->state = HU_TLS_NEGOTIATING;
    tls->want[HU_TLS_READ] = HU_TLS_WAIT_READ;
    tls->want[HU_TLS_WRITE] = HU_TLS_WAIT_WRITE;
    return tls;
}

int hu_tls_attach(struct hu_tls *tls, const struct hu_tls_transport *transport)
{
    if (!tls || tls->engine || !transport || !transport->ops || !transport->ops->read ||
        !transport->ops->write || !transport->ops->wait_fd || !transport->ops->close) {
        errno = EINVAL;
        return -1;
    }
    tls->transport = *transport;
    tls->engine = tls->backend->create(&tls->options, &tls->transport);
    if (!tls->engine) {
        memset(&tls->transport, 0, sizeof(tls->transport));
        return -1;
    }
    gettimeofday(&tls->started, 0);
    return 0;
}

int hu_tls_handshake(struct hu_tls *tls)
{
    int result;
    if (!tls || !tls->engine) {
        errno = EINVAL;
        return -1;
    }
    if (tls->state == HU_TLS_READY && !tls->closing) {
        return 1;
    }
    if (tls->state != HU_TLS_NEGOTIATING) {
        errno = tls->failure ? tls->failure : EPIPE;
        return -1;
    }
    if (!remaining(tls)) {
        return failed(tls, ETIMEDOUT);
    }
    result = tls->backend->handshake(tls->engine, &tls->want[HU_TLS_HANDSHAKE]);
    if (result < 0) {
        return failed(tls, errno);
    }
    if (result > 0) {
        tls->state = HU_TLS_READY;
    }
    return result > 0 ? 1 : 0;
}

static int usable(struct hu_tls *tls)
{
    if (!tls || !tls->engine) {
        errno = EINVAL;
        return 0;
    }
    if (tls->state == HU_TLS_FAILED) {
        errno = tls->failure;
        return 0;
    }
    if (tls->state == HU_TLS_NEGOTIATING) {
        errno = EAGAIN;
        return 0;
    }
    return 1;
}

int hu_tls_read(struct hu_tls *tls, void *buf, unsigned size)
{
    int result;
    if (!usable(tls)) {
        return -1;
    }
    if (!size) {
        return 0;
    }
    if (!buf) {
        errno = EINVAL;
        return -1;
    }
    if (tls->state == HU_TLS_CLOSED) {
        return 0;
    }
    tls->want[HU_TLS_READ] = HU_TLS_WAIT_READ;
    result = tls->backend->read(tls->engine, buf, size, &tls->want[HU_TLS_READ]);
    if (result < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
        return failed(tls, errno);
    }
    if (!result) {
        tls->state = HU_TLS_CLOSED;
    }
    return result;
}

int hu_tls_write(struct hu_tls *tls, const void *buf, unsigned size)
{
    int result;
    if (!usable(tls)) {
        return -1;
    }
    if (tls->closing || tls->state == HU_TLS_CLOSED) {
        errno = EPIPE;
        return -1;
    }
    if (!size) {
        return 0;
    }
    if (!buf) {
        errno = EINVAL;
        return -1;
    }
    tls->want[HU_TLS_WRITE] = HU_TLS_WAIT_WRITE;
    result = tls->backend->write(tls->engine, buf, size, &tls->want[HU_TLS_WRITE]);
    if (!result) {
        return failed(tls, EPIPE);
    }
    if (result < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
        return failed(tls, errno);
    }
    return result;
}

unsigned hu_tls_pending(struct hu_tls *tls)
{
    return tls && tls->engine && tls->state == HU_TLS_READY
               ? tls->backend->pending(tls->engine)
               : 0;
}

int hu_tls_info(struct hu_tls *tls, struct hu_tls_info *info)
{
    if (!tls || !info) {
        errno = EINVAL;
        return -1;
    }
    memset(info, 0, sizeof(*info));
    if (tls->engine) {
        tls->backend->info(tls->engine, info);
    }
    info->state = tls->state;
    if (tls->failure && !info->message[0]) {
        strncpy(info->message, strerror(tls->failure), sizeof(info->message) - 1);
        info->error = tls->failure == ETIMEDOUT ? 4 : tls->failure == EACCES ? 2 : 1;
    }
    return 0;
}

int hu_tls_interest(struct hu_tls *tls, int op, struct hu_tls_wait *wait)
{
    int remaining_ms;
    if (!tls || !tls->engine || !wait || op < 1 || op > 4) {
        errno = EINVAL;
        return -1;
    }
    wait->fd = tls->transport.ops->wait_fd(tls->transport.context);
    wait->events = tls->want[op];
    wait->timeout_ms = tls->backend->timer_ms(tls->engine, op);
    if (tls->state == HU_TLS_FAILED || tls->state == HU_TLS_CLOSED ||
        (op == HU_TLS_READ && hu_tls_pending(tls))) {
        wait->timeout_ms = 0;
    }
    if (op == HU_TLS_HANDSHAKE) {
        if (tls->state == HU_TLS_READY) {
            wait->timeout_ms = 0;
        } else {
            remaining_ms = remaining(tls);
            if (wait->timeout_ms < 0 || remaining_ms < wait->timeout_ms) {
                wait->timeout_ms = remaining_ms;
            }
        }
    }
    return 0;
}

int hu_tls_wait(struct hu_tls *tls, int op, int timeout)
{
    struct hu_tls_wait wait;
    fd_set readfds, writefds;
    struct timeval tv;
    int result;
    if (timeout < -1) {
        errno = EINVAL;
        return -1;
    }
    if (hu_tls_interest(tls, op, &wait) < 0) {
        return -1;
    }
    if (wait.timeout_ms >= 0 && (timeout < 0 || wait.timeout_ms < timeout)) {
        timeout = wait.timeout_ms;
    }
    if (wait.fd < 0 || wait.fd >= FD_SETSIZE) {
        errno = EINVAL;
        return -1;
    }
    FD_ZERO(&readfds);
    FD_ZERO(&writefds);
    if (wait.events & HU_TLS_WAIT_READ) {
        FD_SET(wait.fd, &readfds);
    }
    if (wait.events & HU_TLS_WAIT_WRITE) {
        FD_SET(wait.fd, &writefds);
    }
    tv.tv_sec = timeout < 0 ? 0 : timeout / 1000;
    tv.tv_usec = timeout < 0 ? 0 : timeout % 1000 * 1000;
    result = select(wait.fd + 1, &readfds, &writefds, NULL, timeout < 0 ? NULL : &tv);
    if (result < 0) {
        return -1;
    }
    /* A provider timer is a reason to retry, not an application timeout. */
    return result > 0 || (wait.timeout_ms >= 0 && wait.timeout_ms == timeout) ? 1 : 0;
}

int hu_tls_handshake_wait(struct hu_tls *tls)
{
    int result;
    while ((result = hu_tls_handshake(tls)) == 0) {
        if (hu_tls_wait(tls, HU_TLS_HANDSHAKE, -1) < 0) {
            return -1;
        }
    }
    return result < 0 ? -1 : 0;
}

int hu_tls_shutdown(struct hu_tls *tls)
{
    int result;
    if (!usable(tls)) {
        return -1;
    }
    tls->closing = 1;
    result = tls->backend->shutdown(tls->engine, &tls->want[HU_TLS_SHUTDOWN]);
    if (result < 0) {
        return failed(tls, errno);
    }
    return result;
}

void hu_tls_destroy(struct hu_tls *tls)
{
    if (!tls) {
        return;
    }
    if (tls->engine) {
        tls->backend->destroy(tls->engine);
        tls->transport.ops->close(tls->transport.context);
    }
    free(tls);
}
