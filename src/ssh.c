#include <helios/unix/ssh_backend.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#ifndef HU_SSH_DEFAULT_BACKEND
#define HU_SSH_DEFAULT_BACKEND hu_ssh_offload_backend
#endif
extern const struct hu_ssh_backend HU_SSH_DEFAULT_BACKEND;

struct hu_ssh {
    const struct hu_ssh_backend *backend;
    struct hu_ssh_transport transport;
    void *engine;
};

struct hu_ssh *hu_ssh_open(const struct hu_ssh_backend *backend,
                           const struct hu_ssh_options *options,
                           const struct hu_ssh_transport *transport)
{
    struct hu_ssh *session;
    if (!backend) {
        backend = &HU_SSH_DEFAULT_BACKEND;
    }
    if (!options || !options->host || !*options->host || !options->user ||
        !*options->user || !options->port || options->port > 65535 ||
        options->columns > 65535 || options->rows > 65535 ||
        options->timeout_ms < 100 || options->timeout_ms > 120000 || !transport ||
        !transport->ops || !transport->ops->read || !transport->ops->write ||
        !transport->ops->wait_fd || !transport->ops->close || backend->version != 1 ||
        !backend->open || !backend->status || !backend->trust ||
        !backend->authenticate || !backend->resize || !backend->read ||
        !backend->write || !backend->eof || !backend->interest || !backend->destroy) {
        errno = EINVAL;
        return NULL;
    }
    session = calloc(1, sizeof(*session));
    if (!session) {
        errno = ENOMEM;
        return NULL;
    }
    session->backend = backend;
    session->transport = *transport;
    session->engine = backend->open(options, &session->transport);
    if (!session->engine) {
        free(session);
        return NULL;
    }
    return session;
}

int hu_ssh_status(struct hu_ssh *session, struct hu_ssh_info *info)
{
    if (!session || !info) {
        errno = EINVAL;
        return -1;
    }
    return session->backend->status(session->engine, info);
}

int hu_ssh_trust(struct hu_ssh *session, int accept)
{
    if (!session) {
        errno = EINVAL;
        return -1;
    }
    return session->backend->trust(session->engine, accept != 0);
}

int hu_ssh_authenticate(struct hu_ssh *session, const struct hu_ssh_auth *auth)
{
    if (!session || !auth ||
        (auth->method != HU_SSH_PASSWORD && auth->method != HU_SSH_PUBLICKEY) ||
        (auth->method == HU_SSH_PUBLICKEY &&
         (!auth->key || !auth->key_size || auth->key_size > HU_SSH_MAX_KEY))) {
        errno = EINVAL;
        return -1;
    }
    return session->backend->authenticate(session->engine, auth);
}

int hu_ssh_resize(struct hu_ssh *session, unsigned columns, unsigned rows)
{
    if (!session || !columns || !rows || columns > 65535 || rows > 65535) {
        errno = EINVAL;
        return -1;
    }
    return session->backend->resize(session->engine, columns, rows);
}

int hu_ssh_read(struct hu_ssh *session, void *buffer, unsigned size)
{
    if (!session || (!buffer && size)) {
        errno = EINVAL;
        return -1;
    }
    return size ? session->backend->read(session->engine, buffer, size) : 0;
}

int hu_ssh_write(struct hu_ssh *session, const void *buffer, unsigned size)
{
    if (!session || (!buffer && size)) {
        errno = EINVAL;
        return -1;
    }
    return size ? session->backend->write(session->engine, buffer, size) : 0;
}

int hu_ssh_send_eof(struct hu_ssh *session)
{
    if (!session) {
        errno = EINVAL;
        return -1;
    }
    return session->backend->eof(session->engine);
}

int hu_ssh_wait_fd(struct hu_ssh *session)
{
    if (!session) {
        errno = EINVAL;
        return -1;
    }
    return session->transport.ops->wait_fd(session->transport.context);
}

int hu_ssh_interest(struct hu_ssh *session, int operation, struct hu_ssh_wait *wait)
{
    if (!session || !wait || operation < HU_SSH_READ || operation > HU_SSH_PROGRESS) {
        errno = EINVAL;
        return -1;
    }
    wait->fd = hu_ssh_wait_fd(session);
    wait->events = 0;
    wait->timeout_ms = -1;
    return session->backend->interest(session->engine, operation, wait);
}

void hu_ssh_close(struct hu_ssh *session)
{
    if (session) {
        session->backend->destroy(session->engine);
        session->transport.ops->close(session->transport.context);
        free(session);
    }
}
