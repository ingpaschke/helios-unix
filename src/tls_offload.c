#include <helios/unix/tls_backend.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

struct offload {
    const struct hu_tls_transport *transport;
    struct hu_tls_offload_start start;
    struct hu_tls_info info;
    int started, shutdown;
};

static void *create(const struct hu_tls_options *options,
                    const struct hu_tls_transport *transport)
{
    struct offload *offload;
    if (!transport->ops->control || options->configuration) {
        errno = EOPNOTSUPP;
        return NULL;
    }
    offload = calloc(1, sizeof(*offload));
    if (!offload) {
        errno = ENOMEM;
        return NULL;
    }
    offload->transport = transport;
    offload->start.peer = options->peer;
    offload->start.timeout_ms = options->timeout_ms;
    offload->info.state = HU_TLS_NEGOTIATING;
    return offload;
}

static int handshake(void *context, int *want)
{
    struct offload *offload = context;
    int result;
    *want = 0; /* Host negotiation is queried on a timer, not socket writability. */
    if (!offload->started) {
        if (offload->transport->ops->control(offload->transport->context,
                                             HU_TLS_CTL_START, &offload->start,
                                             sizeof(offload->start)) < 0) {
            return -1;
        }
        offload->started = 1;
    }
    result =
        offload->transport->ops->control(offload->transport->context, HU_TLS_CTL_STATUS,
                                         &offload->info, sizeof(offload->info));
    if (result < 0) {
        return -1;
    }
    if (offload->info.state == HU_TLS_NEGOTIATING) {
        return 0;
    }
    if (offload->info.state == HU_TLS_READY) {
        return 1;
    }
    errno = offload->info.error == 2   ? EACCES
            : offload->info.error == 4 ? ETIMEDOUT
                                       : ECONNRESET;
    return -1;
}

static int receive(void *context, void *buffer, unsigned size, int *want)
{
    struct offload *offload = context;
    *want = HU_TLS_WAIT_READ;
    return offload->transport->ops->read(offload->transport->context, buffer, size);
}

static int send_data(void *context, const void *buffer, unsigned size, int *want)
{
    struct offload *offload = context;
    *want = HU_TLS_WAIT_WRITE;
    return offload->transport->ops->write(offload->transport->context, buffer, size);
}

static unsigned pending(void *context)
{
    (void)context;
    return 0;
} /* plaintext is in the waitable host pipe */

static int finish(void *context, int *want)
{
    struct offload *offload = context;
    *want = 0;
    if (offload->shutdown) {
        return 1;
    }
    if (offload->transport->ops->control(offload->transport->context,
                                         HU_TLS_CTL_SHUTDOWN, NULL, 0) < 0) {
        return -1;
    }
    offload->shutdown = 1;
    return 1; /* host worker drains accepted data asynchronously */
}

static int timer(void *context, int operation)
{
    (void)context;
    return operation == HU_TLS_HANDSHAKE ? 20 : -1;
}

static void info(void *context, struct hu_tls_info *info)
{
    *info = ((struct offload *)context)->info;
}

static void destroy(void *context)
{
    free(context);
}
const struct hu_tls_backend hu_tls_offload_backend = {
    1,       "host-offload", create, handshake, receive, send_data,
    pending, finish,         timer,  info,      destroy};
