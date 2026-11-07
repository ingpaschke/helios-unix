#include <helios/unix/tls_fd.h>
#include <helios/unix/tls_backend.h>
#include "wire.h"
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* The native SDK exposes shutdown modes as numbers rather than SHUT_* names. */
#ifndef SHUT_WR
#define SHUT_WR 1
#endif

/* HTL1 is private to this socket transport, not part of the TLS engine API. */
enum { TLS_LEVEL = 0xfff2 };

enum { TLS_CAPABILITIES, TLS_START, TLS_STATUS };

enum { TLS_START_SIZE = 264, TLS_STATUS_SIZE = 224 };

struct socket_transport {
    int fd;
};

static void encode_start(unsigned char *data, const struct hu_tls_offload_start *start)
{
    struct wire_writer writer = {data};
    wire_write_word(&writer, 1);
    wire_write_word(&writer, start->timeout_ms);
    wire_write_string(&writer, start->peer, 256);
}

static int decode_status(const unsigned char *data, struct hu_tls_info *info)
{
    struct wire_reader reader = {data};
    struct hu_tls_info decoded;
    char magic[4];
    unsigned reserved;

    wire_read_bytes(&reader, magic, sizeof(magic));
    memset(&decoded, 0, sizeof(decoded));
    decoded.state = wire_read_word(&reader);
    decoded.error = wire_read_word(&reader);
    reserved = wire_read_word(&reader);
    wire_read_bytes(&reader, decoded.protocol, sizeof(decoded.protocol));
    wire_read_bytes(&reader, decoded.cipher, sizeof(decoded.cipher));
    wire_read_bytes(&reader, decoded.message, sizeof(decoded.message));
    if (memcmp(magic, "HTL1", sizeof(magic)) || reserved ||
        decoded.protocol[sizeof(decoded.protocol) - 1] ||
        decoded.cipher[sizeof(decoded.cipher) - 1] ||
        decoded.message[sizeof(decoded.message) - 1] ||
        decoded.state < HU_TLS_NEGOTIATING || decoded.state > HU_TLS_CLOSED) {
        errno = EIO;
        return -1;
    }
    *info = decoded;
    return 0;
}

static int socket_read(void *context, void *data, unsigned size)
{
    return read(((struct socket_transport *)context)->fd, data, size);
}

static int socket_write(void *context, const void *data, unsigned size)
{
    return write(((struct socket_transport *)context)->fd, data, size);
}

static int socket_fd(void *context)
{
    return ((struct socket_transport *)context)->fd;
}

static void socket_close(void *context)
{
    close(socket_fd(context));
    free(context);
}

static int socket_control(void *context, int operation, void *data, unsigned size)
{
    int fd = socket_fd(context);
    unsigned char request[TLS_START_SIZE], response[TLS_STATUS_SIZE];
#ifdef __HELIOS
    int length;
#else
    socklen_t length;
#endif
    switch (operation) {
    case HU_TLS_CTL_START: {
        const struct hu_tls_offload_start *start = data;
        char capabilities[4];
        if (size != sizeof(*start)) {
            errno = EINVAL;
            return -1;
        }
        length = sizeof(capabilities);
        if (getsockopt(fd, TLS_LEVEL, TLS_CAPABILITIES, capabilities, &length) < 0) {
            return -1;
        }
        if (length != sizeof(capabilities) || memcmp(capabilities, "HTL1", 4)) {
            errno = EOPNOTSUPP;
            return -1;
        }
        encode_start(request, start);
        return setsockopt(fd, TLS_LEVEL, TLS_START, (char *)request, sizeof(request));
    }
    case HU_TLS_CTL_STATUS:
        if (size != sizeof(struct hu_tls_info)) {
            errno = EINVAL;
            return -1;
        }
        length = sizeof(response);
        if (getsockopt(fd, TLS_LEVEL, TLS_STATUS, (char *)response, &length) < 0) {
            return -1;
        }
        if (length != sizeof(response)) {
            errno = EIO;
            return -1;
        }
        return decode_status(response, data);
    case HU_TLS_CTL_SHUTDOWN:
        return shutdown(fd, SHUT_WR);
    default:
        errno = EOPNOTSUPP;
        return -1;
    }
}

static const struct hu_tls_transport_ops socket_ops = {
    socket_read, socket_write, socket_fd, socket_control, socket_close};

int hu_tls_attach_fd(struct hu_tls *tls, int fd)
{
    struct socket_transport *socket;
    struct hu_tls_transport transport;
    int flags, saved_errno;
    if (fd < 0 || fd >= FD_SETSIZE || !tls || hu_tls_fd_get(fd)) {
        errno = EINVAL;
        return -1;
    }
    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    socket = malloc(sizeof(*socket));
    if (!socket) {
        errno = ENOMEM;
        return -1;
    }
    socket->fd = fd;
    transport.ops = &socket_ops;
    transport.context = socket;
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        free(socket);
        return -1;
    }
    if (hu_tls_attach(tls, &transport) < 0) {
        saved_errno = errno;
        fcntl(fd, F_SETFL, flags);
        free(socket);
        errno = saved_errno;
        return -1;
    }
    return 0; /* The TLS object now owns the descriptor and adapter. */
}
