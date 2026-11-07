#include <helios/unix/ssh_backend.h>
#include "wire.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* HSH1 belongs to this transport adapter; applications use native records. */
enum ssh_control {
    SSH_CAPABILITIES,
    SSH_START,
    SSH_STATUS,
    SSH_TRUST,
    SSH_AUTHENTICATE,
    SSH_RESIZE,
    SSH_SEND_EOF,
    SSH_FRAGMENT
};

enum {
    SSH_LEVEL = 0xfff3,
    START_SIZE = 1184,
    STATUS_SIZE = 508,
    AUTH_SIZE = 8720,
    STATUS_MESSAGE_SIZE = 316,
    FRAGMENT_HEADER_SIZE = 12,
    FRAGMENT_DATA_SIZE = 480
};

struct offload {
    const struct hu_ssh_transport *transport;
};

static void encode_start(unsigned char *data, const struct hu_ssh_options *options,
                         const char *terminal, const char *command)
{
    struct wire_writer writer = {data};
    wire_write_word(&writer, 1);
    wire_write_word(&writer, options->timeout_ms);
    wire_write_word(&writer, options->port);
    wire_write_word(&writer, options->columns);
    wire_write_word(&writer, options->rows);
    wire_write_word(&writer, options->pty != 0);
    wire_write_word(&writer, 0);
    wire_write_word(&writer, 0);
    wire_write_string(&writer, options->host, 256);
    wire_write_string(&writer, options->user, 64);
    wire_write_string(&writer, terminal, 64);
    wire_write_string(&writer, command, 768);
}

static int decode_status(const unsigned char *data, struct hu_ssh_info *info)
{
    struct wire_reader reader = {data};
    struct hu_ssh_info decoded;
    char magic[4];
    wire_read_bytes(&reader, magic, sizeof(magic));
    memset(&decoded, 0, sizeof(decoded));
    decoded.state = wire_read_word(&reader);
    decoded.error = wire_read_word(&reader);
    decoded.exit_status = (int)wire_read_word(&reader);
    decoded.exit_valid = wire_read_word(&reader);
    decoded.auth_methods = wire_read_word(&reader);
    decoded.auth_attempt = wire_read_word(&reader);
    (void)wire_read_word(&reader); /* Reserved. */
    wire_read_bytes(&reader, decoded.key_type, sizeof(decoded.key_type));
    wire_read_bytes(&reader, decoded.fingerprint, sizeof(decoded.fingerprint));
    wire_read_bytes(&reader, decoded.message, STATUS_MESSAGE_SIZE);
    if (memcmp(magic, "HSH1", sizeof(magic)) || decoded.state < HU_SSH_CONNECTING ||
        decoded.state > HU_SSH_FAILED ||
        decoded.key_type[sizeof(decoded.key_type) - 1] ||
        decoded.fingerprint[sizeof(decoded.fingerprint) - 1] ||
        decoded.message[STATUS_MESSAGE_SIZE - 1]) {
        errno = EIO;
        return -1;
    }
    *info = decoded;
    return 0;
}

static void encode_authentication(unsigned char *data, const struct hu_ssh_auth *auth,
                                  const char *secret)
{
    struct wire_writer writer = {data};
    wire_write_word(&writer, auth->method);
    wire_write_word(&writer, auth->method == HU_SSH_PUBLICKEY ? auth->key_size : 0);
    wire_write_word(&writer, 0);
    wire_write_word(&writer, 0);
    wire_write_string(&writer, secret, 512);
    /* calloc has already zeroed the unused private-key bytes. */
    if (auth->method == HU_SSH_PUBLICKEY) {
        wire_write_bytes(&writer, auth->key, auth->key_size);
    }
}

static unsigned encode_fragment(unsigned char *data, int operation, unsigned total,
                                unsigned offset, const void *payload, unsigned count)
{
    struct wire_writer writer = {data};
    wire_write_word(&writer, operation);
    wire_write_word(&writer, total);
    wire_write_word(&writer, offset);
    wire_write_bytes(&writer, payload, count);
    return FRAGMENT_HEADER_SIZE + count;
}

static int control(struct offload *offload, int operation, void *data, unsigned size)
{
    const struct hu_ssh_transport *transport = offload->transport;
    unsigned expected = size;
    int result;

    /* SetSocketInfo has a 512-byte IOC buffer, including its framing. */
    if (operation == SSH_START || operation == SSH_AUTHENTICATE) {
        unsigned offset = 0;
        unsigned char fragment[FRAGMENT_HEADER_SIZE + FRAGMENT_DATA_SIZE];
        while (offset < size) {
            unsigned count = size - offset;
            unsigned fragment_size;
            if (count > FRAGMENT_DATA_SIZE) {
                count = FRAGMENT_DATA_SIZE;
            }
            fragment_size = encode_fragment(fragment, operation, size, offset,
                                            (unsigned char *)data + offset, count);
            if (transport->ops->control(transport->context, SSH_FRAGMENT, fragment,
                                        &fragment_size) < 0) {
                return -1;
            }
            offset += count;
        }
        return 0;
    }
    result = transport->ops->control(transport->context, operation, data, &size);
    if (result == 0 && size != expected) {
        errno = EIO;
        return -1;
    }
    return result;
}

static void *open_session(const struct hu_ssh_options *options,
                          const struct hu_ssh_transport *transport)
{
    struct offload *offload;
    unsigned char request[START_SIZE];
    const char *terminal = options->terminal ? options->terminal : "vt100";
    const char *command = options->command ? options->command : "";

    if (!transport->ops->control) {
        errno = EOPNOTSUPP;
        return NULL;
    }
    if (strlen(options->host) > 255 || strlen(options->user) > 63 ||
        strlen(terminal) > 63 || strlen(command) > 767) {
        errno = E2BIG;
        return NULL;
    }
    offload = malloc(sizeof(*offload));
    if (!offload) {
        errno = ENOMEM;
        return NULL;
    }
    offload->transport = transport;
    if (control(offload, SSH_CAPABILITIES, request, 4) < 0) {
        free(offload);
        return NULL;
    }
    if (memcmp(request, "HSH1", 4)) {
        free(offload);
        errno = EOPNOTSUPP;
        return NULL;
    }
    encode_start(request, options, terminal, command);
    if (control(offload, SSH_START, request, sizeof(request)) < 0) {
        free(offload);
        return NULL;
    }
    return offload;
}

static int status(void *context, struct hu_ssh_info *info)
{
    unsigned char response[STATUS_SIZE];
    if (control(context, SSH_STATUS, response, sizeof(response)) < 0) {
        return -1;
    }
    return decode_status(response, info);
}

static int trust(void *context, int accept)
{
    unsigned char request[4];
    struct wire_writer writer = {request};
    wire_write_word(&writer, accept);
    return control(context, SSH_TRUST, request, sizeof(request));
}

static int authenticate(void *context, const struct hu_ssh_auth *auth)
{
    const char *secret = auth->secret ? auth->secret : "";
    unsigned char *request;
    int result;
    if (strlen(secret) > 511) {
        errno = E2BIG;
        return -1;
    }
    request = calloc(1, AUTH_SIZE);
    if (!request) {
        errno = ENOMEM;
        return -1;
    }
    encode_authentication(request, auth, secret);
    result = control(context, SSH_AUTHENTICATE, request, AUTH_SIZE);
    memset(request, 0, AUTH_SIZE);
    free(request);
    return result;
}

static int resize(void *context, unsigned columns, unsigned rows)
{
    unsigned char request[8];
    struct wire_writer writer = {request};
    wire_write_word(&writer, columns);
    wire_write_word(&writer, rows);
    return control(context, SSH_RESIZE, request, sizeof(request));
}

static int receive(void *context, void *data, unsigned size)
{
    struct offload *offload = context;
    return offload->transport->ops->read(offload->transport->context, data, size);
}

static int send_data(void *context, const void *data, unsigned size)
{
    struct offload *offload = context;
    return offload->transport->ops->write(offload->transport->context, data, size);
}

static int eof(void *context)
{
    unsigned char request[4] = {0, 0, 0, 0};
    return control(context, SSH_SEND_EOF, request, sizeof(request));
}

static int interest(void *context, int operation, struct hu_ssh_wait *wait)
{
    (void)context;
    wait->events = operation == HU_SSH_WRITE ? HU_SSH_WAIT_WRITE : HU_SSH_WAIT_READ;
    wait->timeout_ms = operation == HU_SSH_PROGRESS ? 100 : -1;
    return 0;
}

const struct hu_ssh_backend hu_ssh_offload_backend = {
    1,      "host-offload", open_session, status, trust,    authenticate,
    resize, receive,        send_data,    eof,    interest, free};

struct socket_transport {
    int fd;
};

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

static int socket_control(void *context, int operation, void *data, unsigned *size)
{
    int fd = socket_fd(context);
    int result;
#ifdef __HELIOS
    int length = *size;
#else
    socklen_t length = *size;
#endif
    if (operation == SSH_CAPABILITIES || operation == SSH_STATUS) {
        result = getsockopt(fd, SSH_LEVEL, operation, data, &length);
        if (result == 0 && length != *size) {
            errno = EIO;
            return -1;
        }
        return result;
    }
    return setsockopt(fd, SSH_LEVEL, operation, data, *size);
}

static void socket_close(void *context)
{
    close(socket_fd(context));
    free(context);
}

static const struct hu_ssh_transport_ops socket_ops = {
    socket_read, socket_write, socket_fd, socket_control, socket_close};

struct hu_ssh *hu_ssh_open_fd(const struct hu_ssh_options *options, int fd)
{
    struct socket_transport *socket;
    struct hu_ssh_transport transport;
    struct hu_ssh *session;
    int flags, saved_errno;

    flags = fcntl(fd, F_GETFL);
    if (flags < 0) {
        return NULL;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        return NULL;
    }
    socket = malloc(sizeof(*socket));
    if (!socket) {
        errno = ENOMEM;
        goto fail;
    }
    socket->fd = fd;
    transport.ops = &socket_ops;
    transport.context = socket;
    session = hu_ssh_open(NULL, options, &transport);
    if (session) {
        return session; /* The session now owns the socket and its adapter. */
    }
    free(socket);
fail:
    saved_errno = errno;
    fcntl(fd, F_SETFL, flags);
    errno = saved_errno;
    return NULL;
}
