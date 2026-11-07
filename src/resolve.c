#include <helios/unix/resolve.h>
#include <helios/unix/netdb.h>
#include <helios/unix/api.h>
#include <helios/unix/poll.h>
#include "wire.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

int hu_resolve_launch(pid_t *pid, int fd, const char *name, int reverse,
                      const struct hu_spawn_attr *attr)
{
    struct hu_spawn_actions actions;
    struct hu_spawn_attr settings;
    int e;
    char *args[] = {"hu-resolve", (char *)name, reverse ? "1" : "0", NULL};
    if (!name || !*name || strlen(name) > 253) {
        return EINVAL;
    }
    memset(&settings, 0, sizeof(settings));
    if (attr) {
        settings = *attr;
    }
    settings.closefrom = 3;
    hu_spawn_actions_init(&actions);
    e = hu_spawn_adddup2(&actions, fd, 1);
    if (!e) {
        e = hu_spawn_addclose(&actions, 0);
    }
    if (!e) {
        e = hu_spawn_addclose(&actions, 2);
    }
    if (!e) {
        e = hu_spawn(pid, "/helios/lib/hu-resolve", &actions, &settings, args, NULL);
    }
    hu_spawn_actions_destroy(&actions);
    return e;
}

/* HUR1 contains byte addresses, not native sockaddr structures or pointers. */
static void encode_result(unsigned char *data, const struct hu_resolve_result *result)
{
    struct wire_writer writer = {data};
    unsigned char header[4];
    header[0] = result->error;
    header[1] = result->count;
    header[2] = header[3] = 0;
    wire_write_bytes(&writer, "HUR1", 4);
    wire_write_bytes(&writer, header, sizeof(header));
    wire_write_bytes(&writer, result->addresses, sizeof(result->addresses));
    wire_write_bytes(&writer, result->canonical, sizeof(result->canonical));
}

static int decode_result(const unsigned char *data, struct hu_resolve_result *result)
{
    struct wire_reader reader = {data};
    struct hu_resolve_result decoded;
    unsigned char header[4];
    char magic[4];
    wire_read_bytes(&reader, magic, sizeof(magic));
    wire_read_bytes(&reader, header, sizeof(header));
    decoded.error = header[0];
    decoded.count = header[1];
    wire_read_bytes(&reader, decoded.addresses, sizeof(decoded.addresses));
    wire_read_bytes(&reader, decoded.canonical, sizeof(decoded.canonical));
    if (memcmp(magic, "HUR1", sizeof(magic)) || decoded.error > EAI_OVERFLOW ||
        decoded.count > 32 || header[2] || header[3] ||
        decoded.canonical[sizeof(decoded.canonical) - 1] ||
        (!decoded.error && !decoded.count)) {
        errno = EIO;
        return -1;
    }
    *result = decoded;
    return 0;
}

int hu_resolve_send(int fd, const char *name, int reverse)
{
    struct hu_resolve_result result;
    unsigned char record[HU_RESOLVE_WIRE_SIZE];
    struct addrinfo hints, *addresses = NULL, *address;
    unsigned offset = 0;
    int count;

    memset(&result, 0, sizeof(result));
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_CANONNAME;
    result.error = getaddrinfo(name, NULL, &hints, &addresses);
    if (!result.error) {
        for (address = addresses; address && result.count < 32;
             address = address->ai_next) {
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)address->ai_addr;
            memcpy(result.addresses[result.count++], &ipv4->sin_addr, 4);
        }
        if (addresses->ai_canonname) {
            strncpy(result.canonical, addresses->ai_canonname,
                    sizeof(result.canonical) - 1);
        }
        if (reverse) {
            getnameinfo(addresses->ai_addr, addresses->ai_addrlen, result.canonical,
                        sizeof(result.canonical), NULL, 0, 0);
        }
    }
    freeaddrinfo(addresses);
    encode_result(record, &result);
    while (offset < sizeof(record)) {
        count = write(fd, (char *)record + offset, sizeof(record) - offset);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            return -1;
        }
        offset += count;
    }
    return 0;
}

int hu_resolve_receive(int fd, struct hu_resolve_result *result)
{
    unsigned char record[HU_RESOLVE_WIRE_SIZE];
    unsigned offset = 0;
    int count, remaining_ms;
    struct timeval started, now;
    struct hu_pollfd wait;
    if (!result) {
        errno = EINVAL;
        return -1;
    }
    memset(result, 0, sizeof(*result));
    result->error = EAI_FAIL;
    if (hu_set_nonblock(fd, 1) < 0) {
        return -1;
    }
    gettimeofday(&started, NULL);
    wait.fd = fd;
    wait.events = HU_POLLIN;
    while (offset < sizeof(record)) {
        gettimeofday(&now, NULL);
        remaining_ms = 2000 - (now.tv_sec - started.tv_sec) * 1000 -
                       (now.tv_usec - started.tv_usec) / 1000;
        if (remaining_ms <= 0) {
            errno = ETIMEDOUT;
            return -1;
        }
        count = hu_poll(&wait, 1, remaining_ms);
        if (count < 0) {
            return -1;
        }
        if (!count) {
            errno = ETIMEDOUT;
            return -1;
        }
        count = read(fd, (char *)record + offset, sizeof(record) - offset);
        if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
            continue;
        }
        if (count <= 0) {
            errno = EIO;
            return -1;
        }
        offset += count;
    }
    return decode_result(record, result);
}
