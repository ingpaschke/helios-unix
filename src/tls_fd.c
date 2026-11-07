#include <helios/unix/tls_fd.h>
#include <helios/unix/tls_backend.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

/* Per-task legacy adapter. Never expose host-upgrade functions to ports. */
struct entry {
    int fd;
    struct hu_tls *tls;
    struct entry *next;
};
static struct entry *entries;

struct hu_tls *hu_tls_fd_get(int fd)
{
    struct entry *entry;
    for (entry = entries; entry; entry = entry->next) {
        if (entry->fd == fd) {
            return entry->tls;
        }
    }
    return NULL;
}

int hu_tls_fd_attach(int fd, struct hu_tls *tls)
{
    struct entry *entry = malloc(sizeof(*entry));
    if (!entry) {
        errno = ENOMEM;
        return -1;
    }
    if (hu_tls_attach_fd(tls, fd) < 0) {
        free(entry);
        return -1;
    }
    entry->fd = fd;
    entry->tls = tls;
    entry->next = entries;
    entries = entry;
    return 0;
}

int hu_tls_fd_start(int fd, const char *peer, unsigned timeout)
{
    struct hu_tls *tls;
    int saved_errno;
    if (hu_tls_fd_get(fd)) {
        errno = EALREADY;
        return -1;
    }
    tls = hu_tls_create(NULL, NULL, peer, timeout);
    if (!tls) {
        saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }
    if (hu_tls_fd_attach(fd, tls) < 0) {
        saved_errno = errno;
        hu_tls_destroy(tls);
        close(fd);
        errno = saved_errno;
        return -1;
    }
    /* Even a failure stays registered until close: never fall through to
     * plaintext I/O after failed authentication or an unsupported provider. */
    return hu_tls_handshake(tls) < 0 ? -1 : 0;
}

int hu_tls_fd_handshake(int fd, struct hu_tls_info *info)
{
    struct hu_tls *tls = hu_tls_fd_get(fd);
    int result, saved_errno;
    if (!tls || !info) {
        errno = EINVAL;
        return -1;
    }
    result = hu_tls_handshake(tls);
    saved_errno = errno;
    hu_tls_info(tls, info);
    errno = saved_errno;
    return result;
}

int hu_tls_fd_connect(int fd, const char *peer, unsigned timeout,
                      struct hu_tls_info *info)
{
    struct hu_tls *tls;
    int result, saved_errno;
    if (!info) {
        errno = EINVAL;
        return -1;
    }
    memset(info, 0, sizeof(*info));
    result = hu_tls_fd_start(fd, peer, timeout);
    tls = hu_tls_fd_get(fd);
    if (result >= 0) {
        result = hu_tls_handshake_wait(tls);
    }
    saved_errno = errno;
    if (tls) {
        hu_tls_info(tls, info);
    }
    errno = saved_errno;
    return result;
}

int hu_tls_fd_read(int fd, void *buffer, unsigned size)
{
    struct hu_tls *tls = hu_tls_fd_get(fd);
    return tls ? hu_tls_read(tls, buffer, size) : read(fd, buffer, size);
}

int hu_tls_fd_write(int fd, const void *buffer, unsigned size)
{
    struct hu_tls *tls = hu_tls_fd_get(fd);
    return tls ? hu_tls_write(tls, buffer, size) : write(fd, buffer, size);
}

int hu_tls_fd_close(int fd)
{
    struct entry **slot = &entries, *entry;
    while (*slot && (*slot)->fd != fd) {
        slot = &(*slot)->next;
    }
    if (!*slot) {
        return close(fd);
    }
    entry = *slot;
    *slot = entry->next;
    {
        struct hu_tls_info info;
        struct timeval start, now;
        int result = 1, saved_errno = 0, remaining_ms;
        hu_tls_info(entry->tls, &info);
        if (info.state == HU_TLS_READY || info.state == HU_TLS_CLOSED) {
            gettimeofday(&start, NULL);
            while ((result = hu_tls_shutdown(entry->tls)) == 0) {
                gettimeofday(&now, NULL);
                remaining_ms = 5000 - (now.tv_sec - start.tv_sec) * 1000 -
                               (now.tv_usec - start.tv_usec) / 1000;
                if (remaining_ms > 5000) {
                    remaining_ms = 5000;
                }
                if (remaining_ms <= 0) {
                    saved_errno = ETIMEDOUT;
                    break;
                }
                result = hu_tls_wait(entry->tls, HU_TLS_SHUTDOWN, remaining_ms);
                if (result < 0 && errno != EINTR) {
                    saved_errno = errno;
                    break;
                }
                if (!result) {
                    saved_errno = ETIMEDOUT;
                    break;
                }
            }
            if (result < 0 && !saved_errno) {
                saved_errno = errno;
            }
        }
        /* Entry is removed before releasing the fd. Never return EINTR after
         * closing it: legacy EINTRLOOP(close) could act on a reused descriptor. */
        hu_tls_destroy(entry->tls);
        free(entry);
        if (saved_errno) {
            errno = saved_errno == EINTR ? EIO : saved_errno;
            return -1;
        }
        return 0;
    }
}

static int add_interest(struct hu_tls *tls, int operation, struct hu_tls_wait *wait,
                        fd_set *readfds, fd_set *writefds, int *maximum, int *timeout)
{
    if (hu_tls_interest(tls, operation, wait) < 0) {
        return -1;
    }
    if (wait->fd < 0 || wait->fd >= FD_SETSIZE) {
        errno = EINVAL;
        return -1;
    }
    if (wait->events & HU_TLS_WAIT_READ) {
        FD_SET(wait->fd, readfds);
    }
    if (wait->events & HU_TLS_WAIT_WRITE) {
        FD_SET(wait->fd, writefds);
    }
    if (wait->fd >= *maximum) {
        *maximum = wait->fd + 1;
    }
    if (wait->timeout_ms >= 0 && (*timeout < 0 || wait->timeout_ms < *timeout)) {
        *timeout = wait->timeout_ms;
    }
    return 0;
}

static int ready(const struct hu_tls_wait *wait, fd_set *readfds, fd_set *writefds,
                 int elapsed_ms)
{
    return ((wait->events & HU_TLS_WAIT_READ) && FD_ISSET(wait->fd, readfds)) ||
           ((wait->events & HU_TLS_WAIT_WRITE) && FD_ISSET(wait->fd, writefds)) ||
           (wait->timeout_ms >= 0 && elapsed_ms >= wait->timeout_ms);
}

struct interest {
    struct hu_tls_wait read, write;
};

/* Round up fractional milliseconds without overflowing the select adapter. */
static int timeout_milliseconds(const struct timeval *timeout)
{
    int milliseconds, fraction;
    if (timeout->tv_sec > INT_MAX / 1000) {
        return INT_MAX;
    }
    milliseconds = timeout->tv_sec * 1000;
    fraction = (timeout->tv_usec + 999) / 1000;
    return fraction > INT_MAX - milliseconds ? INT_MAX : milliseconds + fraction;
}

int hu_tls_fd_select(int n, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
                     struct timeval *timeout)
{
    fd_set physical_read, physical_write, physical_except, logical_read, logical_write,
        logical_except;
    struct timeval wait_time, start, now;
    struct interest *plans;
    int i, maximum = n, timeout_ms = -1, result, count = 0, elapsed_ms;
    struct hu_tls *tls;
    if (n < 0 || n > FD_SETSIZE ||
        (timeout && (timeout->tv_sec < 0 || timeout->tv_usec < 0 ||
                     timeout->tv_usec >= 1000000))) {
        errno = EINVAL;
        return -1;
    }
    if (!entries) {
        return select(n, readfds, writefds, exceptfds, timeout);
    }
    FD_ZERO(&logical_read);
    FD_ZERO(&logical_write);
    FD_ZERO(&logical_except);
    if (readfds) {
        logical_read = *readfds;
    }
    if (writefds) {
        logical_write = *writefds;
    }
    if (exceptfds) {
        logical_except = *exceptfds;
    }
    physical_read = logical_read;
    physical_write = logical_write;
    physical_except = logical_except;
    if (timeout) {
        timeout_ms = timeout_milliseconds(timeout);
    }
    plans = calloc(n ? n : 1, sizeof(*plans));
    if (!plans) {
        errno = ENOMEM;
        return -1;
    }
    /* Remove all logical descriptors first, then add physical interests.
     * This also works when a custom transport waits on a different fd. */
    for (i = 0; i < n; i++) {
        if (hu_tls_fd_get(i)) {
            FD_CLR(i, &physical_read);
            FD_CLR(i, &physical_write);
            FD_CLR(i, &physical_except);
        }
    }
    for (i = 0; i < n; i++) {
        if ((tls = hu_tls_fd_get(i)) != NULL) {
            if (FD_ISSET(i, &logical_read) &&
                add_interest(tls, HU_TLS_READ, &plans[i].read, &physical_read,
                             &physical_write, &maximum, &timeout_ms) < 0) {
                goto fail;
            }
            if (FD_ISSET(i, &logical_write) &&
                add_interest(tls, HU_TLS_WRITE, &plans[i].write, &physical_read,
                             &physical_write, &maximum, &timeout_ms) < 0) {
                goto fail;
            }
            /* TLS records have no application urgent-data channel. */
        }
    }
    wait_time.tv_sec = timeout_ms < 0 ? 0 : timeout_ms / 1000;
    wait_time.tv_usec = timeout_ms < 0 ? 0 : timeout_ms % 1000 * 1000;
    gettimeofday(&start, NULL);
    result = select(maximum, &physical_read, &physical_write, &physical_except,
                    timeout_ms < 0 ? NULL : &wait_time);
    if (result < 0) {
        goto fail;
    }
    gettimeofday(&now, NULL);
    elapsed_ms =
        (now.tv_sec - start.tv_sec) * 1000 + (now.tv_usec - start.tv_usec) / 1000;
    if (result == 0 && timeout_ms >= 0 && elapsed_ms < timeout_ms) {
        elapsed_ms = timeout_ms;
    }
    if (readfds) {
        FD_ZERO(readfds);
    }
    if (writefds) {
        FD_ZERO(writefds);
    }
    if (exceptfds) {
        FD_ZERO(exceptfds);
    }
    for (i = 0; i < n; i++) {
        tls = hu_tls_fd_get(i);
        if (FD_ISSET(i, &logical_read) &&
            (tls ? ready(&plans[i].read, &physical_read, &physical_write, elapsed_ms)
                 : FD_ISSET(i, &physical_read))) {
            FD_SET(i, readfds);
            count++;
        }
        if (FD_ISSET(i, &logical_write) &&
            (tls ? ready(&plans[i].write, &physical_read, &physical_write, elapsed_ms)
                 : FD_ISSET(i, &physical_write))) {
            FD_SET(i, writefds);
            count++;
        }
        if (!tls && FD_ISSET(i, &logical_except) && FD_ISSET(i, &physical_except)) {
            FD_SET(i, exceptfds);
            count++;
        }
    }
    free(plans);
    return count;
fail:
    free(plans);
    return -1;
}
