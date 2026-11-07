/* Check the public adapters against the fixed HSH1/HTL1 socket control ABI. */
#include <helios/unix/ssh.h>
#include <helios/unix/tls_fd.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>

/* Keep the timeout boundary test private to this translation unit. */
#include "../../src/tls_fd.c"

static unsigned char ssh_start[1184], ssh_auth[8720], tls_start[264];
static unsigned char ssh_resize[8];
static unsigned fragment_used, fragment_operation;
static int bad_ssh_status, bad_tls_status, eof_requests;

static unsigned word(const unsigned char *data)
{
    return data[0] | (unsigned)data[1] << 8 | (unsigned)data[2] << 16 |
           (unsigned)data[3] << 24;
}

static void put_word(unsigned char *data, unsigned value)
{
    data[0] = value;
    data[1] = value >> 8;
    data[2] = value >> 16;
    data[3] = value >> 24;
}

int getsockopt(int fd, int level, int operation, void *data, socklen_t *size)
{
    unsigned char *bytes = data;
    (void)fd;
    assert(level == 0xfff2 || level == 0xfff3);
    if (operation == 0) {
        assert(*size == 4);
        memcpy(data, level == 0xfff2 ? "HTL1" : "HSH1", 4);
        return 0;
    }
    assert(operation == 2);
    memset(data, 0, *size);
    if (level == 0xfff3) {
        assert(*size == 508);
        memcpy(data, "HSH1", 4);
        put_word(bytes + 4, HU_SSH_READY);
        put_word(bytes + 12, (unsigned)-7);
        put_word(bytes + 16, 1);
        put_word(bytes + 20, 3);
        put_word(bytes + 24, 2);
        strcpy((char *)bytes + 32, "ssh-rsa");
        strcpy((char *)bytes + 96, "SHA256:fixture");
        strcpy((char *)bytes + 192, "ready");
        if (bad_ssh_status) {
            bytes[507] = 1;
        }
    } else {
        assert(*size == 224);
        memcpy(data, "HTL1", 4);
        put_word(bytes + 4, HU_TLS_READY);
        strcpy((char *)bytes + 16, "TLSv1.3");
        strcpy((char *)bytes + 32, "TEST-CIPHER");
        if (bad_tls_status) {
            put_word(bytes + 12, 1);
        }
    }
    return 0;
}

int setsockopt(int fd, int level, int operation, const void *data, socklen_t size)
{
    const unsigned char *bytes = data;
    (void)fd;
    if (level == 0xfff2) {
        assert(operation == 1 && size == sizeof(tls_start));
        memcpy(tls_start, data, size);
        return 0;
    }
    assert(level == 0xfff3);
    if (operation == 7) {
        unsigned control = word(bytes), total = word(bytes + 4),
                 offset = word(bytes + 8);
        unsigned char *record = control == 1 ? ssh_start : ssh_auth;
        assert(control == 1 || control == 4);
        assert(total == (control == 1 ? sizeof(ssh_start) : sizeof(ssh_auth)));
        assert(size > 12 && size <= 492);
        if (!offset) {
            fragment_used = 0;
            fragment_operation = control;
        }
        assert(control == fragment_operation && offset == fragment_used);
        assert(offset + size - 12 <= total);
        memcpy(record + offset, bytes + 12, size - 12);
        fragment_used += size - 12;
    } else if (operation == 3) {
        assert(size == 4 && word(bytes) == 1);
    } else if (operation == 5) {
        assert(size == sizeof(ssh_resize));
        memcpy(ssh_resize, data, size);
    } else {
        assert(operation == 6 && size == 4 && !word(bytes));
        eof_requests++;
    }
    return 0;
}

static void ssh_records(void)
{
    struct hu_ssh_options options = {"peer.test", "user", "xterm", "command", 2222,
                                     132,         43,     30000,   1,         NULL};
    const char key[] = {0, (char)0x80, (char)0xff};
    struct hu_ssh_auth auth = {HU_SSH_PUBLICKEY, "passphrase", key, sizeof(key)};
    struct hu_ssh_info info;
    struct hu_ssh *session;
    int pair[2];
    unsigned i;
    assert(!socketpair(AF_UNIX, SOCK_STREAM, 0, pair));
    session = hu_ssh_open_fd(&options, pair[0]);
    assert(session && fragment_used == sizeof(ssh_start));
    assert(word(ssh_start) == 1 && word(ssh_start + 4) == 30000);
    assert(word(ssh_start + 8) == 2222 && word(ssh_start + 12) == 132);
    assert(word(ssh_start + 16) == 43 && word(ssh_start + 20) == 1);
    assert(!word(ssh_start + 24) && !word(ssh_start + 28));
    assert(!strcmp((char *)ssh_start + 32, "peer.test"));
    assert(!strcmp((char *)ssh_start + 288, "user"));
    assert(!strcmp((char *)ssh_start + 352, "xterm"));
    assert(!strcmp((char *)ssh_start + 416, "command"));
    assert(!hu_ssh_status(session, &info));
    assert(info.state == HU_SSH_READY && info.exit_status == -7 && info.exit_valid);
    assert(info.auth_methods == 3 && info.auth_attempt == 2);
    assert(!strcmp(info.key_type, "ssh-rsa") && !strcmp(info.message, "ready"));
    bad_ssh_status = 1;
    assert(hu_ssh_status(session, &info) < 0 && errno == EIO);
    bad_ssh_status = 0;
    assert(!hu_ssh_trust(session, 1));
    assert(!hu_ssh_authenticate(session, &auth) && fragment_used == sizeof(ssh_auth));
    assert(word(ssh_auth) == HU_SSH_PUBLICKEY && word(ssh_auth + 4) == sizeof(key));
    assert(!word(ssh_auth + 8) && !word(ssh_auth + 12));
    assert(!strcmp((char *)ssh_auth + 16, "passphrase"));
    assert(!memcmp(ssh_auth + 528, key, sizeof(key)));
    for (i = 528 + sizeof(key); i < sizeof(ssh_auth); i++) {
        assert(!ssh_auth[i]);
    }
    assert(!hu_ssh_resize(session, 101, 37));
    assert(word(ssh_resize) == 101 && word(ssh_resize + 4) == 37);
    assert(!hu_ssh_send_eof(session) && eof_requests == 1);
    hu_ssh_close(session);
    assert(fcntl(pair[0], F_GETFL) < 0 && errno == EBADF);
    close(pair[1]);
}

static void tls_records(void)
{
    struct hu_tls_info info;
    int pair[2];
    assert(!socketpair(AF_UNIX, SOCK_STREAM, 0, pair));
    assert(!hu_tls_fd_connect(pair[0], "peer.test", 30000, &info));
    assert(word(tls_start) == 1 && word(tls_start + 4) == 30000);
    assert(!strcmp((char *)tls_start + 8, "peer.test"));
    assert(info.state == HU_TLS_READY && !strcmp(info.protocol, "TLSv1.3"));
    assert(!strcmp(info.cipher, "TEST-CIPHER"));
    bad_tls_status = 1;
    /* Query the transport again via a fresh object; ready sessions cache state. */
    assert(!hu_tls_fd_close(pair[0]));
    close(pair[1]);
    assert(!socketpair(AF_UNIX, SOCK_STREAM, 0, pair));
    assert(hu_tls_fd_connect(pair[0], "peer.test", 30000, &info) < 0 && errno == EIO);
    assert(!hu_tls_fd_close(pair[0]));
    close(pair[1]);
}

int main(void)
{
    struct timeval boundary = {INT_MAX / 1000, 999999};
    ssh_records();
    tls_records();
    assert(timeout_milliseconds(&boundary) == INT_MAX);
    boundary.tv_sec = 0;
    boundary.tv_usec = 1;
    assert(timeout_milliseconds(&boundary) == 1);
    puts("PASS HSH1/HTL1 records, fragment order, status validation, ownership and "
         "timeout bounds");
    return 0;
}
