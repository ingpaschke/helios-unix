/* Exercise the client's actual encoding negotiation through a host PTY. */
#define main ssh_client_main
#include "../../services/hu-ssh.c"
#undef main
#include <assert.h>

int hu_ssh_interest(struct hu_ssh *session, int operation, struct hu_ssh_wait *wait)
{
    (void)session;
    assert(operation == HU_SSH_READ);
    wait->fd = 7;
    wait->events = HU_SSH_WAIT_WRITE;
    wait->timeout_ms = 10;
    return 0;
}

static void check_provider_wait(void)
{
    struct hu_ssh_wait wait;
    fd_set readfds, writefds;
    int maximum = 0, timeout = -1;
    FD_ZERO(&readfds);
    FD_ZERO(&writefds);
    assert(
        !add_wait(NULL, HU_SSH_READ, &wait, &readfds, &writefds, &maximum, &timeout));
    assert(maximum == 7 && timeout == 10 && FD_ISSET(7, &writefds));
    assert(wait_ready(&wait, &readfds, &writefds, 0));
    FD_ZERO(&writefds);
    assert(!wait_ready(&wait, &readfds, &writefds, 9));
    assert(wait_ready(&wait, &readfds, &writefds, 10));
}

int hu_terminal_read(int fd, struct hu_terminal_decoder *d, char *out, int size)
{
    (void)d;
    return read(fd, out, size);
}

int hu_terminal_restore(int fd, const struct termios *t)
{
    return tcsetattr(fd, TCSANOW, t);
}

int main(int argc, char **argv)
{
    check_provider_wait();
    struct termios t;
    struct hu_terminal_decoder d = {0, 0};
    char input[128];
    int n, i;
    if (argc > 1) {
        char answer[8];
        if (prompt("test: ", answer, sizeof(answer), 1) < 0) {
            return 2;
        }
        fputs(answer, stdout);
        return 0;
    }
    assert(tcgetattr(0, &t) == 0);
    cfmakeraw(&t);
    assert(tcsetattr(0, TCSANOW, &t) == 0);
    signal(SIGTERM, interrupt);
    n = terminal_encoding(&d, input, sizeof(input));
    fprintf(stderr, "mode=%d keys=", saved_encoding);
    for (i = 0; i < n; i++) {
        fprintf(stderr, "%02x", (unsigned char)input[i]);
    }
    fputc('\n', stderr);
    restore();
    restore(); /* Cleanup can also run through atexit. */
    return 0;
}
