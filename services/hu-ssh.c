/* Native Helios SSH terminal client; protocol and crypto live in a provider. */
#include <helios/unix/ssh.h>
#include <helios/unix/api.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <netdb.h>
#ifdef __HELIOS
#include <helios/unix/netdb.h>
#endif
#include <termios.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static volatile sig_atomic_t interrupted, resized;
static int raw, old_flags = -1;
static int saved_encoding = -1;
static struct termios saved_terminal;

static void interrupt(int sig)
{
    interrupted = sig;
}

static void resize_signal(int sig)
{
    (void)sig;
    resized = 1;
}

static void restore(void)
{
    if (saved_encoding >= 0) {
        const char *mode = saved_encoding ? "\033%G" : "\033%@";
        int left = 3;
        while (left) {
            int n = write(1, mode, left);
            if (n > 0) {
                mode += n;
                left -= n;
            } else if (n < 0 && errno == EINTR) {
                continue;
            } else {
                break;
            }
        }
        saved_encoding = -1;
    }
    if (raw) {
        hu_terminal_restore(0, &saved_terminal);
    }
    if (old_flags >= 0) {
        fcntl(0, F_SETFL, old_flags);
    }
}

static void pause_ms(unsigned ms)
{
    struct timeval t;
    t.tv_sec = ms / 1000;
    t.tv_usec = (ms % 1000) * 1000;
    select(0, NULL, NULL, NULL, &t);
}

static int prompt(const char *message, char *out, unsigned size, int secret)
{
    struct termios old, t;
    int hidden = 0, too_long = 0;
    size_t n;
    if (interrupted || size < 2) {
        return -1;
    }
    fputs(message, stderr);
    fflush(stderr);
    if (secret && tcgetattr(0, &old) == 0) {
        t = old;
        t.c_lflag &= ~ECHO;
        hidden = tcsetattr(0, TCSANOW, &t) == 0;
    }
    if (!fgets(out, size, stdin)) {
        if (hidden) {
            tcsetattr(0, TCSANOW, &old);
        }
        return -1;
    }
    n = strlen(out);
    if (n == size - 1 && out[n - 1] != '\n') {
        int tail = fgetc(stdin);
        if (tail != '\n' && tail != EOF) {
            too_long = 1;
        }
    }
    if (hidden) {
        tcsetattr(0, TCSANOW, &old);
        fputc('\n', stderr);
    }
    if (too_long) {
        fprintf(stderr, "ssh: input too long\n");
        return -1;
    }
    if (ferror(stdin)) {
        return -1;
    }
    while (n && (out[n - 1] == '\n' || out[n - 1] == '\r')) {
        out[--n] = 0;
    }
    return interrupted ? -1 : 0;
}

/* This client's hosts file contains: hostname port key-type fingerprint.
 * It is intentionally separate from OpenSSH's encoded known_hosts format. */
static int host_key(const struct hu_ssh_options *o, const struct hu_ssh_info *i,
                    const char *file)
{
    char line[512], host[256], type[64], fingerprint[96], answer[32];
    unsigned port;
    FILE *f = fopen(file, "r");
    if (f) {
        while (fgets(line, sizeof(line), f)) {
            if (sscanf(line, "%255s %u %63s %95s", host, &port, type, fingerprint) !=
                4) {
                continue;
            }
            if (strcmp(host, o->host) || port != o->port) {
                continue;
            }
            if (!strcmp(type, i->key_type) && !strcmp(fingerprint, i->fingerprint)) {
                fclose(f);
                return 1;
            }
            fclose(f);
            fprintf(stderr, "ssh: host key changed for %s:%u (%s)\n", o->host, o->port,
                    file);
            return 0;
        }
        fclose(f);
    }
    fprintf(stderr, "Host %s:%u (%s)\n%s\n", o->host, o->port, i->key_type,
            i->fingerprint);
    if (prompt("Remember this host key? (yes/no) ", answer, sizeof(answer), 0) < 0 ||
        strcmp(answer, "yes")) {
        return 0;
    }
    f = fopen(file, "a");
    if (!f) {
        fprintf(stderr, "ssh: cannot save %s: %s\n", file, strerror(errno));
        return 0;
    }
    {
        int written =
            fprintf(f, "%s %u %s %s\n", o->host, o->port, i->key_type, i->fingerprint);
        int closed = fclose(f);
        if (written < 0 || closed != 0) {
            fprintf(stderr, "ssh: cannot save host key\n");
            return 0;
        }
    }
    return 1;
}

static int connect_host(const char *host, const char *port)
{
    struct addrinfo hints, *addresses, *address;
    int fd = -1, error, last_error = 0;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    error = getaddrinfo(host, port, &hints, &addresses);
    if (error) {
        fprintf(stderr, "ssh: %s: %s\n", host, gai_strerror(error));
        return -1;
    }
    for (address = addresses; address && !interrupted; address = address->ai_next) {
        fd = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
        if (fd < 0) {
            last_error = errno;
            continue;
        }
        if (connect(fd, address->ai_addr, address->ai_addrlen) == 0) {
            break;
        }
        last_error = errno;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(addresses);
    if (fd < 0) {
        fprintf(stderr, "ssh: connect %s:%s: %s\n", host, port, strerror(last_error));
    }
    return fd;
}

static int write_all(int fd, const char *data, int size)
{
    while (size && !interrupted) {
        int n = write(fd, data, size);
        if (n > 0) {
            data += n;
            size -= n;
        } else if (n < 0 && errno == EINTR) {
            continue;
        } else {
            return -1;
        }
    }
    return size ? -1 : 0;
}

/* Xterm's read-only private mode 1020 reports the current UTF-8 setting.
 * Keep any interleaved keyboard bytes for the relay; only remove the reply.
 * Older terminals that do not answer are left in their existing encoding. */
static int terminal_encoding(struct hu_terminal_decoder *decoder, char *input, int size)
{
    const char *term = getenv("TERM");
    struct timeval now, until;
    int used = 0, i, n;
    long left;
    if (!term || strncmp(term, "xterm", 5) || !isatty(0) || !isatty(1)) {
        return 0;
    }
    if (gettimeofday(&until, NULL) < 0) {
        return 0;
    }
    until.tv_sec += 2;
    if (write_all(1, "\033[?1020$p", 9) < 0) {
        return 0;
    }
    while (used < size - 2 && !interrupted) {
        fd_set r;
        struct timeval timeout;
        gettimeofday(&now, NULL);
        left = (until.tv_sec - now.tv_sec) * 1000000L + until.tv_usec - now.tv_usec;
        if (left <= 0) {
            break;
        }
        timeout.tv_sec = left / 1000000;
        timeout.tv_usec = left % 1000000;
        FD_ZERO(&r);
        FD_SET(0, &r);
        n = select(1, &r, NULL, NULL, &timeout);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            break;
        }
        n = hu_terminal_read(0, decoder, input + used, size - used);
        if (n < 0 && (errno == EAGAIN || errno == EINTR)) {
            continue;
        }
        if (n <= 0) {
            break;
        }
        used += n;
        for (i = 0; i + 11 <= used; i++) {
            if (!memcmp(input + i, "\033[?1020;", 8) && input[i + 8] >= '0' &&
                input[i + 8] <= '4' && !memcmp(input + i + 9, "$y", 2)) {
                int state = input[i + 8] - '0';
                memmove(input + i, input + i + 11, used - i - 11);
                used -= 11;
                if (state >= 1 && state <= 4) {
                    saved_encoding = state == 1 || state == 3;
                    write_all(1, "\033%G", 3);
                }
                return used;
            }
        }
    }
    return used;
}

struct relay_buffer {
    char data[4096];
    unsigned size, offset;
};

struct relay_state {
    struct hu_ssh *session;
    struct hu_terminal_decoder decoder;
    struct relay_buffer outgoing;
    int input_eof, input_eof_sent, output_eof;
};

static int retryable_error(void)
{
    return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR;
}

static int relay_resize(struct hu_ssh *session)
{
    struct hu_ssh_info info;
    unsigned rows, columns;
    resized = 0;
    if (hu_terminal_size(0, &rows, &columns) == 0 &&
        hu_ssh_resize(session, columns, rows) < 0) {
        if (hu_ssh_status(session, &info) < 0 || info.state == HU_SSH_READY) {
            perror("ssh: resize");
            return -1;
        }
    }
    return 0;
}

/* EOF follows the last accepted input byte; remote output is drained separately. */
static int relay_eof(struct relay_state *relay)
{
    struct hu_ssh_info info;
    if (!relay->input_eof || relay->outgoing.size || relay->input_eof_sent) {
        return 0;
    }
    if (hu_ssh_send_eof(relay->session) < 0 &&
        (hu_ssh_status(relay->session, &info) < 0 || info.state != HU_SSH_CLOSED)) {
        perror("ssh: EOF");
        return -1;
    }
    relay->input_eof_sent = 1;
    return 0;
}

static int relay_write(struct relay_state *relay)
{
    struct relay_buffer *buffer = &relay->outgoing;
    struct hu_ssh_info info;
    int count = hu_ssh_write(relay->session, buffer->data + buffer->offset,
                             buffer->size - buffer->offset);
    if (count > 0) {
        buffer->offset += count;
        if (buffer->offset == buffer->size) {
            buffer->offset = buffer->size = 0;
        }
    } else if (count < 0 && !retryable_error()) {
        if (hu_ssh_status(relay->session, &info) == 0 && info.state == HU_SSH_CLOSED) {
            buffer->size = buffer->offset = 0;
            relay->input_eof = relay->input_eof_sent = 1;
        } else {
            perror("ssh: write");
            return -1;
        }
    }
    return 0;
}

static int relay_read(struct relay_state *relay)
{
    char incoming[4096];
    int count = hu_ssh_read(relay->session, incoming, sizeof(incoming));
    if (count > 0) {
        return write_all(1, incoming, count);
    }
    if (count == 0) {
        relay->output_eof = 1;
    } else if (!retryable_error()) {
        perror("ssh: read");
        return -1;
    }
    return 0;
}

static int relay_input(struct relay_state *relay)
{
    struct relay_buffer *buffer = &relay->outgoing;
    int count =
        hu_terminal_read(0, &relay->decoder, buffer->data, sizeof(buffer->data));
    if (count > 0) {
        buffer->size = count;
    } else if (count == 0) {
        relay->input_eof = 1;
    } else if (!retryable_error()) {
        perror("ssh: input");
        return -1;
    }
    return 0;
}

static int add_wait(struct hu_ssh *session, int operation, struct hu_ssh_wait *wait,
                    fd_set *readfds, fd_set *writefds, int *maximum, int *timeout)
{
    if (hu_ssh_interest(session, operation, wait) < 0) {
        return -1;
    }
    if (wait->fd < 0 || wait->fd >= FD_SETSIZE) {
        errno = EINVAL;
        return -1;
    }
    if (wait->events & HU_SSH_WAIT_READ) {
        FD_SET(wait->fd, readfds);
    }
    if (wait->events & HU_SSH_WAIT_WRITE) {
        FD_SET(wait->fd, writefds);
    }
    if (wait->fd > *maximum) {
        *maximum = wait->fd;
    }
    if (wait->timeout_ms >= 0 && (*timeout < 0 || wait->timeout_ms < *timeout)) {
        *timeout = wait->timeout_ms;
    }
    return 0;
}

static int wait_ready(const struct hu_ssh_wait *wait, fd_set *readfds, fd_set *writefds,
                      int elapsed_ms)
{
    return ((wait->events & HU_SSH_WAIT_READ) && FD_ISSET(wait->fd, readfds)) ||
           ((wait->events & HU_SSH_WAIT_WRITE) && FD_ISSET(wait->fd, writefds)) ||
           (wait->timeout_ms >= 0 && elapsed_ms >= wait->timeout_ms);
}

static int relay(struct hu_ssh *session, int pty)
{
    struct relay_state relay;
    struct hu_ssh_info info;
    struct stat input_stat;
    int regular_input = fstat(0, &input_stat) == 0 && S_ISREG(input_stat.st_mode);
    int fd = hu_ssh_wait_fd(session);

    memset(&relay, 0, sizeof(relay));
    relay.session = session;
    if (fd < 0 || fd >= FD_SETSIZE) {
        errno = EINVAL;
        return 255;
    }
    if (hu_ssh_status(session, &info) < 0) {
        return 255;
    }
    if (info.state == HU_SSH_CLOSED) {
        relay.input_eof = relay.input_eof_sent = 1;
    }
    if (pty && isatty(0)) {
        if (hu_terminal_raw(0, &saved_terminal) < 0) {
            perror("ssh: terminal raw mode");
            return 255;
        }
        raw = 1;
        relay.decoder.helios_c1 = 1;
    }
    old_flags = fcntl(0, F_GETFL);
    if (old_flags < 0 || fcntl(0, F_SETFL, old_flags | O_NONBLOCK) < 0) {
        perror("ssh: terminal flags");
        return 255;
    }
    if (raw) {
        relay.outgoing.size = terminal_encoding(&relay.decoder, relay.outgoing.data,
                                                sizeof(relay.outgoing.data));
    }
    resized = 1;
    while (!interrupted) {
        fd_set readfds, writefds;
        struct timeval timeout, started, now;
        struct hu_ssh_wait read_wait, write_wait;
        int timeout_ms = relay.output_eof ? 100 : -1;
        int input_ready, accepting_input, result, elapsed_ms, maximum = 0;

        if ((pty && resized && relay_resize(session) < 0) || relay_eof(&relay) < 0) {
            return 255;
        }
        FD_ZERO(&readfds);
        FD_ZERO(&writefds);
        accepting_input = !relay.input_eof && !relay.outgoing.size && !relay.output_eof;
        input_ready = regular_input && accepting_input;
        if (!regular_input && accepting_input) {
            FD_SET(0, &readfds);
        }
        memset(&read_wait, 0, sizeof(read_wait));
        memset(&write_wait, 0, sizeof(write_wait));
        read_wait.timeout_ms = write_wait.timeout_ms = -1;
        if (!relay.output_eof && add_wait(session, HU_SSH_READ, &read_wait, &readfds,
                                          &writefds, &maximum, &timeout_ms) < 0) {
            return 255;
        }
        if (relay.outgoing.size &&
            add_wait(session, HU_SSH_WRITE, &write_wait, &readfds, &writefds, &maximum,
                     &timeout_ms) < 0) {
            return 255;
        }
        if (input_ready) {
            timeout_ms = 0;
        }
        timeout.tv_sec = timeout_ms < 0 ? 0 : timeout_ms / 1000;
        timeout.tv_usec = timeout_ms < 0 ? 0 : timeout_ms % 1000 * 1000;
        gettimeofday(&started, NULL);
        result = select(maximum + 1, &readfds, &writefds, NULL,
                        timeout_ms < 0 ? NULL : &timeout);
        if (result < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("ssh: select");
            return 255;
        }
        gettimeofday(&now, NULL);
        elapsed_ms = (now.tv_sec - started.tv_sec) * 1000 +
                     (now.tv_usec - started.tv_usec) / 1000;
        if (elapsed_ms < 0) {
            elapsed_ms = 0;
        }
        if (!result && elapsed_ms < timeout_ms) {
            elapsed_ms = timeout_ms;
        }
        if (relay.outgoing.size &&
            wait_ready(&write_wait, &readfds, &writefds, elapsed_ms) &&
            relay_write(&relay) < 0) {
            return 255;
        }
        if (!relay.output_eof &&
            wait_ready(&read_wait, &readfds, &writefds, elapsed_ms) &&
            relay_read(&relay) < 0) {
            return 255;
        }
        if (!relay.outgoing.size && (input_ready || FD_ISSET(0, &readfds)) &&
            relay_input(&relay) < 0) {
            return 255;
        }
        if (relay.output_eof) {
            if (hu_ssh_status(session, &info) < 0) {
                perror("ssh: status");
                return 255;
            }
            if (info.state == HU_SSH_FAILED) {
                fprintf(stderr, "ssh: %s\n", info.message);
                return 255;
            }
            if (info.state == HU_SSH_CLOSED) {
                return info.exit_valid ? info.exit_status : 255;
            }
        }
    }
    return 255;
}

static void usage(void)
{
    fputs("Usage: ssh [-t|-T] [-p port] [-l user] [-i private-key] [-K hosts-file] "
          "[user@]host [command ...]\n",
          stderr);
}

int main(int argc, char **argv)
{
    struct hu_ssh_options options;
    struct hu_ssh_info info;
    struct hu_ssh *session = NULL;
    char host[256], user[64], hosts[512], command[768], port[16], secret[512];
    char *key = NULL, *identity = NULL, *hosts_file = NULL, *username = NULL, *target,
         *separator, *home;
    int argument = 1, pty = -1, fd = -1, status = 255, trusted = 0, key_tried = 0,
        password_tries = 0;
    long number;
    unsigned key_size = 0;
    setvbuf(stdin, NULL, _IONBF, 0);
    memset(&options, 0, sizeof(options));
    command[0] = 0;
    strcpy(port, "22");
    while (argument < argc && argv[argument][0] == '-' && argv[argument][1]) {
        char *option = argv[argument++];
        if (!strcmp(option, "--")) {
            break;
        }
        if (!strcmp(option, "-t")) {
            pty = 1;
            continue;
        }
        if (!strcmp(option, "-T")) {
            pty = 0;
            continue;
        }
        if (!strcmp(option, "--help")) {
            usage();
            return 0;
        }
        if (argument == argc) {
            usage();
            return 2;
        }
        if (!strcmp(option, "-l")) {
            username = argv[argument++];
        } else if (!strcmp(option, "-i")) {
            identity = argv[argument++];
        } else if (!strcmp(option, "-K")) {
            hosts_file = argv[argument++];
        } else if (!strcmp(option, "-p")) {
            char *end;
            number = strtol(argv[argument++], &end, 10);
            if (*end || number < 1 || number > 65535) {
                usage();
                return 2;
            }
            sprintf(port, "%ld", number);
        } else {
            usage();
            return 2;
        }
    }
    if (argument == argc) {
        usage();
        return 2;
    }
    target = argv[argument++];
    separator = strrchr(target, '@');
    if (separator) {
        if (separator == target || separator - target >= sizeof(user)) {
            usage();
            return 2;
        }
        memcpy(user, target, separator - target);
        user[separator - target] = 0;
        username = user;
        target = separator + 1;
    }
    if (!*target || strlen(target) >= sizeof(host)) {
        usage();
        return 2;
    }
    strcpy(host, target);
    if (!username) {
        username = getenv("USER");
    }
    if (!username) {
        username = getenv("LOGNAME");
    }
    if (!username || !*username || strlen(username) >= sizeof(user)) {
        fprintf(stderr, "ssh: specify user@host or -l user\n");
        return 2;
    }
    if (username != user) {
        strcpy(user, username);
    }
    while (argument < argc) {
        if (strlen(command) + strlen(argv[argument]) + 2 > sizeof(command)) {
            fprintf(stderr, "ssh: command too long\n");
            return 2;
        }
        if (*command) {
            strcat(command, " ");
        }
        strcat(command, argv[argument++]);
    }
    home = getenv("HOME");
    if (!home) {
        home = "/helios/users/guest";
    }
    if (!hosts_file) {
        if (strlen(home) + 12 >= sizeof(hosts)) {
            fprintf(stderr, "ssh: HOME too long\n");
            return 2;
        }
        sprintf(hosts, "%s/.ssh", home);
        if (mkdir(hosts, 0700) < 0 && errno != EEXIST) {
            perror("ssh: .ssh");
            return 255;
        }
        strcat(hosts, "/hosts");
        hosts_file = hosts;
    }
    if (identity) {
        FILE *f = fopen(identity, "rb");
        int count;
        if (!f) {
            perror(identity);
            return 255;
        }
        key = malloc(HU_SSH_MAX_KEY + 1);
        if (!key) {
            fclose(f);
            return 255;
        }
        count = fread(key, 1, HU_SSH_MAX_KEY + 1, f);
        fclose(f);
        if (count <= 0 || count > HU_SSH_MAX_KEY) {
            fprintf(stderr, "ssh: private key must be at most %d bytes\n",
                    HU_SSH_MAX_KEY);
            free(key);
            return 255;
        }
        key_size = count;
    }
    signal(SIGINT, interrupt);
    signal(SIGTERM, interrupt);
    signal(SIGHUP, interrupt);
    signal(SIGPIPE, SIG_IGN);
#ifdef SIGWINCH
    signal(SIGWINCH, resize_signal);
#endif
    atexit(restore);
    {
        options.host = host;
        options.user = user;
        options.port = atoi(port);
        options.terminal = getenv("TERM");
        if (!options.terminal) {
            options.terminal = "vt100";
        }
        options.command = *command ? command : NULL;
        options.pty = pty < 0 ? (!*command && isatty(0)) : pty;
        options.columns = 80;
        options.rows = 24;
        options.timeout_ms = 30000;
        if (options.pty) {
            hu_terminal_size(0, &options.rows, &options.columns);
        }
        fd = connect_host(host, port);
        if (fd < 0) {
            goto done;
        }
        session = hu_ssh_open_fd(&options, fd);
        if (!session) {
            perror("ssh: SSH provider (requires an SSH-enabled io-server)");
            close(fd);
            goto done;
        }
        while (!interrupted) {
            if (hu_ssh_status(session, &info) < 0) {
                perror("ssh: status");
                goto done;
            }
            if (info.state == HU_SSH_HOSTKEY && !trusted) {
                trusted = host_key(&options, &info, hosts_file);
                if (hu_ssh_trust(session, trusted) < 0) {
                    perror("ssh: host key");
                    goto done;
                }
                if (!trusted) {
                    goto done;
                }
            } else if (info.state == HU_SSH_AUTH) {
                struct hu_ssh_auth auth;
                memset(&auth, 0, sizeof(auth));
                secret[0] = 0;
                if (key && !key_tried && (info.auth_methods & HU_SSH_PUBLICKEY)) {
                    auth.method = HU_SSH_PUBLICKEY;
                    auth.key = key;
                    auth.key_size = key_size;
                    key_tried = 1;
                    if (prompt("Private-key passphrase (Return if none): ", secret,
                               sizeof(secret), 1) < 0) {
                        goto done;
                    }
                } else if ((info.auth_methods & HU_SSH_PASSWORD) &&
                           password_tries++ < 3) {
                    if (info.auth_attempt) {
                        fprintf(stderr, "ssh: %s\n", info.message);
                    }
                    auth.method = HU_SSH_PASSWORD;
                    if (prompt("Password: ", secret, sizeof(secret), 1) < 0) {
                        goto done;
                    }
                } else {
                    fprintf(stderr, "ssh: no usable authentication method\n");
                    goto done;
                }
                auth.secret = secret;
                if (hu_ssh_authenticate(session, &auth) < 0) {
                    memset(secret, 0, sizeof(secret));
                    perror("ssh: authentication");
                    goto done;
                }
                memset(secret, 0, sizeof(secret));
            } else if (info.state == HU_SSH_READY ||
                       (info.state == HU_SSH_CLOSED && info.exit_valid)) {
                status = relay(session, options.pty);
                goto done;
            } else if (info.state == HU_SSH_FAILED || info.state == HU_SSH_CLOSED) {
                fprintf(stderr, "ssh: %s\n", info.message);
                goto done;
            }
            pause_ms(100);
        }
    }
done:
    hu_ssh_close(session);
    if (key) {
        memset(key, 0, HU_SSH_MAX_KEY + 1);
        free(key);
    }
    restore();
    raw = 0;
    old_flags = -1;
    return status;
}
