#ifndef HELIOS_UNIX_SSH_H
#define HELIOS_UNIX_SSH_H
/* SSH session API. Providers may implement SSH locally or offload it. */
#define HU_SSH_CONNECTING 1
#define HU_SSH_HOSTKEY 2
#define HU_SSH_AUTH 3
#define HU_SSH_OPENING 4
#define HU_SSH_READY 5
#define HU_SSH_CLOSED 6
#define HU_SSH_FAILED 7
#define HU_SSH_PASSWORD 1
#define HU_SSH_PUBLICKEY 2
#define HU_SSH_MAX_KEY 8192
#define HU_SSH_READ 1
#define HU_SSH_WRITE 2
#define HU_SSH_PROGRESS 3
#define HU_SSH_WAIT_READ 1
#define HU_SSH_WAIT_WRITE 2
struct hu_ssh_wait { int fd, events, timeout_ms; };
struct hu_ssh_options {
    const char *host, *user, *terminal, *command;
    unsigned port, columns, rows, timeout_ms;
    int pty;
    const void *configuration; /* provider-specific settings, normally NULL */
};
struct hu_ssh_info {
    int state, error, exit_status, exit_valid;
    unsigned auth_methods, auth_attempt;
    char key_type[64], fingerprint[96], message[320];
};
struct hu_ssh_auth {
    unsigned method;
    const char *secret; /* password or private-key passphrase */
    const char *key;
    unsigned key_size;
};
struct hu_ssh;
struct hu_ssh_backend;
struct hu_ssh_transport;
/* On success the session owns the transport; on failure the caller owns it.
 * Read/write are nonblocking. Authentication and host-key decisions are
 * explicit, and must be driven using hu_ssh_status. */
struct hu_ssh *hu_ssh_open(const struct hu_ssh_backend *,
    const struct hu_ssh_options *, const struct hu_ssh_transport *);
/* Convenience adapter: takes a connected TCP fd on success only. */
struct hu_ssh *hu_ssh_open_fd(const struct hu_ssh_options *, int fd);
int hu_ssh_status(struct hu_ssh *, struct hu_ssh_info *);
int hu_ssh_trust(struct hu_ssh *, int accept);
int hu_ssh_authenticate(struct hu_ssh *, const struct hu_ssh_auth *);
int hu_ssh_resize(struct hu_ssh *, unsigned columns, unsigned rows);
int hu_ssh_read(struct hu_ssh *, void *, unsigned);
int hu_ssh_write(struct hu_ssh *, const void *, unsigned);
int hu_ssh_send_eof(struct hu_ssh *);
int hu_ssh_wait_fd(struct hu_ssh *);
int hu_ssh_interest(struct hu_ssh *, int operation, struct hu_ssh_wait *);
void hu_ssh_close(struct hu_ssh *);
#endif
