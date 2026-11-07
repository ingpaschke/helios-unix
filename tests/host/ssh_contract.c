#include <helios/unix/ssh_backend.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
static int closes, destroys, deny;

struct engine {
    const struct hu_ssh_transport *t;
    int ready;
};

static int input(void *p, void *b, unsigned n)
{
    (void)p;
    if (n) {
        memset(b, 'x', n);
    }
    return n;
}

static int output(void *p, const void *b, unsigned n)
{
    (void)p;
    (void)b;
    return n;
}

static int descriptor(void *p)
{
    (void)p;
    return 7;
}

static void close_transport(void *p)
{
    (void)p;
    closes++;
}
static const struct hu_ssh_transport_ops byte_ops = {input, output, descriptor, NULL,
                                                     close_transport};

static void *open_engine(const struct hu_ssh_options *o,
                         const struct hu_ssh_transport *t)
{
    struct engine *e;
    assert(!strcmp(o->host, "example"));
    if (deny) {
        errno = EIO;
        return NULL;
    }
    e = calloc(1, sizeof(*e));
    e->t = t;
    return e;
}

static int status(void *p, struct hu_ssh_info *i)
{
    memset(i, 0, sizeof(*i));
    i->state = ((struct engine *)p)->ready ? HU_SSH_READY : HU_SSH_HOSTKEY;
    return 0;
}

static int trust(void *p, int accept)
{
    ((struct engine *)p)->ready = accept;
    return 0;
}

static int auth(void *p, const struct hu_ssh_auth *a)
{
    (void)p;
    assert(a->method == HU_SSH_PASSWORD);
    return 0;
}

static int resize(void *p, unsigned c, unsigned r)
{
    (void)p;
    assert(c == 132 && r == 43);
    return 0;
}

static int read_engine(void *p, void *b, unsigned n)
{
    struct engine *e = p;
    return e->t->ops->read(e->t->context, b, n);
}

static int write_engine(void *p, const void *b, unsigned n)
{
    struct engine *e = p;
    return e->t->ops->write(e->t->context, b, n);
}

static int eof(void *p)
{
    (void)p;
    return 0;
}

static int interest(void *p, int op, struct hu_ssh_wait *w)
{
    (void)p;
    (void)op;
    w->events = HU_SSH_WAIT_WRITE;
    w->timeout_ms = 0;
    return 0;
}

static void destroy(void *p)
{
    destroys++;
    free(p);
}
const struct hu_ssh_backend hu_ssh_offload_backend = {
    1,      "mock-native", open_engine,  status, trust,    auth,
    resize, read_engine,   write_engine, eof,    interest, destroy};

int main(void)
{
    struct hu_ssh_options o = {"example", "user", "xterm", NULL, 22,
                               80,        24,     30000,   1,    NULL};
    struct hu_ssh_transport t = {&byte_ops, NULL};
    struct hu_ssh_info i;
    struct hu_ssh_auth a = {HU_SSH_PASSWORD, "password", NULL, 0};
    struct hu_ssh *s;
    char bytes[4];
    struct hu_ssh_wait w;
    s = hu_ssh_open(NULL, &o, &t);
    assert(s);
    assert(hu_ssh_status(s, &i) == 0 && i.state == HU_SSH_HOSTKEY);
    assert(hu_ssh_trust(s, 1) == 0 && hu_ssh_status(s, &i) == 0 &&
           i.state == HU_SSH_READY);
    assert(hu_ssh_authenticate(s, &a) == 0 && hu_ssh_resize(s, 132, 43) == 0);
    assert(hu_ssh_resize(s, 0, 43) == -1 && errno == EINVAL);
    assert(hu_ssh_read(s, bytes, 4) == 4 && !memcmp(bytes, "xxxx", 4));
    assert(hu_ssh_write(s, bytes, 4) == 4 && hu_ssh_wait_fd(s) == 7 &&
           hu_ssh_send_eof(s) == 0);
    assert(hu_ssh_interest(s, HU_SSH_READ, &w) == 0 && w.fd == 7 &&
           w.events == HU_SSH_WAIT_WRITE && w.timeout_ms == 0);
    assert(hu_ssh_read(s, NULL, 1) == -1 && errno == EINVAL);
    hu_ssh_close(s);
    assert(closes == 1 && destroys == 1);
    deny = 1;
    assert(!hu_ssh_open(NULL, &o, &t) && errno == EIO);
    assert(closes == 1);
    o.port = 0;
    assert(!hu_ssh_open(NULL, &o, &t) && errno == EINVAL);
    hu_ssh_close(NULL);
    return 0;
}
