#include <helios/unix/ssh_backend.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#ifndef HU_SSH_DEFAULT_BACKEND
#define HU_SSH_DEFAULT_BACKEND hu_ssh_offload_backend
#endif
extern const struct hu_ssh_backend HU_SSH_DEFAULT_BACKEND;
struct hu_ssh {
    const struct hu_ssh_backend *backend;
    struct hu_ssh_transport transport;
    void *engine;
};
struct hu_ssh *hu_ssh_open(const struct hu_ssh_backend *b,
    const struct hu_ssh_options *o, const struct hu_ssh_transport *t)
{
    struct hu_ssh *s;
    if(!b)b=&HU_SSH_DEFAULT_BACKEND;
    if(!o || !o->host || !*o->host || !o->user || !*o->user ||
       !o->port || o->port>65535 || o->columns>65535 || o->rows>65535 ||
       o->timeout_ms<100 || o->timeout_ms>120000 || !t || !t->ops ||
       !t->ops->read || !t->ops->write || !t->ops->wait_fd || !t->ops->close ||
       b->version!=1 || !b->open || !b->status || !b->trust ||
       !b->authenticate || !b->resize || !b->read || !b->write || !b->eof || !b->interest || !b->destroy) {
        errno=EINVAL;return NULL;
    }
    s=calloc(1,sizeof(*s));if(!s){errno=ENOMEM;return NULL;}
    s->backend=b;s->transport=*t;
    s->engine=b->open(o,&s->transport);
    if(!s->engine){free(s);return NULL;}
    return s;
}
int hu_ssh_status(struct hu_ssh *s,struct hu_ssh_info *i)
{if(!s||!i){errno=EINVAL;return -1;}return s->backend->status(s->engine,i);}
int hu_ssh_trust(struct hu_ssh *s,int accept)
{if(!s){errno=EINVAL;return -1;}return s->backend->trust(s->engine,accept!=0);}
int hu_ssh_authenticate(struct hu_ssh *s,const struct hu_ssh_auth *a)
{
    if(!s||!a || (a->method!=HU_SSH_PASSWORD && a->method!=HU_SSH_PUBLICKEY) ||
       (a->method==HU_SSH_PUBLICKEY && (!a->key || !a->key_size || a->key_size>HU_SSH_MAX_KEY))) {
        errno=EINVAL;return -1;
    }
    return s->backend->authenticate(s->engine,a);
}
int hu_ssh_resize(struct hu_ssh *s,unsigned c,unsigned r)
{if(!s||!c||!r||c>65535||r>65535){errno=EINVAL;return -1;}return s->backend->resize(s->engine,c,r);}
int hu_ssh_read(struct hu_ssh *s,void *b,unsigned n)
{if(!s||(!b&&n)){errno=EINVAL;return -1;}return n?s->backend->read(s->engine,b,n):0;}
int hu_ssh_write(struct hu_ssh *s,const void *b,unsigned n)
{if(!s||(!b&&n)){errno=EINVAL;return -1;}return n?s->backend->write(s->engine,b,n):0;}
int hu_ssh_send_eof(struct hu_ssh *s)
{if(!s){errno=EINVAL;return -1;}return s->backend->eof(s->engine);}
int hu_ssh_wait_fd(struct hu_ssh *s)
{if(!s){errno=EINVAL;return -1;}return s->transport.ops->wait_fd(s->transport.context);}
int hu_ssh_interest(struct hu_ssh *s,int op,struct hu_ssh_wait *w)
{
    if(!s||!w||op<HU_SSH_READ||op>HU_SSH_PROGRESS){errno=EINVAL;return -1;}
    w->fd=hu_ssh_wait_fd(s);w->events=0;w->timeout_ms=-1;
    return s->backend->interest(s->engine,op,w);
}
void hu_ssh_close(struct hu_ssh *s)
{if(s){s->backend->destroy(s->engine);s->transport.ops->close(s->transport.context);free(s);}}
