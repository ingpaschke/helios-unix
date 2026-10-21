#include <helios/unix/tls_backend.h>
#include <sys/types.h>
#include <sys/time.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#ifndef HU_TLS_DEFAULT_BACKEND
#define HU_TLS_DEFAULT_BACKEND hu_tls_offload_backend
#endif
extern const struct hu_tls_backend HU_TLS_DEFAULT_BACKEND;
struct hu_tls {
    const struct hu_tls_backend *backend;
    struct hu_tls_options options;
    struct hu_tls_transport transport;
    void *engine;
    char peer[256];
    unsigned state;
    int want[5],failure,closing;
    struct timeval started;
};
static int remaining(struct hu_tls *t)
{
    struct timeval now;long elapsed;
    gettimeofday(&now,0);
    elapsed=(now.tv_sec-t->started.tv_sec)*1000+(now.tv_usec-t->started.tv_usec)/1000;
    if(elapsed<0)elapsed=0;
    return elapsed>=(long)t->options.timeout_ms?0:t->options.timeout_ms-elapsed;
}
static int failed(struct hu_tls *t,int error)
{t->state=HU_TLS_FAILED;t->failure=error?error:EIO;errno=t->failure;return -1;}
struct hu_tls *hu_tls_create(const struct hu_tls_backend *b,const void *config,const char *peer,unsigned timeout)
{
    struct hu_tls *t;
    if(!b)b=&HU_TLS_DEFAULT_BACKEND;
    if(!peer || !*peer || strlen(peer)>255 || timeout<100 || timeout>120000 ||
       b->version!=1 || !b->create || !b->handshake || !b->read || !b->write ||
       !b->pending || !b->shutdown || !b->timer_ms || !b->info || !b->destroy) {
        errno=EINVAL;return NULL;
    }
    t=calloc(1,sizeof(*t));if(!t){errno=ENOMEM;return NULL;}
    strcpy(t->peer,peer);t->options.peer=t->peer;t->options.timeout_ms=timeout;
    t->options.configuration=config;t->backend=b;t->state=HU_TLS_NEGOTIATING;
    t->want[HU_TLS_READ]=HU_TLS_WAIT_READ;t->want[HU_TLS_WRITE]=HU_TLS_WAIT_WRITE;
    return t;
}
int hu_tls_attach(struct hu_tls *t,const struct hu_tls_transport *transport)
{
    if(!t || t->engine || !transport || !transport->ops || !transport->ops->read ||
       !transport->ops->write || !transport->ops->wait_fd || !transport->ops->close) {
        errno=EINVAL;return -1;
    }
    t->transport=*transport;
    t->engine=t->backend->create(&t->options,&t->transport);
    if(!t->engine){memset(&t->transport,0,sizeof(t->transport));return -1;}
    gettimeofday(&t->started,0);return 0;
}
int hu_tls_handshake(struct hu_tls *t)
{
    int r;
    if(!t || !t->engine){errno=EINVAL;return -1;}
    if(t->state==HU_TLS_READY && !t->closing)return 1;
    if(t->state!=HU_TLS_NEGOTIATING){errno=t->failure?t->failure:EPIPE;return -1;}
    if(!remaining(t))return failed(t,ETIMEDOUT);
    r=t->backend->handshake(t->engine,&t->want[HU_TLS_HANDSHAKE]);
    if(r<0)return failed(t,errno);
    if(r>0)t->state=HU_TLS_READY;
    return r>0?1:0;
}
static int usable(struct hu_tls *t)
{
    if(!t || !t->engine){errno=EINVAL;return 0;}
    if(t->state==HU_TLS_FAILED){errno=t->failure;return 0;}
    if(t->state==HU_TLS_NEGOTIATING){errno=EAGAIN;return 0;}
    return 1;
}
int hu_tls_read(struct hu_tls *t,void *buf,unsigned n)
{
    int r;
    if(!usable(t))return -1;
    if(!n)return 0;
    if(!buf){errno=EINVAL;return -1;}
    if(t->state==HU_TLS_CLOSED)return 0;
    t->want[HU_TLS_READ]=HU_TLS_WAIT_READ;
    r=t->backend->read(t->engine,buf,n,&t->want[HU_TLS_READ]);
    if(r<0 && errno!=EAGAIN && errno!=EWOULDBLOCK && errno!=EINTR)return failed(t,errno);
    if(!r)t->state=HU_TLS_CLOSED;
    return r;
}
int hu_tls_write(struct hu_tls *t,const void *buf,unsigned n)
{
    int r;
    if(!usable(t))return -1;
    if(t->closing || t->state==HU_TLS_CLOSED){errno=EPIPE;return -1;}
    if(!n)return 0;
    if(!buf){errno=EINVAL;return -1;}
    t->want[HU_TLS_WRITE]=HU_TLS_WAIT_WRITE;
    r=t->backend->write(t->engine,buf,n,&t->want[HU_TLS_WRITE]);
    if(!r)return failed(t,EPIPE);
    if(r<0 && errno!=EAGAIN && errno!=EWOULDBLOCK && errno!=EINTR)return failed(t,errno);
    return r;
}
unsigned hu_tls_pending(struct hu_tls *t)
{return t && t->engine && t->state==HU_TLS_READY?t->backend->pending(t->engine):0;}
int hu_tls_info(struct hu_tls *t,struct hu_tls_info *info)
{
    if(!t || !info){errno=EINVAL;return -1;}
    memset(info,0,sizeof(*info));if(t->engine)t->backend->info(t->engine,info);
    info->state=t->state;
    if(t->failure && !info->message[0]) {
        strncpy(info->message,strerror(t->failure),sizeof(info->message)-1);
        info->error=t->failure==ETIMEDOUT?4:1;
    }
    return 0;
}
int hu_tls_interest(struct hu_tls *t,int op,struct hu_tls_wait *w)
{
    int left;
    if(!t || !t->engine || !w || op<1 || op>4){errno=EINVAL;return -1;}
    w->fd=t->transport.ops->wait_fd(t->transport.context);
    w->events=t->want[op];w->timeout_ms=t->backend->timer_ms(t->engine,op);
    if(t->state==HU_TLS_FAILED || t->state==HU_TLS_CLOSED ||
       (op==HU_TLS_READ && hu_tls_pending(t)))w->timeout_ms=0;
    if(op==HU_TLS_HANDSHAKE) {
        if(t->state==HU_TLS_READY)w->timeout_ms=0;
        else {left=remaining(t);if(w->timeout_ms<0 || left<w->timeout_ms)w->timeout_ms=left;}
    }
    return 0;
}
int hu_tls_wait(struct hu_tls *t,int op,int timeout)
{
    struct hu_tls_wait w;fd_set r,s;struct timeval tv;int result;
    if(timeout< -1){errno=EINVAL;return -1;}
    if(hu_tls_interest(t,op,&w)<0)return -1;
    if(w.timeout_ms>=0 && (timeout<0 || w.timeout_ms<timeout))timeout=w.timeout_ms;
    if(w.fd<0 || w.fd>=FD_SETSIZE){errno=EINVAL;return -1;}
    FD_ZERO(&r);FD_ZERO(&s);
    if(w.events&HU_TLS_WAIT_READ)FD_SET(w.fd,&r);
    if(w.events&HU_TLS_WAIT_WRITE)FD_SET(w.fd,&s);
    tv.tv_sec=timeout<0?0:timeout/1000;tv.tv_usec=timeout<0?0:timeout%1000*1000;
    result=select(w.fd+1,&r,&s,NULL,timeout<0?NULL:&tv);
    if(result<0)return -1;
    /* A provider timer is a reason to retry, not an application timeout. */
    return result>0 || (w.timeout_ms>=0 && w.timeout_ms==timeout)?1:0;
}
int hu_tls_handshake_wait(struct hu_tls *t)
{
    int r;
    while((r=hu_tls_handshake(t))==0)if(hu_tls_wait(t,HU_TLS_HANDSHAKE,-1)<0)return -1;
    return r<0?-1:0;
}
int hu_tls_shutdown(struct hu_tls *t)
{
    int r;
    if(!usable(t))return -1;
    t->closing=1;
    r=t->backend->shutdown(t->engine,&t->want[HU_TLS_SHUTDOWN]);
    if(r<0)return failed(t,errno);
    return r;
}
void hu_tls_destroy(struct hu_tls *t)
{
    if(!t)return;
    if(t->engine){t->backend->destroy(t->engine);t->transport.ops->close(t->transport.context);}
    free(t);
}
