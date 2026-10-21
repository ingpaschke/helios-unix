#include <helios/unix/tls_backend.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
struct offload {
    const struct hu_tls_transport *transport;
    struct hu_tls_offload_start start;
    struct hu_tls_info info;
    int started,shutdown;
};
static void *create(const struct hu_tls_options *o,const struct hu_tls_transport *t)
{
    struct offload *p;
    if(!t->ops->control || o->configuration){errno=EOPNOTSUPP;return NULL;}
    p=calloc(1,sizeof(*p));if(!p){errno=ENOMEM;return NULL;}
    p->transport=t;p->start.peer=o->peer;p->start.timeout_ms=o->timeout_ms;
    p->info.state=HU_TLS_NEGOTIATING;return p;
}
static int handshake(void *ctx,int *want)
{
    struct offload *p=ctx;int r;
    *want=0; /* Host negotiation is queried on a timer, not socket writability. */
    if(!p->started) {
        if(p->transport->ops->control(p->transport->context,HU_TLS_CTL_START,&p->start,sizeof(p->start))<0)return -1;
        p->started=1;
    }
    r=p->transport->ops->control(p->transport->context,HU_TLS_CTL_STATUS,&p->info,sizeof(p->info));
    if(r<0)return -1;
    if(p->info.state==HU_TLS_NEGOTIATING)return 0;
    if(p->info.state==HU_TLS_READY)return 1;
    errno=p->info.error==2?EACCES:p->info.error==4?ETIMEDOUT:ECONNRESET;return -1;
}
static int receive(void *ctx,void *b,unsigned n,int *want)
{struct offload *p=ctx;*want=HU_TLS_WAIT_READ;return p->transport->ops->read(p->transport->context,b,n);}
static int send_data(void *ctx,const void *b,unsigned n,int *want)
{struct offload *p=ctx;*want=HU_TLS_WAIT_WRITE;return p->transport->ops->write(p->transport->context,b,n);}
static unsigned pending(void *ctx){(void)ctx;return 0;} /* plaintext is in the waitable host pipe */
static int finish(void *ctx,int *want)
{
    struct offload *p=ctx;*want=0;
    if(p->shutdown)return 1;
    if(p->transport->ops->control(p->transport->context,HU_TLS_CTL_SHUTDOWN,NULL,0)<0)return -1;
    p->shutdown=1;return 1; /* host worker drains accepted data asynchronously */
}
static int timer(void *ctx,int op){(void)ctx;return op==HU_TLS_HANDSHAKE?20:-1;}
static void info(void *ctx,struct hu_tls_info *i){*i=((struct offload *)ctx)->info;}
static void destroy(void *ctx){free(ctx);}
const struct hu_tls_backend hu_tls_offload_backend={1,"host-offload",create,handshake,receive,send_data,pending,finish,timer,info,destroy};
