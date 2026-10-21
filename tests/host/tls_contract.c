/* A deliberately non-cryptographic engine exercises the native provider
 * boundary. It is TEST ONLY and never built into the Helios library. */
#include <helios/unix/tls_backend.h>
#include <helios/unix/tls_fd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <stdio.h>
static int closed,destroyed,controls;
struct engine {const struct hu_tls_transport *t;int step,read_again,write_again,shutting;char pending[8];unsigned count;};
static void *create(const struct hu_tls_options *o,const struct hu_tls_transport *t)
{struct engine *e=calloc(1,sizeof(*e));assert(!strcmp(o->peer,"native.example"));e->t=t;return e;}
static int handshake(void *ctx,int *want)
{
    struct engine *e=ctx;char b;int n;
    if(!e->step){e->step=1;*want=HU_TLS_WAIT_READ;return 0;}
    n=e->t->ops->read(e->t->context,&b,1);
    if(n<0 && errno==EAGAIN){*want=HU_TLS_WAIT_READ;return 0;}
    if(n!=1 || b!='H'){errno=EACCES;return -1;}
    e->step=2;return 1;
}
static int receive(void *ctx,void *buf,unsigned n,int *want)
{
    struct engine *e=ctx;char b[8];int k;unsigned i,take;
    if(!e->read_again++){*want=HU_TLS_WAIT_WRITE;errno=EAGAIN;return -1;}
    if(!e->count){
        k=e->t->ops->read(e->t->context,b,sizeof(b));
        if(k<0){*want=HU_TLS_WAIT_READ;return -1;}
        if(!k)return 0;
        for(i=0;i<(unsigned)k;i++)e->pending[i]=b[i]^0x55;
        e->count=k;
    }
    take=n<e->count?n:e->count;memcpy(buf,e->pending,take);
    e->count-=take;memmove(e->pending,e->pending+take,e->count);return take;
}
static int send_data(void *ctx,const void *buf,unsigned n,int *want)
{
    struct engine *e=ctx;char b[2];unsigned i;
    if(!e->write_again++){*want=HU_TLS_WAIT_READ;errno=EAGAIN;return -1;}
    if(n>sizeof(b))n=sizeof(b);
    for(i=0;i<n;i++)b[i]=((const char *)buf)[i]^0x55;
    return e->t->ops->write(e->t->context,b,n);
}
static unsigned pending(void *ctx){return ((struct engine *)ctx)->count;}
static int shutdown_tls(void *ctx,int *want)
{
    struct engine *e=ctx;
    if(!e->shutting++){*want=HU_TLS_WAIT_WRITE;return 0;}
    if(e->shutting==2)assert(e->t->ops->write(e->t->context,"S",1)==1);
    return 1;
}
static int timer(void *ctx,int op){(void)ctx;(void)op;return -1;}
static void info(void *ctx,struct hu_tls_info *i){(void)ctx;strcpy(i->protocol,"TEST-NOT-TLS");}
static void destroy(void *ctx){destroyed++;free(ctx);}
static const struct hu_tls_backend backend={1,"test-only",create,handshake,receive,send_data,pending,shutdown_tls,timer,info,destroy};
static int tr_read(void *p,void *b,unsigned n){return read(*(int *)p,b,n);}
static int tr_write(void *p,const void *b,unsigned n){return write(*(int *)p,b,n);}
static int tr_fd(void *p){return *(int *)p;}
static void tr_close(void *p){closed++;close(*(int *)p);}
static const struct hu_tls_transport_ops byte_ops={tr_read,tr_write,tr_fd,NULL,tr_close};
static const struct hu_tls_transport_ops rejected_ops={tr_read,tr_write,tr_fd,NULL,tr_close};
static void test_byte_transport(void)
{
    int f[2];struct hu_tls *t;struct hu_tls_transport transport;struct hu_tls_info i;struct hu_tls_wait w;
    assert(!socketpair(AF_UNIX,SOCK_STREAM,0,f));transport.ops=&byte_ops;transport.context=&f[0];
    t=hu_tls_create(&backend,NULL,"native.example",100);assert(t);
    assert(!hu_tls_attach(t,&transport));assert(hu_tls_handshake(t)==0);
    assert(!hu_tls_interest(t,HU_TLS_HANDSHAKE,&w) && w.events==HU_TLS_WAIT_READ);
    assert(write(f[1],"H",1)==1);assert(!hu_tls_handshake_wait(t));
    assert(!hu_tls_info(t,&i) && i.state==HU_TLS_READY);
    assert(hu_tls_shutdown(t)==0);assert(hu_tls_wait(t,HU_TLS_SHUTDOWN,100)==1);
    assert(hu_tls_shutdown(t)==1);assert(hu_tls_write(t,"x",1)<0 && errno==EPIPE);
    hu_tls_destroy(t);close(f[1]);assert(closed==1);
    assert(!socketpair(AF_UNIX,SOCK_STREAM,0,f));
    t=hu_tls_create(NULL,NULL,"native.example",100);assert(t);
    transport.ops=&rejected_ops;transport.context=&f[0];
    assert(hu_tls_attach(t,&transport)<0 && errno==EOPNOTSUPP);
    hu_tls_destroy(t);assert(closed==1);close(f[0]);close(f[1]);
}
static void test_fd_adapter(void)
{
    int f[2],plain[2],r;struct hu_tls *t;fd_set rd,wr;struct timeval zero={0,0};char b[8];
    assert(!socketpair(AF_UNIX,SOCK_STREAM,0,f));assert(!pipe(plain));
    t=hu_tls_create(&backend,NULL,"native.example",1000);assert(t);
    assert(!hu_tls_fd_attach(f[0],t));assert(hu_tls_handshake(t)==0);
    assert(write(f[1],"H",1)==1);assert(!hu_tls_handshake_wait(t));
    assert(hu_tls_fd_read(f[0],b,1)<0 && errno==EAGAIN); /* read needs WRITE */
    FD_ZERO(&rd);FD_SET(f[0],&rd);assert(hu_tls_fd_select(f[0]+1,&rd,NULL,NULL,&zero)==1);
    assert(hu_tls_fd_write(f[0],"ABC",3)<0 && errno==EAGAIN); /* write needs READ */
    FD_ZERO(&wr);FD_SET(f[0],&wr);assert(hu_tls_fd_select(f[0]+1,NULL,&wr,NULL,&zero)==0);
    b[0]='a'^0x55;b[1]='b'^0x55;assert(write(f[1],b,2)==2);
    FD_ZERO(&wr);FD_SET(f[0],&wr);assert(hu_tls_fd_select(f[0]+1,NULL,&wr,NULL,&zero)==1);
    assert(hu_tls_fd_write(f[0],"ABC",3)==2);assert(read(f[1],b,2)==2 && b[0]==('A'^0x55) && b[1]==('B'^0x55));
    assert(hu_tls_fd_read(f[0],b,1)==1 && b[0]=='a');assert(hu_tls_pending(t)==1);
    FD_ZERO(&rd);FD_SET(f[0],&rd);
    assert(hu_tls_fd_select(f[0]+1,&rd,NULL,NULL,NULL)==1);
    /* Buffered plaintext is ready without any wire readability; preserve a
     * simultaneous unrelated descriptor in the same event-loop call. */
    assert(write(plain[1],"P",1)==1);
    FD_ZERO(&rd);FD_SET(f[0],&rd);FD_SET(plain[0],&rd);
    r=hu_tls_fd_select((f[0]>plain[0]?f[0]:plain[0])+1,&rd,NULL,NULL,&zero);
    assert(r==2 && FD_ISSET(f[0],&rd) && FD_ISSET(plain[0],&rd));
    assert(hu_tls_fd_read(f[0],b,1)==1 && b[0]=='b');
    assert(!hu_tls_fd_close(f[0]) && !hu_tls_fd_get(f[0]));
    assert(read(f[1],b,1)==1 && b[0]=='S');assert(read(f[1],b,1)==0);close(f[1]);
    assert(hu_tls_fd_read(plain[0],b,1)==1 && b[0]=='P');
    hu_tls_fd_close(plain[0]);hu_tls_fd_close(plain[1]);
    assert(!socketpair(AF_UNIX,SOCK_STREAM,0,f));assert(!hu_tls_fd_get(f[0]));
    assert(write(f[1],"raw",3)==3);assert(hu_tls_fd_read(f[0],b,3)==3 && !memcmp(b,"raw",3));
    hu_tls_fd_close(f[0]);close(f[1]);
}
static void test_failure_cancel_timeout(void)
{
    int f[2];char b;struct hu_tls *t;struct timeval delay={0,130000};struct hu_tls_info i;
    assert(!socketpair(AF_UNIX,SOCK_STREAM,0,f));t=hu_tls_create(&backend,NULL,"native.example",100);assert(t);
    assert(!hu_tls_fd_attach(f[0],t));assert(hu_tls_write(t,"x",1)<0 && errno==EAGAIN);
    assert(!hu_tls_handshake(t));assert(write(f[1],"X",1)==1);
    assert(hu_tls_handshake(t)<0 && errno==EACCES);
    assert(hu_tls_fd_read(f[0],&b,1)<0 && errno==EACCES);
    hu_tls_fd_close(f[0]);close(f[1]);
    assert(!socketpair(AF_UNIX,SOCK_STREAM,0,f));t=hu_tls_create(&backend,NULL,"native.example",100);
    assert(!hu_tls_fd_attach(f[0],t));assert(!hu_tls_handshake(t));select(0,NULL,NULL,NULL,&delay);
    assert(hu_tls_handshake(t)<0 && errno==ETIMEDOUT);
    assert(!hu_tls_info(t,&i) && i.state==HU_TLS_FAILED && i.error==4);
    hu_tls_fd_close(f[0]);assert(read(f[1],&b,1)==0);close(f[1]);
    assert(!socketpair(AF_UNIX,SOCK_STREAM,0,f));t=hu_tls_create(&backend,NULL,"native.example",100);
    assert(!hu_tls_fd_attach(f[0],t));hu_tls_fd_close(f[0]);assert(read(f[1],&b,1)==0);close(f[1]);
}
static void test_no_offload(void)
{
    int f[2];char b;struct hu_tls_info i;
    assert(!socketpair(AF_UNIX,SOCK_STREAM,0,f));
    assert(hu_tls_fd_start(f[0],"native.example",100)<0);
    assert(hu_tls_fd_get(f[0]));
    assert(hu_tls_fd_write(f[0],"MUST NOT LEAK",13)<0);
    assert(!hu_tls_info(hu_tls_fd_get(f[0]),&i) && i.state==HU_TLS_FAILED);
    hu_tls_fd_close(f[0]);assert(read(f[1],&b,1)==0);close(f[1]);
}
int main(void)
{
    test_byte_transport();test_fd_adapter();test_failure_cancel_timeout();test_no_offload();
    assert(destroyed==5 && controls==0);
    puts("PASS native-provider contract: byte-only transport, authentication gate, cross-direction waits, buffered plaintext, partial writes, cancellation, deadlines, fd cleanup");return 0;
}
