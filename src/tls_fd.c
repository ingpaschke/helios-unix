#include <helios/unix/tls_fd.h>
#include <helios/unix/tls_backend.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
/* Per-task legacy adapter. Never expose host-upgrade functions to ports. */
struct entry { int fd;struct hu_tls *tls;struct entry *next; };
static struct entry *entries;
struct socket_transport {int fd;};
static unsigned get32(const unsigned char *p)
{return (unsigned)p[0]|(unsigned)p[1]<<8|(unsigned)p[2]<<16|(unsigned)p[3]<<24;}
static void put32(unsigned char *p,unsigned n)
{p[0]=n;p[1]=n>>8;p[2]=n>>16;p[3]=n>>24;}
static int socket_read(void *ctx,void *buf,unsigned n)
{return read(((struct socket_transport *)ctx)->fd,buf,n);}
static int socket_write(void *ctx,const void *buf,unsigned n)
{return write(((struct socket_transport *)ctx)->fd,buf,n);}
static int socket_fd(void *ctx){return ((struct socket_transport *)ctx)->fd;}
static void socket_close(void *ctx){close(socket_fd(ctx));free(ctx);}
static int socket_control(void *ctx,int op,void *data,unsigned size)
{
    int fd=socket_fd(ctx);unsigned char wire[264];
#ifdef __HELIOS
    int n;
#else
    socklen_t n;
#endif
    struct hu_tls_offload_start *start=data;struct hu_tls_info *info=data;
    switch(op) {
    case HU_TLS_CTL_START:
        if(size!=sizeof(*start)){errno=EINVAL;return -1;}
        n=4;if(getsockopt(fd,0xfff2,0,(char *)wire,&n)<0)return -1;
        if(n!=4 || memcmp(wire,"HTL1",4)){errno=EOPNOTSUPP;return -1;}
        memset(wire,0,sizeof(wire));put32(wire,1);put32(wire+4,start->timeout_ms);
        memcpy(wire+8,start->peer,strlen(start->peer));
        return setsockopt(fd,0xfff2,1,(char *)wire,sizeof(wire));
    case HU_TLS_CTL_STATUS:
        if(size!=sizeof(*info)){errno=EINVAL;return -1;}
        n=224;if(getsockopt(fd,0xfff2,2,(char *)wire,&n)<0)return -1;
        if(n!=224 || memcmp(wire,"HTL1",4) || get32(wire+12) || wire[31] || wire[95] || wire[223]){errno=EIO;return -1;}
        memset(info,0,sizeof(*info));info->state=get32(wire+4);info->error=get32(wire+8);
        memcpy(info->protocol,wire+16,16);memcpy(info->cipher,wire+32,64);memcpy(info->message,wire+96,128);
        if(info->state<HU_TLS_NEGOTIATING || info->state>HU_TLS_CLOSED){errno=EIO;return -1;}
        return 0;
    case HU_TLS_CTL_SHUTDOWN:return shutdown(fd,1);
    default:errno=EOPNOTSUPP;return -1;
    }
}
static const struct hu_tls_transport_ops socket_ops={socket_read,socket_write,socket_fd,socket_control,socket_close};
struct hu_tls *hu_tls_fd_get(int fd)
{struct entry *p;for(p=entries;p;p=p->next)if(p->fd==fd)return p->tls;return NULL;}
int hu_tls_attach_fd(struct hu_tls *tls,int fd)
{
    struct socket_transport *s;struct hu_tls_transport t;int flags,saved;
    if(fd<0 || fd>=FD_SETSIZE || !tls || hu_tls_fd_get(fd)){errno=EINVAL;return -1;}
    flags=fcntl(fd,F_GETFL,0);if(flags<0)return -1;
    s=malloc(sizeof(*s));if(!s){errno=ENOMEM;return -1;}
    s->fd=fd;t.ops=&socket_ops;t.context=s;
    if(fcntl(fd,F_SETFL,flags|O_NONBLOCK)<0){free(s);return -1;}
    if(hu_tls_attach(tls,&t)<0) {
        saved=errno;fcntl(fd,F_SETFL,flags);free(s);errno=saved;return -1;
    }
    return 0;
}
int hu_tls_fd_attach(int fd,struct hu_tls *tls)
{
    struct entry *p=malloc(sizeof(*p));
    if(!p){errno=ENOMEM;return -1;}
    if(hu_tls_attach_fd(tls,fd)<0){free(p);return -1;}
    p->fd=fd;p->tls=tls;p->next=entries;entries=p;return 0;
}
int hu_tls_fd_start(int fd,const char *peer,unsigned timeout)
{
    struct hu_tls *t;int saved;
    if(hu_tls_fd_get(fd)){errno=EALREADY;return -1;}
    t=hu_tls_create(NULL,NULL,peer,timeout);
    if(!t){saved=errno;close(fd);errno=saved;return -1;}
    if(hu_tls_fd_attach(fd,t)<0){saved=errno;hu_tls_destroy(t);close(fd);errno=saved;return -1;}
    /* Even a failure stays registered until close: never fall through to
     * plaintext I/O after failed authentication or an unsupported provider. */
    return hu_tls_handshake(t)<0?-1:0;
}
int hu_tls_fd_handshake(int fd,struct hu_tls_info *info)
{
    struct hu_tls *t=hu_tls_fd_get(fd);int r,saved;
    if(!t || !info){errno=EINVAL;return -1;}
    r=hu_tls_handshake(t);saved=errno;hu_tls_info(t,info);errno=saved;return r;
}
int hu_tls_fd_connect(int fd,const char *peer,unsigned timeout,struct hu_tls_info *info)
{
    struct hu_tls *t;int r,saved;
    if(!info){errno=EINVAL;return -1;}
    memset(info,0,sizeof(*info));r=hu_tls_fd_start(fd,peer,timeout);t=hu_tls_fd_get(fd);
    if(r>=0)r=hu_tls_handshake_wait(t);
    saved=errno;if(t)hu_tls_info(t,info);errno=saved;return r;
}
int hu_tls_fd_read(int fd,void *b,unsigned n)
{struct hu_tls *t=hu_tls_fd_get(fd);return t?hu_tls_read(t,b,n):read(fd,b,n);}
int hu_tls_fd_write(int fd,const void *b,unsigned n)
{struct hu_tls *t=hu_tls_fd_get(fd);return t?hu_tls_write(t,b,n):write(fd,b,n);}
int hu_tls_fd_close(int fd)
{
    struct entry **p=&entries,*e;
    while(*p && (*p)->fd!=fd)p=&(*p)->next;
    if(!*p)return close(fd);
    e=*p;*p=e->next;
    {
        struct hu_tls_info info;struct timeval start,now;int r=1,saved=0,left;
        hu_tls_info(e->tls,&info);
        if(info.state==HU_TLS_READY || info.state==HU_TLS_CLOSED) {
            gettimeofday(&start,NULL);
            while((r=hu_tls_shutdown(e->tls))==0) {
                gettimeofday(&now,NULL);
                left=5000-(now.tv_sec-start.tv_sec)*1000-(now.tv_usec-start.tv_usec)/1000;
                if(left>5000)left=5000;
                if(left<=0){saved=ETIMEDOUT;break;}
                r=hu_tls_wait(e->tls,HU_TLS_SHUTDOWN,left);
                if(r<0 && errno!=EINTR){saved=errno;break;}
                if(!r){saved=ETIMEDOUT;break;}
            }
            if(r<0 && !saved)saved=errno;
        }
        /* Entry is removed before releasing the fd. Never return EINTR after
         * closing it: legacy EINTRLOOP(close) could act on a reused descriptor. */
        hu_tls_destroy(e->tls);free(e);
        if(saved){errno=saved==EINTR?EIO:saved;return -1;}
        return 0;
    }
}
static int add_interest(struct hu_tls *t,int op,struct hu_tls_wait *w,fd_set *r,fd_set *s,int *max,int *timeout)
{
    if(hu_tls_interest(t,op,w)<0)return -1;
    if(w->fd<0 || w->fd>=FD_SETSIZE){errno=EINVAL;return -1;}
    if(w->events&HU_TLS_WAIT_READ)FD_SET(w->fd,r);
    if(w->events&HU_TLS_WAIT_WRITE)FD_SET(w->fd,s);
    if(w->fd>=*max)*max=w->fd+1;
    if(w->timeout_ms>=0 && (*timeout<0 || w->timeout_ms<*timeout))*timeout=w->timeout_ms;
    return 0;
}
static int ready(const struct hu_tls_wait *w,fd_set *r,fd_set *s,int elapsed)
{
    return ((w->events&HU_TLS_WAIT_READ) && FD_ISSET(w->fd,r)) ||
           ((w->events&HU_TLS_WAIT_WRITE) && FD_ISSET(w->fd,s)) ||
           (w->timeout_ms>=0 && elapsed>=w->timeout_ms);
}
struct interest {struct hu_tls_wait read,write;};
int hu_tls_fd_select(int n,fd_set *readfds,fd_set *writefds,fd_set *exceptfds,struct timeval *timeout)
{
    fd_set r,s,x,ir,is,ix;struct timeval tv,start,now;struct interest *plans;
    int i,max=n,ms=-1,result,count=0,elapsed;struct hu_tls *t;
    if(n<0 || n>FD_SETSIZE || (timeout && (timeout->tv_sec<0 || timeout->tv_usec<0 || timeout->tv_usec>=1000000))) {
        errno=EINVAL;return -1;
    }
    if(!entries)return select(n,readfds,writefds,exceptfds,timeout);
    FD_ZERO(&ir);FD_ZERO(&is);FD_ZERO(&ix);
    if(readfds)ir=*readfds;if(writefds)is=*writefds;if(exceptfds)ix=*exceptfds;
    r=ir;s=is;x=ix;
    if(timeout)ms=timeout->tv_sec>2147483?2147483000:timeout->tv_sec*1000+(timeout->tv_usec+999)/1000;
    plans=calloc(n?n:1,sizeof(*plans));if(!plans){errno=ENOMEM;return -1;}
    /* Remove all logical descriptors first, then add physical interests.
     * This also works when a custom transport waits on a different fd. */
    for(i=0;i<n;i++)if(hu_tls_fd_get(i)){FD_CLR(i,&r);FD_CLR(i,&s);FD_CLR(i,&x);}
    for(i=0;i<n;i++)if((t=hu_tls_fd_get(i))!=NULL) {
        if(FD_ISSET(i,&ir) && add_interest(t,HU_TLS_READ,&plans[i].read,&r,&s,&max,&ms)<0)goto fail;
        if(FD_ISSET(i,&is) && add_interest(t,HU_TLS_WRITE,&plans[i].write,&r,&s,&max,&ms)<0)goto fail;
        /* TLS records have no application urgent-data channel. */
    }
    tv.tv_sec=ms<0?0:ms/1000;tv.tv_usec=ms<0?0:ms%1000*1000;
    gettimeofday(&start,NULL);result=select(max,&r,&s,&x,ms<0?NULL:&tv);
    if(result<0)goto fail;
    gettimeofday(&now,NULL);elapsed=(now.tv_sec-start.tv_sec)*1000+(now.tv_usec-start.tv_usec)/1000;
    if(result==0 && ms>=0 && elapsed<ms)elapsed=ms;
    if(readfds)FD_ZERO(readfds);if(writefds)FD_ZERO(writefds);if(exceptfds)FD_ZERO(exceptfds);
    for(i=0;i<n;i++) {
        t=hu_tls_fd_get(i);
        if(FD_ISSET(i,&ir) && (t?ready(&plans[i].read,&r,&s,elapsed):FD_ISSET(i,&r))){FD_SET(i,readfds);count++;}
        if(FD_ISSET(i,&is) && (t?ready(&plans[i].write,&r,&s,elapsed):FD_ISSET(i,&s))){FD_SET(i,writefds);count++;}
        if(!t && FD_ISSET(i,&ix) && FD_ISSET(i,&x)){FD_SET(i,exceptfds);count++;}
    }
    free(plans);return count;
fail:
    free(plans);return -1;
}
