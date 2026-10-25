#include <helios/unix/ssh_backend.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
/* Private HSH1 wire ABI; no application or native provider uses these controls. */
#define SSH_LEVEL 0xfff3
#define START_SIZE 1184
#define STATUS_SIZE 508
#define AUTH_SIZE 8720
static unsigned get32(const unsigned char *p)
{return (unsigned)p[0]|(unsigned)p[1]<<8|(unsigned)p[2]<<16|(unsigned)p[3]<<24;}
static void put32(unsigned char *p,unsigned n)
{p[0]=n;p[1]=n>>8;p[2]=n>>16;p[3]=n>>24;}
struct offload {const struct hu_ssh_transport *transport;};
static int control(struct offload *p,int op,void *wire,unsigned n)
{
    /* SetSocketInfo has a 512-byte IOC buffer, including its framing. */
    unsigned pos=0,expected=n;unsigned char chunk[492];int rc;
    if(op==1||op==4) {
        while(pos<n) {
            unsigned count=n-pos>480?480:n-pos,size=count+12;
            put32(chunk,op);put32(chunk+4,n);put32(chunk+8,pos);
            memcpy(chunk+12,(unsigned char *)wire+pos,count);
            if(p->transport->ops->control(p->transport->context,7,chunk,&size)<0)return -1;
            pos+=count;
        }
        return 0;
    }
    rc=p->transport->ops->control(p->transport->context,op,wire,&n);
    if(rc==0 && n!=expected){errno=EIO;return -1;}
    return rc;
}
static void *open_session(const struct hu_ssh_options *o,const struct hu_ssh_transport *t)
{
    struct offload *p;unsigned char w[START_SIZE];
    const char *term=o->terminal?o->terminal:"vt100",*cmd=o->command?o->command:"";
    if(!t->ops->control){errno=EOPNOTSUPP;return NULL;}
    if(strlen(o->host)>255||strlen(o->user)>63||strlen(term)>63||strlen(cmd)>767){errno=E2BIG;return NULL;}
    p=malloc(sizeof(*p));if(!p){errno=ENOMEM;return NULL;}p->transport=t;
    if(control(p,0,w,4)<0){free(p);return NULL;}
    if(memcmp(w,"HSH1",4)){free(p);errno=EOPNOTSUPP;return NULL;}
    memset(w,0,sizeof(w));put32(w,1);put32(w+4,o->timeout_ms);put32(w+8,o->port);
    put32(w+12,o->columns);put32(w+16,o->rows);put32(w+20,o->pty!=0);
    strcpy((char *)w+32,o->host);strcpy((char *)w+288,o->user);
    strcpy((char *)w+352,term);strcpy((char *)w+416,cmd);
    if(control(p,1,w,sizeof(w))<0){free(p);return NULL;}return p;
}
static int status(void *ctx,struct hu_ssh_info *i)
{
    unsigned char w[STATUS_SIZE];struct offload *p=ctx;
    if(control(p,2,w,sizeof(w))<0)return -1;
    if(memcmp(w,"HSH1",4)||w[95]||w[191]||w[507]||get32(w+4)<1||get32(w+4)>7){errno=EIO;return -1;}
    memset(i,0,sizeof(*i));i->state=get32(w+4);i->error=get32(w+8);
    i->exit_status=(int)get32(w+12);i->exit_valid=get32(w+16);
    i->auth_methods=get32(w+20);i->auth_attempt=get32(w+24);
    memcpy(i->key_type,w+32,64);memcpy(i->fingerprint,w+96,96);memcpy(i->message,w+192,316);return 0;
}
static int trust(void *ctx,int accept)
{unsigned char w[4];put32(w,accept);return control(ctx,3,w,4);}
static int authenticate(void *ctx,const struct hu_ssh_auth *a)
{
    unsigned char *w;int r;const char *secret=a->secret?a->secret:"";
    if(strlen(secret)>511){errno=E2BIG;return -1;}
    w=calloc(1,AUTH_SIZE);if(!w){errno=ENOMEM;return -1;}
    put32(w,a->method);put32(w+4,a->method==HU_SSH_PUBLICKEY?a->key_size:0);
    strcpy((char *)w+16,secret);
    if(a->method==HU_SSH_PUBLICKEY)memcpy(w+528,a->key,a->key_size);
    r=control(ctx,4,w,AUTH_SIZE);memset(w,0,AUTH_SIZE);free(w);return r;
}
static int resize(void *ctx,unsigned c,unsigned r)
{unsigned char w[8];put32(w,c);put32(w+4,r);return control(ctx,5,w,8);}
static int receive(void *ctx,void *b,unsigned n)
{struct offload *p=ctx;return p->transport->ops->read(p->transport->context,b,n);}
static int send_data(void *ctx,const void *b,unsigned n)
{struct offload *p=ctx;return p->transport->ops->write(p->transport->context,b,n);}
static int eof(void *ctx){unsigned char w[4]={0,0,0,0};return control(ctx,6,w,4);}
static int interest(void *ctx,int op,struct hu_ssh_wait *w)
{(void)ctx;w->events=op==HU_SSH_WRITE?HU_SSH_WAIT_WRITE:HU_SSH_WAIT_READ;w->timeout_ms=op==HU_SSH_PROGRESS?100:-1;return 0;}
const struct hu_ssh_backend hu_ssh_offload_backend={1,"host-offload",open_session,status,trust,authenticate,resize,receive,send_data,eof,interest,free};
struct socket_transport {int fd;};
static int socket_read(void *ctx,void *b,unsigned n){return read(((struct socket_transport *)ctx)->fd,b,n);}
static int socket_write(void *ctx,const void *b,unsigned n){return write(((struct socket_transport *)ctx)->fd,b,n);}
static int socket_fd(void *ctx){return ((struct socket_transport *)ctx)->fd;}
static int socket_control(void *ctx,int op,void *w,unsigned *n)
{
    int fd=socket_fd(ctx),r;
#ifdef __HELIOS
    int size=*n;
#else
    socklen_t size=*n;
#endif
    if(op==0||op==2){r=getsockopt(fd,SSH_LEVEL,op,w,&size);if(r==0 && size!=*n){errno=EIO;return -1;}return r;}
    return setsockopt(fd,SSH_LEVEL,op,w,*n);
}
static void socket_close(void *ctx){close(socket_fd(ctx));free(ctx);}
static const struct hu_ssh_transport_ops socket_ops={socket_read,socket_write,socket_fd,socket_control,socket_close};
struct hu_ssh *hu_ssh_open_fd(const struct hu_ssh_options *o,int fd)
{
    struct socket_transport *p;struct hu_ssh_transport t;struct hu_ssh *s;int flags,saved;
    flags=fcntl(fd,F_GETFL);if(flags<0)return NULL;
    if(fcntl(fd,F_SETFL,flags|O_NONBLOCK)<0)return NULL;
    p=malloc(sizeof(*p));if(!p){errno=ENOMEM;goto fail;}
    p->fd=fd;t.ops=&socket_ops;t.context=p;s=hu_ssh_open(NULL,o,&t);
    if(s)return s;free(p);
fail:
    saved=errno;fcntl(fd,F_SETFL,flags);errno=saved;return NULL;
}
