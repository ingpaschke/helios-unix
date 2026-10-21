#include <helios/unix/poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <syslib.h>
#include <gsp.h>
#include <codes.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
/* Private FG_Select mode shared with /fifo and the Linux /internet server.
 * Unlike O_Exception, this does not subscribe to urgent socket data. */
#define HU_O_HANGUP 0x08
static int status(Stream *s,int fd,int *value)
{
    if((s->Type & ~Type_Flags)==Type_Socket) {
        int size=sizeof(*value);
        return getsockopt(fd,SOL_IOCTL,0x4004687f,value,&size);
    }
    if((s->Type & ~Type_Flags)==(Type_Fifo & ~Type_Flags)) {
        MCB m;word data[2],rc;Port reply=NewPort();
        if(reply==NullPort){errno=ENOMEM;return -1;}
        Wait(&s->Mutex);
        InitMCB(&m,MsgHdr_Flags_preserve,s->Server,reply,FC_GSP|FG_GetSize|s->FnMod);
        m.Control=data;m.Data=NULL;m.Timeout=10*OneSec;
        rc=PutMsg(&m);
        if(rc>=0){m.MsgHdr.Dest=reply;m.Timeout=10*OneSec;rc=GetMsg(&m);}
        Signal(&s->Mutex);FreePort(reply);
        if(rc<0 || m.MsgHdr.ContSize!=2){errno=EIO;return -1;}
        *value=data[1];return 0;
    }
    {
        struct stat st;
        if(fstat(fd,&st)<0)return -1;
        if(!S_ISREG(st.st_mode)){errno=EOPNOTSUPP;return -1;}
    }
    *value=HU_POLLIN|HU_POLLOUT;return 0;
}
int hu_poll(struct hu_pollfd *fds,unsigned count,int timeout)
{
    Stream **streams;word *modes;unsigned i;int ready=0,bits,n,active=0;word rc;
    struct timeval zero={0,0};
    if((!fds&&count)||count>65536){errno=EINVAL;return -1;}
    /* Preserve POSIX's synchronous signal checks without a periodic timer. */
    if(select(0,NULL,NULL,NULL,&zero)<0)return -1;
    streams=calloc(count?count:1,sizeof(*streams));modes=calloc(count?count:1,sizeof(*modes));
    if(!streams||!modes){free(streams);free(modes);errno=ENOMEM;return -1;}
    for(i=0;i<count;i++) {
        Stream *s;
        fds[i].revents=0;if(fds[i].fd<0)continue;
        s=fdstream(fds[i].fd);
        if(!s){fds[i].revents=HU_POLLNVAL;ready++;continue;}
        if(s->Type==Type_Pseudo) {
            Wait(&s->Mutex);rc=s->Type==Type_Pseudo?ReOpen(s):0;Signal(&s->Mutex);
            if(rc<0){errno=EIO;goto fail;}
        }
        if((s->Type & ~Type_Flags)!=Type_Socket &&
           (s->Type & ~Type_Flags)!=(Type_Fifo & ~Type_Flags) &&
           (s->Type & ~Type_Flags)!=(Type_File & ~Type_Flags)) {
            errno=EOPNOTSUPP;goto fail;
        }
        if(status(s,fds[i].fd,&bits)<0)goto fail;
        fds[i].revents=bits & (fds[i].events|HU_POLLERR|HU_POLLHUP|HU_POLLNVAL);
        if(fds[i].revents)ready++;
        streams[i]=s;
        if((s->Type & ~Type_Flags)==(Type_File & ~Type_Flags))continue;
        if((s->Type & ~Type_Flags)==Type_Socket ||
           (s->Type & ~Type_Flags)==(Type_Fifo & ~Type_Flags))
            modes[i]|=HU_O_HANGUP;
        if(fds[i].events&HU_POLLIN)modes[i]|=O_ReadOnly;
        if(fds[i].events&HU_POLLOUT)modes[i]|=O_WriteOnly;
        if(fds[i].events&HU_POLLPRI)modes[i]|=O_Exception;
        if(modes[i])active++;
    }
    if(ready||timeout==0)goto done;
    if(!active) {
        struct timeval wait;
        wait.tv_sec=timeout/1000;wait.tv_usec=(timeout%1000)*1000;
        if(select(0,NULL,NULL,NULL,timeout<0?NULL:&wait)<0)goto fail;
        goto done;
    }
    /* One native subscription per stream. No per-fd 100 Hz RPC loop. */
    rc=SelectStream(count,streams,modes,timeout<0?-1:
                    timeout>2147483?2147483000:timeout*1000);
    if(select(0,NULL,NULL,NULL,&zero)<0)goto fail;
    if(rc<0 && (rc&EG_Mask)!=EG_Timeout) {
        errno=(rc&EG_Mask)==EG_Exception?EINTR:EIO;goto fail;
    }
    if(rc>0)for(i=0;i<count;i++)if(modes[i]&O_Selected) {
        if(status(streams[i],fds[i].fd,&bits)<0)goto fail;
        fds[i].revents=bits & (fds[i].events|HU_POLLERR|HU_POLLHUP|HU_POLLNVAL);
        if(fds[i].revents)ready++;
    }
    if(select(0,NULL,NULL,NULL,&zero)<0)goto fail;
done:
    n=ready;free(streams);free(modes);return n;
fail:
    free(streams);free(modes);return -1;
}
