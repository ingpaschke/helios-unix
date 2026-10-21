#include <helios/unix/api.h>
#include <helios/unix/channel.h>
#include <helios/unix/poll.h>
#include <syslib.h>
#include <gsp.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#undef CHECK
#define CHECK(x) do{if(!(x)){printf("FAIL native channel line %d errno=%d: %s\n",__LINE__,errno,#x);return 1;}}while(0)
int main(void)
{
    int fd[2],n,total,i,alias;
    char data[1024],readback[1024];
    struct hu_pollfd p;
    signal(SIGPIPE,SIG_IGN);
    memset(data,'Q',sizeof(data));
    CHECK(hu_channel(fd)==0);
    CHECK((fdstream(fd[0])->Type & ~Type_Flags)==(Type_Fifo & ~Type_Flags));
    CHECK(hu_set_nonblock(fd[0],1)==0);
    CHECK(read(fd[0],readback,1)==-1 && (errno==EAGAIN || errno==EWOULDBLOCK));
    p.fd=fd[0];p.events=HU_POLLIN;
    CHECK(hu_poll(&p,1,20)==0);
    CHECK(hu_set_nonblock(fd[1],1)==0);
    for(total=0;total<65536;) {
        n=write(fd[1],data,sizeof(data));
        if(n<0){CHECK(errno==EAGAIN || errno==EWOULDBLOCK);break;}
        CHECK(n>0);total+=n;
    }
    CHECK(total==16384);
    p.fd=fd[1];p.events=HU_POLLOUT;CHECK(hu_poll(&p,1,0)==0);
    CHECK(read(fd[0],readback,sizeof(readback))==sizeof(readback));
    CHECK(!memcmp(data,readback,sizeof(data)));
    CHECK(hu_poll(&p,1,100)==1 && (p.revents&HU_POLLOUT));
    alias=dup(fd[1]);CHECK(alias>=0);
    CHECK(close(fd[1])==0);
    for(i=1024;i<total;i+=1024)CHECK(read(fd[0],readback,sizeof(readback))==1024);
    p.fd=fd[0];p.events=HU_POLLIN;CHECK(hu_poll(&p,1,0)==0);
    CHECK(close(alias)==0);
    CHECK(hu_poll(&p,1,100)==1 && (p.revents&HU_POLLHUP));
    CHECK(read(fd[0],readback,1)==0);CHECK(close(fd[0])==0);
    for(i=0;i<50;i++) {
        CHECK(hu_channel(fd)==0);CHECK(close(fd[1])==0);
        CHECK(read(fd[0],readback,1)==0);CHECK(close(fd[0])==0);
    }
    CHECK(hu_channel(fd)==0);CHECK(close(fd[0])==0);
    CHECK(write(fd[1],data,1)==-1 && errno==EPIPE);CHECK(close(fd[1])==0);
    puts("PASS native FIFO: 16 KiB bound, EAGAIN, readiness, dup lifetime, empty EOF, EPIPE and 50 close cycles");
    return 0;
}
