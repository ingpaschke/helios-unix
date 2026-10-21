#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <helios/unix/api.h>
#include <helios/unix/poll.h>
#define CHECK(x) do{if(!(x)){printf("FAIL line %d: %s errno=%d\n",__LINE__,#x,errno);return 1;}}while(0)
int main(int argc,char **argv)
{
    struct sockaddr_in addr;
    int fd,alias,n,enabled,plain,high;char buf[32];struct hu_pollfd polls[3];
    CHECK(argc==3);
    memset(&addr,0,sizeof(addr));addr.sin_family=AF_INET;
    addr.sin_addr.s_addr=inet_addr(argv[1]);addr.sin_port=htons(atoi(argv[2]));
    signal(SIGPIPE,SIG_IGN);
    fd=socket(AF_INET,SOCK_STREAM,0);CHECK(fd>=0);
    CHECK(connect(fd,(struct sockaddr *)&addr,sizeof(addr))==0);
    high=fcntl(fd,F_DUPFD,70);CHECK(high>=70);
    polls[0].fd=high;polls[0].events=HU_POLLOUT;
    polls[1].fd=-1;polls[1].events=HU_POLLIN;
    polls[2].fd=9999;polls[2].events=0;
    CHECK(hu_poll(polls,3,0)==2&&polls[0].revents==HU_POLLOUT&&polls[1].revents==0&&polls[2].revents==HU_POLLNVAL);
    CHECK(close(high)==0);CHECK(hu_poll(NULL,0,5)==0);
    CHECK(fcntl(fd,F_SETFD,FD_CLOEXEC)==0);
    alias=dup(fd);CHECK(alias>=0);CHECK(fcntl(alias,F_GETFD)==0);
    CHECK(hu_set_nonblock(alias,1)==0);
    CHECK(fcntl(fd,F_GETFL)&O_NONBLOCK);
    CHECK(read(fd,buf,0)==0);CHECK(write(fd,buf,0)==0);
    n=recv(fd,buf,sizeof(buf),0);CHECK(n==-1&&(errno==EAGAIN||errno==EWOULDBLOCK));
    n=read(alias,buf,sizeof(buf));CHECK(n==-1&&(errno==EAGAIN||errno==EWOULDBLOCK));
    enabled=0;CHECK(ioctl(fd,FIONBIO,(char *)&enabled)==0);
    CHECK(!(fcntl(alias,F_GETFL)&O_NONBLOCK));
    CHECK(shutdown(fd,99)==-1&&errno==EINVAL);
    CHECK(send(fd,"request",7,0)==7);
    CHECK(shutdown(alias,1)==0);
    CHECK(close(fd)==0);
    n=recv(alias,buf,sizeof(buf),0);CHECK(n==5&&!memcmp(buf,"reply",5));
    CHECK(recv(alias,buf,sizeof(buf),0)==0);
    polls[0].fd=alias;polls[0].events=0;
    CHECK(hu_poll(polls,1,1000)==1&&(polls[0].revents&HU_POLLHUP));
    CHECK(close(alias)==0);
    fd=socket(AF_INET,SOCK_STREAM,0);CHECK(fd>=0);
    CHECK(connect(fd,(struct sockaddr *)&addr,sizeof(addr))==0);
    polls[0].fd=fd;polls[0].events=0;
    CHECK(hu_poll(polls,1,2000)==1&&(polls[0].revents&HU_POLLHUP));
    CHECK(recv(fd,buf,sizeof(buf),0)==0);CHECK(close(fd)==0);
    CHECK(shutdown(-1,0)==-1&&errno==EBADF);
    plain=open("/helios/etc/hosts",O_RDONLY);CHECK(plain>=0);
    CHECK(shutdown(plain,0)==-1&&errno==ENOTSOCK);
    polls[0].fd=plain;polls[0].events=HU_POLLIN;
    CHECK(hu_poll(polls,1,0)==1&&polls[0].revents==HU_POLLIN);close(plain);
    printf("PASS nonblocking, dup status, ioctl, zero I/O, SHUT_WR, EOF, errors\n");
    return 0;
}
