#include <helios/unix/resolve.h>
#include <helios/unix/netdb.h>
#include <helios/unix/api.h>
#include <helios/unix/poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
int hu_resolve_launch(pid_t *pid,int fd,const char *name,int reverse,const struct hu_spawn_attr *attr)
{
    struct hu_spawn_actions actions;struct hu_spawn_attr settings;int e;
    char *args[]={"hu-resolve",(char *)name,reverse?"1":"0",NULL};
    if(!name||!*name||strlen(name)>253)return EINVAL;
    memset(&settings,0,sizeof(settings));if(attr)settings=*attr;settings.closefrom=3;
    hu_spawn_actions_init(&actions);e=hu_spawn_adddup2(&actions,fd,1);
    if(!e)e=hu_spawn_addclose(&actions,0);if(!e)e=hu_spawn_addclose(&actions,2);
    if(!e)e=hu_spawn(pid,"/helios/lib/hu-resolve",&actions,&settings,args,NULL);
    hu_spawn_actions_destroy(&actions);return e;
}
int hu_resolve_send(int fd,const char *name,int reverse)
{
    unsigned char wire[HU_RESOLVE_WIRE_SIZE];struct addrinfo hint,*list=NULL,*a;
    int error,count=0,done=0,n;
    memset(wire,0,sizeof(wire));memcpy(wire,"HUR1",4);
    memset(&hint,0,sizeof(hint));hint.ai_family=AF_INET;hint.ai_socktype=SOCK_STREAM;hint.ai_flags=AI_CANONNAME;
    error=getaddrinfo(name,NULL,&hint,&list);
    if(!error) {
        for(a=list;a&&count<32;a=a->ai_next)
            memcpy(wire+8+4*count++,&((struct sockaddr_in *)a->ai_addr)->sin_addr,4);
        if(list->ai_canonname)strncpy((char *)wire+136,list->ai_canonname,255);
        if(reverse)getnameinfo(list->ai_addr,list->ai_addrlen,(char *)wire+136,256,NULL,0,0);
    }
    freeaddrinfo(list);wire[4]=error;wire[5]=count;
    while(done<sizeof(wire)) {
        n=write(fd,(char *)wire+done,sizeof(wire)-done);
        if(n<0&&errno==EINTR)continue;if(n<=0)return -1;done+=n;
    }
    return 0;
}
int hu_resolve_receive(int fd,struct hu_resolve_result *result)
{
    unsigned char wire[HU_RESOLVE_WIRE_SIZE];int done=0,n,remaining;
    struct timeval start,now;struct hu_pollfd p;
    if(!result){errno=EINVAL;return -1;}memset(result,0,sizeof(*result));result->error=EAI_FAIL;
    if(hu_set_nonblock(fd,1)<0)return -1;
    gettimeofday(&start,NULL);p.fd=fd;p.events=HU_POLLIN;
    while(done<sizeof(wire)) {
        gettimeofday(&now,NULL);remaining=2000-(now.tv_sec-start.tv_sec)*1000-(now.tv_usec-start.tv_usec)/1000;
        if(remaining<=0){errno=ETIMEDOUT;return -1;}
        n=hu_poll(&p,1,remaining);if(n<0)return -1;if(!n){errno=ETIMEDOUT;return -1;}
        n=read(fd,(char *)wire+done,sizeof(wire)-done);
        if(n<0&&(errno==EINTR||errno==EAGAIN||errno==EWOULDBLOCK))continue;
        if(n<=0){errno=EIO;return -1;}done+=n;
    }
    if(memcmp(wire,"HUR1",4)||wire[4]>EAI_OVERFLOW||wire[5]>32||wire[6]||wire[7]||
       wire[391]||(!wire[4]&&!wire[5])){errno=EIO;return -1;}
    result->error=wire[4];result->count=wire[5];
    memcpy(result->addresses,wire+8,128);memcpy(result->canonical,wire+136,256);return 0;
}
