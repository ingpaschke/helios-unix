#include <syslib.h>
#include <helios/unix/channel.h>
#include <helios/unix/spawn.h>
#include <helios/unix/poll.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#define HU_CHECK(x) do{if(!(x)){printf("FAIL channel line %d: %s errno=%d\n",__LINE__,#x,errno);return 1;}}while(0)
int main(int argc,char **argv)
{
    int fd[2],n,status;char buf[16];pid_t child;
    struct hu_spawn_actions actions;struct hu_spawn_attr attr;
    char *args[]={"compat-channel-child",NULL};
    HU_CHECK(hu_channel(fd)==0);
    HU_CHECK(write(fd[1],"hello",5)==5); /* no read or select precedes this */
    HU_CHECK(read(fd[0],buf,5)==5&&!memcmp(buf,"hello",5));
    HU_CHECK(close(fd[1])==0);HU_CHECK(read(fd[0],buf,5)==0);close(fd[0]);
    HU_CHECK(hu_channel(fd)==0);hu_spawn_actions_init(&actions);memset(&attr,0,sizeof(attr));
    attr.placement=argc>1?HU_SPAWN_PROCESSOR:HU_SPAWN_LOCAL;attr.processor=argc>1?argv[1]:NULL;
    HU_CHECK(hu_spawn_adddup2(&actions,fd[1],1)==0);
    HU_CHECK(hu_spawn_addclose(&actions,fd[0])==0);
    HU_CHECK(hu_spawn_addclose(&actions,fd[1])==0);
    n=hu_spawn(&child,"/helios/bin/compat-channel-child",&actions,&attr,args,NULL);
    if(n){printf("SPAWN ERROR %d\n",n);return 2;}
    close(fd[1]);n=read(fd[0],buf,sizeof(buf));HU_CHECK(n==5&&!memcmp(buf,"child",5));
    HU_CHECK(read(fd[0],buf,sizeof(buf))==0);close(fd[0]);
    HU_CHECK(waitpid(child,&status,0)==child&&WIFEXITED(status)&&WEXITSTATUS(status)==0);
    hu_spawn_actions_destroy(&actions);
    HU_CHECK(hu_channel(fd)==0);
    hu_spawn_actions_init(&actions);
    HU_CHECK(hu_spawn_adddup2(&actions,fd[0],3)==0);
    attr.closefrom=4;
    {char *reader_args[]={"compat-channel-child","reader",NULL};
     n=hu_spawn(&child,"/helios/bin/compat-channel-child",&actions,&attr,reader_args,NULL);}
    HU_CHECK(n==0);close(fd[0]);
    HU_CHECK(write(fd[1],"R",1)==1);close(fd[1]);
    HU_CHECK(waitpid(child,&status,0)==child&&WIFEXITED(status)&&WEXITSTATUS(status)==0);
    hu_spawn_actions_destroy(&actions);
    HU_CHECK(hu_channel(fd)==0);hu_spawn_actions_init(&actions);
    attr.closefrom=3;
    HU_CHECK(hu_spawn_adddup2(&actions,fd[1],1)==0);
    {char *bulk_args[]={"compat-channel-child","bulk",NULL};
     int total=0,i;
     HU_CHECK(hu_spawn(&child,"/helios/bin/compat-channel-child",&actions,&attr,bulk_args,NULL)==0);
     close(fd[1]);
     while((n=read(fd[0],buf,sizeof(buf)))>0) {
         for(i=0;i<n;i++)HU_CHECK((unsigned char)buf[i]==(total+i)%251);
         total+=n;
     }
     HU_CHECK(n==0 && total==20000);close(fd[0]);
     HU_CHECK(waitpid(child,&status,0)==child&&WIFEXITED(status)&&WEXITSTATUS(status)==0);}
    hu_spawn_actions_destroy(&actions);
    HU_CHECK(hu_channel(fd)==0);hu_spawn_actions_init(&actions);
    HU_CHECK(hu_spawn_adddup2(&actions,fd[1],1)==0);
    {char *idle_args[]={"compat-channel-child","idle-close",NULL};
     struct hu_pollfd p;
     HU_CHECK(hu_spawn(&child,"/helios/bin/compat-channel-child",&actions,&attr,idle_args,NULL)==0);
     close(fd[1]);p.fd=fd[0];p.events=0;
     HU_CHECK(hu_poll(&p,1,3000)==1 && (p.revents&HU_POLLHUP));
     close(fd[0]);HU_CHECK(waitpid(child,&status,0)==child&&WIFEXITED(status)&&WEXITSTATUS(status)==0);}
    hu_spawn_actions_destroy(&actions);
    puts("PASS native buffered channel, EOF, spawn, inherited poll, 20 KiB transfer and delayed HUP");return 0;
}
