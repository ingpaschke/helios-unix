#include <helios/unix/spawn.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define HU_CHECK(x) do{if(!(x)){printf("FAIL spawn line %d: %s errno=%d\n",__LINE__,#x,errno);return 1;}}while(0)
int main(int argc,char **argv)
{
    struct hu_spawn_actions actions;
    struct hu_spawn_attr attr;
    pid_t pid;int status,fd,flags,e,n;char cwd[256],after[256],data[256];
    char *environment[]={"HU_PROBE=child-value",NULL};
    char *args[]={"compat-spawn-child","SPAWN_CHILD",NULL};
    memset(&attr,0,sizeof(attr));attr.placement=argc>1?HU_SPAWN_PROCESSOR:HU_SPAWN_LOCAL;
    attr.processor=argc>1?argv[1]:NULL;attr.directory="/helios/tmp";
    hu_spawn_actions_init(&actions);
    fd=open("/helios/tmp/hu-spawn-output",O_CREAT|O_RDWR|O_TRUNC,0600);HU_CHECK(fd>=0);
    HU_CHECK(fcntl(fd,F_SETFD,FD_CLOEXEC)==0);flags=fcntl(fd,F_GETFD);
    HU_CHECK(fcntl(fd,F_SETFL,O_NONBLOCK)==0);
    HU_CHECK(hu_spawn_adddup2(&actions,fd,1)==0);
    HU_CHECK(getcwd(cwd,sizeof(cwd))!=NULL);
    e=hu_spawn(&pid,"/helios/bin/compat-spawn-child",&actions,&attr,args,environment);
    if(e){printf("SPAWN ERROR %d\n",e);return 2;}
    HU_CHECK(waitpid(pid,&status,0)==pid&&WIFEXITED(status)&&WEXITSTATUS(status)==7);
    HU_CHECK(fcntl(fd,F_GETFD)==flags);HU_CHECK(getcwd(after,sizeof(after))!=NULL&&!strcmp(cwd,after));
    HU_CHECK(lseek(fd,0,0)==0);n=read(fd,data,sizeof(data)-1);HU_CHECK(n>0);data[n]=0;
    HU_CHECK(strstr(data,"SPAWN_CHILD")!=NULL);
    HU_CHECK(strstr(data,"/helios/tmp")&&strstr(data,"ENV=child-value")&&strstr(data,"FLAGS=803"));
    printf("%s",data);
    if(argc>1)HU_CHECK(strstr(data,argv[1])!=NULL);
    HU_CHECK(hu_spawn(&pid,"/no-such-program",&actions,&attr,args,NULL)==ENOENT);
    hu_spawn_actions_destroy(&actions);hu_spawn_actions_init(&actions);
    HU_CHECK(hu_spawn_adddup2(&actions,3999,1)==0);
    HU_CHECK(hu_spawn(&pid,"/helios/bin/compat-spawn-child",&actions,&attr,args,NULL)==EBADF);
    HU_CHECK(fcntl(fd,F_GETFD)==flags);close(fd);unlink("/helios/tmp/hu-spawn-output");
    hu_spawn_actions_destroy(&actions);
    puts("PASS spawn redirection, CLOEXEC source, native waitpid, parent state and failure cleanup");return 0;
}
