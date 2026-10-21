#include <helios/unix/resolve.h>
#include <helios/unix/channel.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#define CHECK(x) do{if(!(x)){printf("FAIL async line %d: %s errno=%d\n",__LINE__,#x,errno);return 1;}}while(0)
int main(int argc,char **argv)
{
    struct hu_spawn_attr attr;struct hu_resolve_result result;
    int fd[2],status,i;pid_t pid;
    memset(&attr,0,sizeof(attr));attr.placement=argc>1?HU_SPAWN_PROCESSOR:HU_SPAWN_LOCAL;
    attr.processor=argc>1?argv[1]:NULL;
    for(i=0;i<10;i++) {
        CHECK(hu_channel(fd)==0);
        CHECK(hu_resolve_launch(&pid,fd[1],"127.0.0.1",0,&attr)==0);close(fd[1]);
        CHECK(hu_resolve_receive(fd[0],&result)==0);close(fd[0]);
        CHECK(!result.error&&result.count==1&&result.addresses[0][0]==127);
        CHECK(waitpid(pid,&status,0)==pid&&WIFEXITED(status)&&WEXITSTATUS(status)==0);
    }
    CHECK(hu_channel(fd)==0);
    CHECK(hu_resolve_launch(&pid,fd[1],"cancel-test.invalid",0,&attr)==0);
    close(fd[0]);close(fd[1]);CHECK(kill(pid,SIGKILL)==0);CHECK(waitpid(pid,&status,0)==pid);
    puts("PASS spawned resolver, owned wire results, repeated reaping and cancellation");return 0;
}
