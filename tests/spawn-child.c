#include <syslib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
int main(int argc,char **argv)
{
    Object *tasks=Locate(NULL,"/tasks");char cwd[256];
    printf("SPAWN_CHILD %s cwd=%s argument=%s\n",tasks?tasks->Name:"unknown",
           getcwd(cwd,sizeof(cwd))?cwd:"unknown",argc>1?argv[1]:"none");
    printf("ENV=%s FLAGS=%x\n",getenv("HU_PROBE")?getenv("HU_PROBE"):"absent",fcntl(1,F_GETFL));
    if(tasks)Close(tasks);return 7;
}
