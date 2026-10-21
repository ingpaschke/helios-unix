#include <helios/unix/channel.h>
#include <syslib.h>
#include <gsp.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
int hu_channel(int fds[2])
{
    static unsigned sequence;
    Object *directory,*object;
    char name[32],path[256];
    int reader=-1,writer=-1,error,attempt;
    if(!fds){errno=EINVAL;return -1;}fds[0]=fds[1]=-1;
    /* Resolve the native service's processor path for remote inheritance. */
    directory=Locate(NULL,"/fifo");
    if(!directory){errno=ENOENT;return -1;}
    object=NULL;
    for(attempt=0;attempt<32 && !object;attempt++) {
        sprintf(name,"hu.%08lx.%08x",(unsigned long)MyTask->Port,++sequence);
        object=Create(directory,name,Type_Fifo,0,NULL);
    }
    if(!object){Close(directory);errno=EIO;return -1;}
    if(strlen(object->Name)>=sizeof(path)){
        Delete(object,NULL);Close(object);Close(directory);errno=ENAMETOOLONG;return -1;
    }
    strcpy(path,object->Name);
    reader=open(path,O_RDONLY);if(reader<0)goto fail;
    writer=open(path,O_WRONLY);if(writer<0)goto fail;
    /* GetEnv acquires its own reference before acknowledging SendEnv. */
    fdstream(reader)->Flags|=Flags_OpenOnGet;
    fdstream(writer)->Flags|=Flags_OpenOnGet;
    Close(object);Close(directory);
    fds[0]=reader;fds[1]=writer;return 0;
fail:
    error=errno;if(reader>=0)close(reader);if(writer>=0)close(writer);
    Delete(object,NULL);Close(object);Close(directory);errno=error;return -1;
}
