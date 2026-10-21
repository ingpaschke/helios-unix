#include "pipe-experimental.h"
#include <syslib.h>
#include <process.h>
#include <unistd.h>
#include <errno.h>
struct hu_pipe_start {Semaphore ready;Stream *reader;word result;};
static void start_reader(struct hu_pipe_start *p)
{p->result=GetFileSize(p->reader);Signal(&p->ready);}
int hu_pipe(int fds[2])
{
    struct hu_pipe_start p;
    if(!fds){errno=EINVAL;return -1;}
    if(pipe(fds)<0)return -1;
    p.reader=fdstream(fds[0]);p.result=-1;InitSemaphore(&p.ready,0);
    if(!Fork(8192,(VoidFnPtr)start_reader,sizeof(word),&p)) {
        close(fds[0]);close(fds[1]);fds[0]=fds[1]=-1;errno=ENOMEM;return -1;
    }
    /* The write end rejects GetSize after connecting; this still completes
     * its rendezvous with the reader. No application byte is consumed. */
    GetFileSize(fdstream(fds[1]));Wait(&p.ready);
    if(p.result<0){close(fds[0]);close(fds[1]);fds[0]=fds[1]=-1;errno=EIO;return -1;}
    return 0;
}
