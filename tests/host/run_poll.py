#!/usr/bin/env python3
"""Exercise the production hu_poll wait loop with deterministic notifications."""
from pathlib import Path
import subprocess,tempfile
s=(Path(__file__).resolve().parents[2]/'src/poll.c').read_text()
s=s[s.index('int hu_poll('):]
pre=r'''
#define _DEFAULT_SOURCE 1
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
typedef long word;
typedef struct Stream {int Type,Mutex;} Stream;
struct hu_pollfd {int fd,events,revents;};
enum {HU_POLLIN=1,HU_POLLOUT=2,HU_POLLPRI=4,HU_POLLERR=8,HU_POLLHUP=16,HU_POLLNVAL=32};
enum {Type_Socket=1,Type_Fifo=2,Type_File=3,Type_Pseudo=4,Type_Flags=0};
enum {O_ReadOnly=1,O_WriteOnly=2,O_Exception=4,HU_O_HANGUP=8,O_Selected=16};
enum {EG_Mask=255,EG_Timeout=9,EG_Exception=10};
static int waits,mode;
static Stream stream={Type_Socket,0};
static Stream *fdstream(int fd){return fd==3?&stream:NULL;}
static void Wait(int *m){(void)m;}
static void Signal(int *m){(void)m;}
static int ReOpen(Stream *s){(void)s;return 0;}
static int status(Stream *s,int fd,int *bits) {
    (void)s;(void)fd;*bits=waits>=2 && mode!=1?HU_POLLIN:0;return 0;
}
static int mock_select(int n,fd_set *r,fd_set *w,fd_set *e,struct timeval *t) {
    (void)n;(void)r;(void)w;(void)e;(void)t;return 0;
}
#define select mock_select
static int SelectStream(unsigned n,Stream **s,word *m,word timeout) {
    assert(n==1 && s[0]==&stream && m[0]==(O_ReadOnly|HU_O_HANGUP));
    if(mode==2)assert(timeout==-1);else assert(timeout>0);
    waits++;m[0]=O_Selected|O_ReadOnly;
    if(mode==1)usleep(20000);
    return 1;
}
'''
post=r'''
int main(void) {
    struct hu_pollfd fd={3,HU_POLLIN,0};
    assert(hu_poll(&fd,1,100)==1 && waits==2 && fd.revents==HU_POLLIN);
    waits=0;mode=1;assert(hu_poll(&fd,1,10)==0 && waits==1 && !fd.revents);
    waits=0;mode=2;assert(hu_poll(&fd,1,-1)==1 && waits==2);
    puts("PASS poll re-arms spurious notifications with original interests and preserves finite/infinite deadlines");
}
'''
with tempfile.TemporaryDirectory(prefix='hu-poll-') as temporary:
    p=Path(temporary);c=p/'test.c';binary=p/'test';c.write_text(pre+s+post)
    subprocess.run(['cc','-std=c99','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-g',str(c),'-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True,timeout=10)
