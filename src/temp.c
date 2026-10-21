#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/time.h>
int mkstemp(char *name)
{
    static unsigned counter;struct timeval tv;
    unsigned value;int length,attempt,i,fd;
    if(!name){errno=EINVAL;return -1;}length=strlen(name);
    if(length<6||strcmp(name+length-6,"XXXXXX")){errno=EINVAL;return -1;}
    tv.tv_sec=tv.tv_usec=0;gettimeofday(&tv,NULL);
    for(attempt=0;attempt<256;attempt++) {
        value=(unsigned)tv.tv_usec^((unsigned)getpid()<<16)^++counter;
        for(i=0;i<6;i++){name[length-1-i]="0123456789abcdefghijklmnopqrstuvwxyz"[value%36];value/=36;}
        fd=open(name,O_RDWR|O_CREAT|O_EXCL,0600);
        if(fd>=0||errno!=EEXIST)return fd;
    }
    errno=EEXIST;return -1;
}
