#include <unistd.h>
#include <helios/unix/poll.h>
#include <string.h>
#include <sys/time.h>
int main(int argc,char **argv)
{
    if(argc>1 && !strcmp(argv[1],"idle-close")) {
        struct timeval tv={0,200000};
        select(0,NULL,NULL,NULL,&tv);
        return 0;
    }
    if(argc>1 && !strcmp(argv[1],"bulk")) {
        char data[20000];int i,n,offset=0;
        for(i=0;i<sizeof(data);i++)data[i]=(char)(i%251);
        while(offset<sizeof(data)) {
            n=write(1,data+offset,sizeof(data)-offset);
            if(n<=0)return 4;
            offset+=n;
        }
        return 0;
    }
    if(argc>1 && !strcmp(argv[1],"reader")) {
        struct hu_pollfd p;
        char c;
        p.fd=3;p.events=HU_POLLIN;
        /* First operation on this inherited, still-lazy stream. */
        if(hu_poll(&p,1,5000)!=1 || !(p.revents&HU_POLLIN))return 2;
        return read(3,&c,1)==1 && c=='R'?0:3;
    }
    return write(1,"child",5)==5?0:1;
}
