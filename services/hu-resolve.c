#include <helios/unix/resolve.h>
#include <signal.h>
#include <unistd.h>
int main(int argc,char **argv)
{
    signal(SIGPIPE,SIG_IGN);
    if(argc!=3)return 2;
    return hu_resolve_send(1,argv[1],argv[2][0]=='1')<0?1:0;
}
