/* Exercise the client's actual encoding negotiation through a host PTY. */
#define main ssh_client_main
#include "../../services/hu-ssh.c"
#undef main
#include <assert.h>

int hu_terminal_read(int fd,struct hu_terminal_decoder *d,char *out,int size)
{(void)d;return read(fd,out,size);}
int hu_terminal_restore(int fd,const struct termios *t)
{return tcsetattr(fd,TCSANOW,t);}

int main(void)
{
    struct termios t;struct hu_terminal_decoder d={0,0};char input[128];int n,i;
    assert(tcgetattr(0,&t)==0);cfmakeraw(&t);assert(tcsetattr(0,TCSANOW,&t)==0);
    signal(SIGTERM,interrupt);
    n=terminal_encoding(&d,input,sizeof(input));
    fprintf(stderr,"mode=%d keys=",saved_encoding);
    for(i=0;i<n;i++)fprintf(stderr,"%02x",(unsigned char)input[i]);
    fputc('\n',stderr);
    restore();restore(); /* Cleanup can also run through atexit. */
    return 0;
}
