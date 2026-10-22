#include <helios/unix/api.h>
#include <errno.h>
#include <unistd.h>
#include <termios.h>
int hu_terminal_size(int fd,unsigned *rows,unsigned *columns)
{
    struct termios t;
    if(!rows||!columns){errno=EINVAL;return -1;}
    if(tcgetattr(fd,&t)<0)return -1;
    if(t.c_min<=0||t.c_time<=0){errno=EINVAL;return -1;}
    *rows=t.c_min;*columns=t.c_time;return 0;
}
int hu_terminal_raw(int fd,struct termios *saved)
{
    struct termios t;
    if(!saved){errno=EINVAL;return -1;}
    if(tcgetattr(fd,saved)<0)return -1;
    /* Helios tcsetattr copies c_cc[VMIN/VTIME] to c_min/c_time. The
     * indices alias VEOF/VEOL in cooked mode; window servers regenerate
     * rows/columns on GetAttributes, so these are not Unix read timers. */
    t=*saved;
    t.c_iflag &= ~(BRKINT|ICRNL|INLCR|IGNCR|IXON|IXOFF|ISTRIP);
    t.c_oflag &= ~OPOST;
    t.c_lflag &= ~(ICANNON|ECHO|ISIG|IEXTEN);
    return tcsetattr(fd,TCSANOW,&t);
}
int hu_terminal_restore(int fd,const struct termios *saved)
{
    if(!saved){errno=EINVAL;return -1;}
    return tcsetattr(fd,TCSANOW,(struct termios *)saved);
}
int hu_terminal_read(int fd,struct hu_terminal_decoder *d,char *out,int size)
{
    unsigned char input[256];int n,i,used=0;unsigned c;
    if(!d||!out||size<2){errno=EINVAL;return -1;}
    n=read(fd,(char *)input,size/2>sizeof(input)?sizeof(input):size/2);
    if(n<=0)return n;
    for(i=0;i<n;i++) {
        c=input[i];
        if(d->utf8_remaining&&c>=128&&c<=191){d->utf8_remaining--;out[used++]=c;continue;}
        d->utf8_remaining=c>=194&&c<=223?1:c>=224&&c<=239?2:c>=240&&c<=244?3:0;
        if(d->helios_c1&&(c==0x9b||c==0x8f)){out[used++]=27;out[used++]=c==0x9b?'[':'O';}
        else out[used++]=c;
    }
    return used;
}
