#include <helios/unix/api.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
int main(void)
{
    struct hu_terminal_decoder d={0,1};
    char input[]={0x9b,'A',0xc2,0x9b,0xe2,0x82,0xac,0x8f,'B'};
    char expected[]={27,'[','A',0xc2,0x9b,0xe2,0x82,0xac,27,'O','B'};
    char out[32];int fd,n,used=0;
    fd=open("/helios/tmp/hu-terminal-input",O_CREAT|O_TRUNC|O_RDWR,0600);
    if(fd<0||write(fd,input,sizeof(input))!=sizeof(input)||lseek(fd,0,0)<0)return 1;
    while((n=hu_terminal_read(fd,&d,out+used,2))>0)used+=n;
    if(n<0||used!=sizeof(expected)||memcmp(out,expected,used))return 2;
    d.helios_c1=0;d.utf8_remaining=0;used=0;lseek(fd,0,0);
    while((n=hu_terminal_read(fd,&d,out+used,2))>0)used+=n;
    close(fd);unlink("/helios/tmp/hu-terminal-input");
    if(n<0||used!=sizeof(input)||memcmp(out,input,used))return 3;
    puts("PASS fragmented UTF-8, explicit Helios CSI/SS3, raw byte preservation");return 0;
}
