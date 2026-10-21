#include <helios/unix/api.h>
#include <fcntl.h>
int hu_set_nonblock(int fd,int enabled)
{
    int flags=fcntl(fd,F_GETFL);
    if(flags<0)return -1;
    return fcntl(fd,F_SETFL,enabled?flags|O_NONBLOCK:flags & ~O_NONBLOCK);
}
