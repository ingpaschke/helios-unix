#include <helios/unix/netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#define CHECK(x) do{if(!(x)){printf("FAIL resolver line %d: %s\n",__LINE__,#x);return 1;}}while(0)
int main(int argc,char **argv)
{
    struct addrinfo hint,*a,*p;char host[256],service[32];int n;
    memset(&hint,0,sizeof(hint));hint.ai_family=AF_INET;
    hint.ai_socktype=SOCK_STREAM;hint.ai_flags=AI_NUMERICHOST|AI_NUMERICSERV|AI_CANONNAME;
    CHECK(getaddrinfo("192.0.2.7","6667",&hint,&a)==0);
    CHECK(a->ai_next==NULL&&a->ai_protocol==IPPROTO_TCP&&a->ai_canonname&&!strcmp(a->ai_canonname,"192.0.2.7"));
    CHECK(getnameinfo(a->ai_addr,a->ai_addrlen,host,sizeof(host),service,sizeof(service),NI_NUMERICHOST|NI_NUMERICSERV)==0);
    CHECK(!strcmp(host,"192.0.2.7")&&!strcmp(service,"6667"));
    CHECK(getnameinfo(a->ai_addr,a->ai_addrlen,host,2,NULL,0,NI_NUMERICHOST)==EAI_OVERFLOW);
    freeaddrinfo(a);
    CHECK(getaddrinfo("localhost","6667",&hint,&a)==EAI_NONAME&&a==NULL);
    hint.ai_flags=0;CHECK(getaddrinfo("127.0.0.1","telnet",&hint,&a)==0);
    CHECK(((struct sockaddr_in *)a->ai_addr)->sin_port==htons(23));
    CHECK(getnameinfo(a->ai_addr,a->ai_addrlen,NULL,0,service,sizeof(service),0)==0&&!strcmp(service,"telnet"));freeaddrinfo(a);
    hint.ai_flags=0;CHECK(getaddrinfo("localhost","6667",&hint,&a)==0);freeaddrinfo(a);
    CHECK(getaddrinfo(NULL,"0",&hint,&a)==0);
    CHECK(((unsigned char *)&((struct sockaddr_in *)a->ai_addr)->sin_addr)[0]==127);freeaddrinfo(a);
    hint.ai_flags=AI_PASSIVE;CHECK(getaddrinfo(NULL,"0",&hint,&a)==0);
    CHECK(((struct sockaddr_in *)a->ai_addr)->sin_addr.s_addr==0);freeaddrinfo(a);
    hint.ai_flags=0;hint.ai_socktype=0;
    CHECK(getaddrinfo("127.0.0.1","80",&hint,&a)==0);
    n=0;for(p=a;p;p=p->ai_next)n++;CHECK(n==2);freeaddrinfo(a);
    hint.ai_family=999;CHECK(getaddrinfo("127.0.0.1","80",&hint,&a)==EAI_FAMILY);
    if(argc>1) {
        memset(&hint,0,sizeof(hint));hint.ai_socktype=SOCK_STREAM;hint.ai_flags=AI_CANONNAME;
        CHECK(getaddrinfo(argv[1],"6667",&hint,&a)==0);
        n=0;for(p=a;p;p=p->ai_next){n++;CHECK(getnameinfo(p->ai_addr,p->ai_addrlen,host,sizeof(host),NULL,0,NI_NUMERICHOST)==0);printf("ADDRESS %s\n",host);}
        printf("COUNT %d CANON %s\n",n,a->ai_canonname);freeaddrinfo(a);
    }
    puts("PASS owned IPv4 resolver API");return 0;
}
