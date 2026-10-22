/* Owned IPv4 results; shared DNS parser with the resident legacy adapter. */
#include <helios/unix/netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#define KTM_DNS_ALLOC malloc
#define KTM_DNS_FREE free
#include "dns-resolver.h"
static char *hu_copy(const char *s)
{char *p=malloc(strlen(s)+1);if(p)strcpy(p,s);return p;}
static int hu_hosts(const char *name,int reverse,unsigned char addr[32][4],int *count,char *canonical)
{
    FILE *f=fopen("/helios/etc/hosts","r");char line[1024],*cursor,*ip,*word;
    unsigned char bytes[4];int match;
    if(!f)return 0;
    while(fgets(line,sizeof(line),f)) {
        char first[256];int last=strlen(line);
        if(last&&line[last-1]=='\n')line[last-1]=0;
        cursor=line;ip=ktm_dns_token(&cursor);
        if(!ip||!ktm_dns_ipv4(ip,bytes))continue;
        word=ktm_dns_token(&cursor);if(!word||strlen(word)>253)continue;
        strcpy(first,word);match=reverse?!memcmp(addr[0],bytes,4):0;
        do {if(!reverse&&ktm_dns_equal(name,word))match=1;}while((word=ktm_dns_token(&cursor))!=NULL);
        if(match) {
            if(!*count)strcpy(canonical,first);
            { int i;
              for(i=0;i<*count;i++)if(!memcmp(addr[i],bytes,4))break;
              if(i==*count&&*count<32)memcpy(addr[(*count)++],bytes,4);
            }
            if(reverse)break;
        }
    }
    fclose(f);return *count!=0;
}
static int hu_service(const char *name,int type,int *port)
{
    char *end;unsigned long n;
    if(!name){*port=0;return 0;}
    if(*name>='0'&&*name<='9') {
        n=strtoul(name,&end,10);
        if(!*end&&n<=65535){*port=(int)n;return 0;}
        if(!*end)return EAI_SERVICE;
    }
    {
        char *protocol=type==SOCK_DGRAM?"udp":"tcp";
        struct servent *s=getservbyname((char *)name,protocol);
        if(!s)return EAI_SERVICE;
        *port=ntohs((unsigned short)s->s_port);return 0;
    }
}
void freeaddrinfo(struct addrinfo *ai)
{while(ai){struct addrinfo *next=ai->ai_next;free(ai->ai_addr);free(ai->ai_canonname);free(ai);ai=next;}}
int getaddrinfo(const char *node,const char *service,const struct addrinfo *hint,struct addrinfo **out)
{
    struct addrinfo zero,*head=NULL,**tail=&head,*ai;
    struct sockaddr_in *sa;
    unsigned char addresses[32][4];char canonical[256];
    int count=0,status,type,first,last,i,port,proto;
    if(!out)return EAI_FAIL;*out=NULL;
    memset(&zero,0,sizeof(zero));if(!hint)hint=&zero;
    if(hint->ai_flags & ~(AI_PASSIVE|AI_CANONNAME|AI_NUMERICHOST|AI_NUMERICSERV))return EAI_BADFLAGS;
    if(hint->ai_family!=AF_UNSPEC&&hint->ai_family!=AF_INET)return EAI_FAMILY;
    if(hint->ai_socktype&&hint->ai_socktype!=SOCK_STREAM&&hint->ai_socktype!=SOCK_DGRAM)return EAI_SOCKTYPE;
    if(hint->ai_protocol&&hint->ai_protocol!=IPPROTO_TCP&&hint->ai_protocol!=IPPROTO_UDP)return EAI_SERVICE;
    if((hint->ai_socktype==SOCK_STREAM&&hint->ai_protocol==IPPROTO_UDP)||
       (hint->ai_socktype==SOCK_DGRAM&&hint->ai_protocol==IPPROTO_TCP))return EAI_SOCKTYPE;
    if(!node&&!service)return EAI_NONAME;
    if(service&&(hint->ai_flags&AI_NUMERICSERV)) {
        const char *p=service;if(!*p)return EAI_NONAME;
        while(*p){if(*p<'0'||*p>'9')return EAI_NONAME;p++;}
    }
    if(!node) {
        memset(addresses[0],0,4);
        if(!(hint->ai_flags&AI_PASSIVE)){addresses[0][0]=127;addresses[0][3]=1;}
        count=1;canonical[0]=0;
    }else if(ktm_dns_ipv4(node,addresses[0])) {count=1;strcpy(canonical,node);}
    else {
        if(hint->ai_flags&AI_NUMERICHOST)return EAI_NONAME;
        if(!hu_hosts(node,0,addresses,&count,canonical)) {
            status=ktm_dns_lookup_all(node,0,addresses[0],canonical,addresses,&count);
            if(status)return status==1?EAI_NONAME:EAI_AGAIN;
        }
    }
    first=hint->ai_socktype?hint->ai_socktype:hint->ai_protocol==IPPROTO_TCP?SOCK_STREAM:
          hint->ai_protocol==IPPROTO_UDP?SOCK_DGRAM:0;
    last=first?first:SOCK_DGRAM;if(!first)first=SOCK_STREAM;
    /* Native SOCK_STREAM=1 and SOCK_DGRAM=2. */
    for(type=first;type<=last;type++) {
        if(hu_service(service,type,&port))continue;
        proto=type==SOCK_STREAM?IPPROTO_TCP:IPPROTO_UDP;
        for(i=0;i<count;i++) {
            ai=calloc(1,sizeof(*ai));sa=calloc(1,sizeof(*sa));
            if(!ai||!sa){free(ai);free(sa);freeaddrinfo(head);return EAI_MEMORY;}
            ai->ai_family=AF_INET;ai->ai_socktype=type;ai->ai_protocol=proto;
            ai->ai_flags=hint->ai_flags;ai->ai_addrlen=sizeof(*sa);ai->ai_addr=(struct sockaddr *)sa;
            sa->sin_family=AF_INET;sa->sin_port=htons(port);memcpy(&sa->sin_addr,addresses[i],4);
            if(!head&&node&&(hint->ai_flags&AI_CANONNAME)) {
                ai->ai_canonname=hu_copy(canonical);
                if(!ai->ai_canonname){freeaddrinfo(ai);return EAI_MEMORY;}
            }
            *tail=ai;tail=&ai->ai_next;
        }
    }
    if(!head)return EAI_SERVICE;*out=head;return 0;
}
const char *gai_strerror(int e)
{
    static const char *errors[]={"Success","Invalid flags","Name or service not found",
        "Temporary resolver failure","Resolver failure","Unsupported address family",
        "Unsupported socket type","Unsupported service","Out of memory","System error","Buffer too small"};
    return e>=0&&e<=10?errors[e]:"Unknown resolver error";
}
int getnameinfo(const struct sockaddr *address,socklen_t size,char *host,socklen_t hostlen,
                char *service,socklen_t servlen,int flags)
{
    const struct sockaddr_in *sa=(const struct sockaddr_in *)address;
    unsigned char bytes[32][4];char name[256],port[32];int count=0,status=1;
    if(flags & ~(NI_NUMERICHOST|NI_NUMERICSERV|NI_NAMEREQD|NI_DGRAM))return EAI_BADFLAGS;
    if(!sa||size<sizeof(*sa)||sa->sin_family!=AF_INET)return EAI_FAMILY;
    if(!host&&!service)return EAI_NONAME;
    memcpy(bytes[0],&sa->sin_addr,4);
    if(host) {
        if(!(flags&NI_NUMERICHOST)) {
            if(hu_hosts(NULL,1,bytes,&count,name))status=0;
            else status=ktm_dns_lookup("reverse",1,bytes[0],name);
        }
        if(status) {
            if((flags&NI_NAMEREQD)&&!(flags&NI_NUMERICHOST))return status==2?EAI_AGAIN:EAI_NONAME;
            sprintf(name,"%u.%u.%u.%u",bytes[0][0],bytes[0][1],bytes[0][2],bytes[0][3]);
        }
        if(strlen(name)>=hostlen)return EAI_OVERFLOW;
    }
    if(service) {
        struct servent *s=NULL;char *protocol=(flags&NI_DGRAM)?"udp":"tcp";
        if(!(flags&NI_NUMERICSERV))s=getservbyport(ntohs(sa->sin_port),protocol);
        if(s){if(strlen(s->s_name)>=sizeof(port))return EAI_OVERFLOW;strcpy(port,s->s_name);}
        else sprintf(port,"%u",(unsigned)ntohs(sa->sin_port));
        if(strlen(port)>=servlen)return EAI_OVERFLOW;
    }
    if(host)strcpy(host,name);if(service)strcpy(service,port);return 0;
}
