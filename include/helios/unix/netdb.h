#ifndef HELIOS_UNIX_NETDB_H
#define HELIOS_UNIX_NETDB_H
#include <sys/types.h>
#include <netdb.h>
struct sockaddr;
#ifndef HU_SOCKLEN_T
#define HU_SOCKLEN_T
typedef unsigned int socklen_t;
#endif
struct addrinfo {
    int ai_flags,ai_family,ai_socktype,ai_protocol;
    socklen_t ai_addrlen;
    struct sockaddr *ai_addr;
    char *ai_canonname;
    struct addrinfo *ai_next;
};
#define AI_PASSIVE 1
#define AI_CANONNAME 2
#define AI_NUMERICHOST 4
#define AI_NUMERICSERV 8
#define NI_NUMERICHOST 1
#define NI_NUMERICSERV 2
#define NI_NAMEREQD 4
#define NI_DGRAM 8
#define EAI_BADFLAGS 1
#define EAI_NONAME 2
#define EAI_AGAIN 3
#define EAI_FAIL 4
#define EAI_FAMILY 5
#define EAI_SOCKTYPE 6
#define EAI_SERVICE 7
#define EAI_MEMORY 8
#define EAI_SYSTEM 9
#define EAI_OVERFLOW 10
int getaddrinfo(const char *,const char *,const struct addrinfo *,struct addrinfo **);
void freeaddrinfo(struct addrinfo *);
const char *gai_strerror(int);
int getnameinfo(const struct sockaddr *,socklen_t,char *,socklen_t,char *,socklen_t,int);
#endif
