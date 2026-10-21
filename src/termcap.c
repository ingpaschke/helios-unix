#include <helios/unix/api.h>
#include <string.h>
#include <stddef.h>
/* These are the xterm/ANSI capabilities used by Irssi's terminfo frontend.
 * No Linux terminfo database is needed on the transputers. */
struct hu_cap {const char *name,*value;};
static const struct hu_cap hu_caps[]={
    {"smcup","\033[?1049h"},{"rmcup","\033[?1049l"},
    {"cup","\033[%i%p1%d;%p2%dH"},{"hpa","\033[%i%p1%dG"},
    {"vpa","\033[%i%p1%dd"},{"cub1","\b"},{"cuf1","\033[C"},
    {"civis","\033[?25l"},{"cnorm","\033[?25h"},
    {"csr","\033[%i%p1%d;%p2%dr"},{"ri","\033M"},{"ind","\n"},
    {"il","\033[%p1%dL"},{"il1","\033[L"},
    {"dl","\033[%p1%dM"},{"dl1","\033[M"},
    {"clear","\033[H\033[2J"},{"ed","\033[J"},{"el","\033[K"},
    {"sgr0","\033[0m"},{"smul","\033[4m"},{"rmul","\033[24m"},
    {"smso","\033[7m"},{"rmso","\033[27m"},{"bold","\033[1m"},
    {"blink","\033[5m"},{"setaf","\033[3%p1%dm"},{"setab","\033[4%p1%dm"},
    {"bel","\007"},{NULL,NULL}
};
static int terminal_fd;
int setupterm(char *term,int fd,int *err)
{
    terminal_fd=fd>=0?fd:0;
    if(!term || (strncmp(term,"xterm",5)&&strcmp(term,"ansi")&&strcmp(term,"vt100")&&strncmp(term,"screen",6))) {
        if(err)*err=0;return -1;
    }
    if(err)*err=1;return 0;
}
char *tigetstr(char *name)
{
    int i;for(i=0;hu_caps[i].name;i++)if(!strcmp(name,hu_caps[i].name))return (char *)hu_caps[i].value;
    return NULL;
}
int tigetnum(char *name)
{
    unsigned rows,columns;
    if(!strcmp(name,"colors"))return 8;
    if(hu_terminal_size(terminal_fd,&rows,&columns)==0) {
        if(!strcmp(name,"cols")&&columns>0)return columns;
        if(!strcmp(name,"lines")&&rows>0)return rows;
    }
    if(!strcmp(name,"cols"))return 80;if(!strcmp(name,"lines"))return 24;return -1;
}
int tigetflag(char *name){return !strcmp(name,"am");}
int tputs(const char *s,int count,int (*put)(int))
{(void)count;if(s)while(*s)put((unsigned char)*s++);return 0;}

