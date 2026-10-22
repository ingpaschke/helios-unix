#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <helios/unix/glob.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#define HU_PATH_LIMIT 1024
struct hu_glob {glob_t *out;int flags;int (*err)(const char *,int);};
static int match(const char *p,const char *s,int noescape)
{
    const char *star=NULL,*retry=NULL;int ok,invert;unsigned char lo,hi,c;
    while(*s) {
        if(*p=='*'){while(*p=='*')p++;star=p;retry=s;continue;}
        c=(unsigned char)*s;ok=0;
        if(*p=='?'){p++;ok=1;}
        else if(*p=='[') {
            const char *start=p++;invert=(*p=='!'||*p=='^');if(invert)p++;
            if(*p==']'){if(c==']')ok=1;p++;}
            while(*p&&*p!=']') {
                if(*p=='\\'&&!noescape&&p[1])p++;
                lo=(unsigned char)*p++;hi=lo;
                if(*p=='-'&&p[1]&&p[1]!=']') {
                    p++;if(*p=='\\'&&!noescape&&p[1])p++;hi=(unsigned char)*p++;
                }
                if(c>=lo&&c<=hi)ok=1;
            }
            if(*p==']'){p++;ok=invert?!ok:ok;}
            else {p=start+1;ok=c=='[';}
        }else if(*p) {
            if(*p=='\\'&&!noescape&&p[1])p++;
            ok=(unsigned char)*p++==c;
        }
        if(ok){s++;continue;}
        if(star){p=star;s=++retry;continue;}
        return 0;
    }
    while(*p=='*')p++;return !*p;
}
static int add(struct hu_glob *g,const char *path,int directory)
{
    glob_t *o=g->out;size_t n=strlen(path),offset=(g->flags&GLOB_DOOFFS)?o->gl_offs:0;
    char **v,*s;int mark=(g->flags&GLOB_MARK)&&directory&&n&&path[n-1]!='/';
    if(offset>65536||o->gl_pathc>65536)return GLOB_NOSPACE;
    s=malloc(n+mark+1);if(!s)return GLOB_NOSPACE;
    memcpy(s,path,n);if(mark)s[n++]='/';s[n]=0;
    v=realloc(o->gl_pathv,(offset+o->gl_pathc+2)*sizeof(char *));
    if(!v){free(s);return GLOB_NOSPACE;}
    if(!o->gl_pathc){size_t i;for(i=0;i<offset;i++)v[i]=NULL;}
    o->gl_pathv=v;v[offset+o->gl_pathc++]=s;v[offset+o->gl_pathc]=NULL;return 0;
}
static int path_error(struct hu_glob *g,const char *path,int e)
{return (g->err&&g->err(path,e))||(g->flags&GLOB_ERR)?GLOB_ABORTED:0;}
static int walk(struct hu_glob *g,const char *base,const char *pattern,unsigned depth);
static int visit(struct hu_glob *g,char *path,const char *rest,unsigned depth)
{
    struct stat st;
    if(*rest) {
        const char *next=rest;size_t n;
        while(*next=='/')next++;
        if(stat(path,&st)<0||!S_ISDIR(st.st_mode))return 0;
        n=strlen(path);
        if(!*next) {
            if(n+2>HU_PATH_LIMIT)return GLOB_NOSPACE;
            path[n++]='/';path[n]=0;
            return add(g,path,1);
        }
        return walk(g,path,next,depth+1);
    }
    return add(g,path,stat(path,&st)==0&&S_ISDIR(st.st_mode));
}
static int join(char *path,const char *base,const char *name)
{
    size_t b=strlen(base),n=strlen(name),slash=b&&base[b-1]!='/';
    if(b+n+slash+1>HU_PATH_LIMIT)return GLOB_NOSPACE;
    memcpy(path,base,b);if(slash)path[b++]='/';memcpy(path+b,name,n+1);return 0;
}
static int walk(struct hu_glob *g,const char *base,const char *pattern,unsigned depth)
{
    struct buffers {char component[HU_PATH_LIMIT],path[HU_PATH_LIMIT];} *buf;
    const char *rest,*p;char *q;DIR *d=NULL;struct dirent *entry;struct stat st;
    size_t n;int e=0,hidden,magic=0;
    if(depth>32)return GLOB_NOSPACE;
    if(!*pattern) {
        if(stat(*base?base:".",&st)<0)return 0;
        return add(g,*base?base:".",S_ISDIR(st.st_mode));
    }
    rest=pattern;while(*rest&&*rest!='/')rest++;
    n=rest-pattern;if(n>=HU_PATH_LIMIT)return GLOB_NOSPACE;
    buf=malloc(sizeof(*buf));if(!buf)return GLOB_NOSPACE;
    memcpy(buf->component,pattern,n);buf->component[n]=0;
    hidden=buf->component[0]=='.'||(!(g->flags&GLOB_NOESCAPE)&&buf->component[0]=='\\'&&buf->component[1]=='.');
    for(p=buf->component;*p;p++) {
        if(*p=='\\'&&!(g->flags&GLOB_NOESCAPE)&&p[1])p++;
        else if(*p=='*'||*p=='?'||*p=='[')magic=1;
    }
    if(!magic) {
        /* Literal lookups need search permission, not directory listing. */
        for(p=buf->component,q=buf->component;*p;p++) {
            if(*p=='\\'&&!(g->flags&GLOB_NOESCAPE)&&p[1])p++;
            *q++=*p;
        }
        *q=0;e=join(buf->path,base,buf->component);
        if(!e && (stat(buf->path,&st)==0 || (!*rest && lstat(buf->path,&st)==0)))
            e=visit(g,buf->path,rest,depth);
        else if(!e && errno!=ENOENT&&errno!=ENOTDIR)e=path_error(g,*base?base:".",errno);
        goto done;
    }
    d=opendir(*base?base:".");
    if(!d){e=errno;e=(e==ENOENT||e==ENOTDIR)?0:path_error(g,*base?base:".",e);goto done;}
    while((entry=readdir(d))!=NULL) {
        if(entry->d_name[0]=='.'&&!hidden)continue;
        if(!match(buf->component,entry->d_name,g->flags&GLOB_NOESCAPE))continue;
        e=join(buf->path,base,entry->d_name);
        if(!e)e=visit(g,buf->path,rest,depth);
        if(e)break;
    }
done:
    if(d)closedir(d);free(buf);return e;
}
static int compare(const void *a,const void *b)
{return strcmp(*(const char *const *)a,*(const char *const *)b);}
int glob(const char *pattern,int flags,int (*err)(const char *,int),glob_t *out)
{
    struct hu_glob g;char *expanded=NULL;const char *p;size_t before,offset;int rc;
    if(!pattern||!out||(flags & ~255)){errno=EINVAL;return GLOB_ABORTED;}
    if(!(flags&GLOB_APPEND)){out->gl_pathc=0;out->gl_pathv=NULL;out->gl_flags=flags;}
    else if((out->gl_flags&GLOB_DOOFFS)!=(flags&GLOB_DOOFFS)){errno=EINVAL;return GLOB_ABORTED;}
    g.out=out;g.flags=flags;g.err=err;before=out->gl_pathc;
    offset=(flags&GLOB_DOOFFS)?out->gl_offs:0;
    p=pattern;
    if((flags&GLOB_TILDE)&&p[0]=='~'&&(p[1]=='/'||!p[1])) {
        const char *home=getenv("HOME");
        if(home){expanded=malloc(strlen(home)+strlen(p)+1);if(!expanded)return GLOB_NOSPACE;
            strcpy(expanded,home);strcat(expanded,p+1);p=expanded;}
    }
    if(!*p)rc=0;
    else if(*p=='/'){while(*p=='/')p++;rc=walk(&g,"/",p,0);}
    else rc=walk(&g,"",p,0);
    if(!rc&&out->gl_pathc==before)rc=(flags&GLOB_NOCHECK)?add(&g,expanded?expanded:pattern,0):GLOB_NOMATCH;
    if(!rc&&!(flags&GLOB_NOSORT))qsort(out->gl_pathv+offset+before,out->gl_pathc-before,sizeof(char *),compare);
    free(expanded);return rc;
}
void globfree(glob_t *out)
{
    size_t i,offset;if(!out)return;offset=(out->gl_flags&GLOB_DOOFFS)?out->gl_offs:0;
    for(i=0;i<out->gl_pathc;i++)free(out->gl_pathv[offset+i]);
    free(out->gl_pathv);out->gl_pathv=NULL;out->gl_pathc=0;
}
