#define _XOPEN_SOURCE 700
#include <helios/unix/glob.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pthread.h>
static void touch(const char *p) {FILE *f=fopen(p,"w");assert(f);fclose(f);}
static void check(const char *pattern,int flags,size_t count) {
    glob_t g={0};assert(glob(pattern,flags,NULL,&g)==0);assert(g.gl_pathc==count);globfree(&g);
}
static void *boundaries(void *unused) {
    char path[1100]={0},pattern[1100],component[256];size_t n=0;glob_t g={0};
    (void)unused;
    /* 1022 characters plus slash and NUL used to overrun the path array. */
    memset(component,'a',255);component[255]=0;
    for(int i=0;i<4;i++) {
        size_t part=i==3?254:255;
        if(n)path[n++]='/';memcpy(path+n,component,part);n+=part;path[n]=0;
        assert(mkdir(path,0700)==0);
    }
    assert(n==1022);strcpy(pattern,path);strcat(pattern,"/");
    assert(glob(pattern,0,NULL,&g)==0 && strlen(g.gl_pathv[0])==1023);globfree(&g);
    assert(glob(pattern,GLOB_MARK,NULL,&g)==0);globfree(&g);
    strcat(pattern,"*");assert(glob(pattern,0,NULL,&g)==GLOB_NOMATCH);globfree(&g);
    /* A matching filename would exceed the configured path limit. */
    strcat(path,"/x");touch(path);
    assert(glob(pattern,0,NULL,&g)==GLOB_NOSPACE);globfree(&g);
    path[1022]='a';path[1023]=0;assert(!mkdir(path,0700));
    strcpy(pattern,path);strcat(pattern,"/");
    assert(glob(pattern,0,NULL,&g)==GLOB_NOSPACE);globfree(&g);
    strcpy(path,"limit");assert(!mkdir(path,0700));
    for(int i=1;i<33;i++){strcat(path,"/d");assert(!mkdir(path,0700));}
    check(path,0,1);strcpy(pattern,path);strcat(pattern,"/");check(pattern,0,1);
    strcpy(path,"deep");assert(!mkdir(path,0700));
    for(int i=0;i<40;i++){strcat(path,"/d");assert(!mkdir(path,0700));}
    assert(glob(path,0,NULL,&g)==GLOB_NOSPACE);globfree(&g);
    return NULL;
}
int main(int argc,char **argv) {
    glob_t g={0};pthread_t thread;pthread_attr_t attr;(void)argc;assert(!chdir(argv[1]));
    touch("abc");touch("adc");touch("a*c");touch(".hidden");assert(!mkdir("dir",0700));
    check("a?c",0,3);check("a*?c",0,3);check("a[b-d]c",0,2);check("a\\*c",0,1);check(".*",0,3);
    assert(!symlink("missing-target","dangling"));
    check("dangling",0,1);check("dangl*",0,1);
    assert(glob("dangling/",0,NULL,&g)==GLOB_NOMATCH);globfree(&g);
    check("absent",GLOB_NOCHECK,1);check("dir",GLOB_MARK,1);
    g.gl_offs=2;assert(!glob("abc",GLOB_DOOFFS,NULL,&g));
    assert(!glob("adc",GLOB_DOOFFS|GLOB_APPEND,NULL,&g));
    assert(g.gl_pathc==2 && !g.gl_pathv[0] && !g.gl_pathv[1] && !strcmp(g.gl_pathv[3],"adc"));globfree(&g);
    assert(!mkdir("search-only",0700));touch("search-only/file");
    assert(!chmod("search-only",0111));check("search-only/file",0,1);
    assert(!chmod("search-only",0700));
    assert(!mkdir("sealed",0000));
    assert(glob("sealed/*",GLOB_ERR,NULL,&g)==GLOB_ABORTED);globfree(&g);
    assert(!chmod("sealed",0700));
    assert(!setenv("HOME",argv[1],1));check("~/abc",GLOB_TILDE,1);
    assert(!pthread_attr_init(&attr));assert(!pthread_attr_setstacksize(&attr,65536));
    assert(!pthread_create(&thread,&attr,boundaries,NULL));assert(!pthread_join(thread,NULL));pthread_attr_destroy(&attr);
    puts("PASS glob matching, escaping, append, tilde, exact path limits and deep traversal on a 64 KiB stack");
}
