#include <helios/unix/glob.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
extern int mkstemp(char *);
#define HU_CHECK(x) do{if(!(x)){printf("FAIL utility line %d: %s errno=%d\n",__LINE__,#x,errno);return 1;}}while(0)
int main(int argc,char **argv)
{
    glob_t g;int a,b,n;char one[128],two[128],base[128];
    strcpy(base,argc>1?argv[1]:"/helios/tmp/hu-test");mkdir(base,0700);
    HU_CHECK(chdir(base)==0);
    a=open("a.txt",O_CREAT|O_WRONLY|O_TRUNC,0600);HU_CHECK(a>=0);close(a);
    a=open("b.txt",O_CREAT|O_WRONLY|O_TRUNC,0600);HU_CHECK(a>=0);close(a);
    a=open(".hidden.txt",O_CREAT|O_WRONLY|O_TRUNC,0600);HU_CHECK(a>=0);close(a);
    memset(&g,0,sizeof(g));g.gl_offs=2;
    HU_CHECK(glob("[ab].txt",GLOB_DOOFFS,NULL,&g)==0);
    HU_CHECK(g.gl_pathc==2&&g.gl_pathv[0]==NULL&&g.gl_pathv[1]==NULL);
    HU_CHECK(!strcmp(g.gl_pathv[2],"a.txt")&&!strcmp(g.gl_pathv[3],"b.txt")&&g.gl_pathv[4]==NULL);
    HU_CHECK(glob("no-such-file",GLOB_DOOFFS|GLOB_APPEND|GLOB_NOCHECK,NULL,&g)==0);
    HU_CHECK(g.gl_pathc==3&&!strcmp(g.gl_pathv[4],"no-such-file"));globfree(&g);
    HU_CHECK(glob("*.txt",0,NULL,&g)==0&&g.gl_pathc==2);globfree(&g);
    HU_CHECK(glob("nothing*",0,NULL,&g)==GLOB_NOMATCH);globfree(&g);
    strcpy(one,"temporaryXXXXXX");strcpy(two,one);
    a=mkstemp(one);b=mkstemp(two);HU_CHECK(a>=0&&b>=0&&strcmp(one,two));
    HU_CHECK(write(a,"one",3)==3);close(a);close(b);
    n=open(one,O_CREAT|O_EXCL|O_RDWR,0600);HU_CHECK(n<0&&errno==EEXIST);
    unlink(one);unlink(two);
    strcpy(one,"invalid");HU_CHECK(mkstemp(one)<0&&errno==EINVAL);
    unlink("a.txt");unlink("b.txt");unlink(".hidden.txt");
    puts("PASS glob offsets/append/matching and temporary files");return 0;
}
