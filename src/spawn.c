#include <helios/unix/spawn.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
extern char **environ;
extern int hu_spawn_native(pid_t *,const char *,const struct hu_spawn_actions *,
                           const struct hu_spawn_attr *,char *const[],char *const[]);
void hu_spawn_actions_init(struct hu_spawn_actions *a){if(a)memset(a,0,sizeof(*a));}
void hu_spawn_actions_destroy(struct hu_spawn_actions *a)
{unsigned i;if(!a)return;for(i=0;i<a->count;i++)free(a->items[i].path);memset(a,0,sizeof(*a));}
static int action(struct hu_spawn_actions *a,int kind,int source,int fd,const char *path,int flags)
{
    struct hu_spawn_action *p;
    if(!a||a->count>=HU_SPAWN_ACTIONS_MAX||fd<0||fd>=4096||source<0||source>=4096)return EINVAL;
    p=&a->items[a->count];memset(p,0,sizeof(*p));
    if(path){p->path=malloc(strlen(path)+1);if(!p->path)return ENOMEM;strcpy(p->path,path);}
    p->kind=kind;p->source=source;p->fd=fd;p->flags=flags;a->count++;return 0;
}
int hu_spawn_addclose(struct hu_spawn_actions *a,int fd){return action(a,0,0,fd,NULL,0);}
int hu_spawn_adddup2(struct hu_spawn_actions *a,int src,int dst){return action(a,1,src,dst,NULL,0);}
int hu_spawn_addopen(struct hu_spawn_actions *a,int fd,const char *p,int flags)
{if(!p)return EINVAL;return action(a,2,0,fd,p,flags);}
int hu_spawn(pid_t *pid,const char *name,const struct hu_spawn_actions *a,
              const struct hu_spawn_attr *attr,char *const argv[],char *const env[])
{
    if(!pid||!name||!*name||!argv||!argv[0])return EINVAL;
    return hu_spawn_native(pid,name,a,attr,argv,env?env:environ);
}
int hu_spawnp(pid_t *pid,const char *name,const struct hu_spawn_actions *a,
              const struct hu_spawn_attr *attr,char *const argv[],char *const env[])
{
    const char *path,*end;char candidate[1024];size_t n;int e,denied=0;
    if(!name||!*name)return EINVAL;
    if(strchr(name,'/'))return hu_spawn(pid,name,a,attr,argv,env);
    path=getenv("PATH");if(!path)path="/helios/local/bin:/helios/bin:/helios/bin/x11";
    do {
        end=strchr(path,':');if(!end)end=path+strlen(path);n=end-path;
        if(n+strlen(name)+2>=sizeof(candidate))return ENAMETOOLONG;
        memcpy(candidate,path,n);if(n)candidate[n++]='/';strcpy(candidate+n,name);
        e=hu_spawn(pid,candidate,a,attr,argv,env);
        if(!e)return 0;if(e==EACCES)denied=1;
        else if(e!=ENOENT&&e!=ENOTDIR)return e;
        path=*end?end+1:NULL;
    }while(path);
    return denied?EACCES:ENOENT;
}
