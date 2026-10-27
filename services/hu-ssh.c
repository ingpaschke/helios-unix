/* Native Helios SSH terminal client; protocol and crypto live in a provider. */
#include <helios/unix/ssh.h>
#include <helios/unix/api.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <netdb.h>
#ifdef __HELIOS
#include <helios/unix/netdb.h>
#endif
#include <termios.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static volatile sig_atomic_t interrupted,resized;
static int raw,old_flags=-1;
static int saved_encoding=-1;
static struct termios saved_terminal;
static void interrupt(int sig){interrupted=sig;}
static void resize_signal(int sig){(void)sig;resized=1;}
static void restore(void)
{
    if(saved_encoding>=0) {
        const char *mode=saved_encoding?"\033%G":"\033%@";int left=3;
        while(left) {int n=write(1,mode,left);
            if(n>0){mode+=n;left-=n;}else if(n<0&&errno==EINTR)continue;else break;}
        saved_encoding=-1;
    }
    if(raw)hu_terminal_restore(0,&saved_terminal);
    if(old_flags>=0)fcntl(0,F_SETFL,old_flags);
}
static void pause_ms(unsigned ms)
{struct timeval t;t.tv_sec=ms/1000;t.tv_usec=(ms%1000)*1000;select(0,NULL,NULL,NULL,&t);}
static int prompt(const char *message,char *out,unsigned size,int secret)
{
    struct termios old,t;int hidden=0,too_long=0;size_t n;
    if(interrupted || size<2)return -1;
    fputs(message,stderr);fflush(stderr);
    if(secret && tcgetattr(0,&old)==0){t=old;t.c_lflag&=~ECHO;hidden=tcsetattr(0,TCSANOW,&t)==0;}
    if(!fgets(out,size,stdin)){if(hidden)tcsetattr(0,TCSANOW,&old);return -1;}
    n=strlen(out);
    if(n==size-1 && out[n-1]!='\n'){
        int tail=fgetc(stdin);
        if(tail!='\n' && tail!=EOF)too_long=1;
    }
    if(hidden){tcsetattr(0,TCSANOW,&old);fputc('\n',stderr);}
    if(too_long){fprintf(stderr,"ssh: input too long\n");return -1;}
    if(ferror(stdin))return -1;
    while(n && (out[n-1]=='\n'||out[n-1]=='\r'))out[--n]=0;
    return interrupted?-1:0;
}
/* This client's hosts file contains: hostname port key-type fingerprint.
 * It is intentionally separate from OpenSSH's encoded known_hosts format. */
static int host_key(const struct hu_ssh_options *o,const struct hu_ssh_info *i,const char *file)
{
    char line[512],host[256],type[64],fingerprint[96],answer[32];unsigned port;
    FILE *f=fopen(file,"r");
    if(f) {
        while(fgets(line,sizeof(line),f)) {
            if(sscanf(line,"%255s %u %63s %95s",host,&port,type,fingerprint)!=4)continue;
            if(strcmp(host,o->host)||port!=o->port)continue;
            if(!strcmp(type,i->key_type)&&!strcmp(fingerprint,i->fingerprint)){fclose(f);return 1;}
            fclose(f);fprintf(stderr,"ssh: host key changed for %s:%u (%s)\n",o->host,o->port,file);return 0;
        }
        fclose(f);
    }
    fprintf(stderr,"Host %s:%u (%s)\n%s\n",o->host,o->port,i->key_type,i->fingerprint);
    if(prompt("Remember this host key? (yes/no) ",answer,sizeof(answer),0)<0 || strcmp(answer,"yes"))return 0;
    f=fopen(file,"a");
    if(!f){fprintf(stderr,"ssh: cannot save %s: %s\n",file,strerror(errno));return 0;}
    {
        int written=fprintf(f,"%s %u %s %s\n",o->host,o->port,i->key_type,i->fingerprint);
        int closed=fclose(f);
        if(written<0 || closed!=0) {
        fprintf(stderr,"ssh: cannot save host key\n");return 0;
        }
    }
    return 1;
}
static int connect_host(const char *host,const char *port)
{
    struct addrinfo hints,*all,*p;int fd=-1,error,last=0;
    memset(&hints,0,sizeof(hints));hints.ai_family=AF_INET;hints.ai_socktype=SOCK_STREAM;
    error=getaddrinfo(host,port,&hints,&all);
    if(error){fprintf(stderr,"ssh: %s: %s\n",host,gai_strerror(error));return -1;}
    for(p=all;p&&!interrupted;p=p->ai_next) {
        fd=socket(p->ai_family,p->ai_socktype,p->ai_protocol);
        if(fd<0){last=errno;continue;}
        if(connect(fd,p->ai_addr,p->ai_addrlen)==0)break;
        last=errno;close(fd);fd=-1;
    }
    freeaddrinfo(all);
    if(fd<0)fprintf(stderr,"ssh: connect %s:%s: %s\n",host,port,strerror(last));
    return fd;
}
static int write_all(int fd,const char *data,int size)
{
    while(size && !interrupted){int n=write(fd,data,size);
        if(n>0){data+=n;size-=n;}
        else if(n<0&&errno==EINTR)continue;else return -1;}
    return size?-1:0;
}
/* Xterm's read-only private mode 1020 reports the current UTF-8 setting.
 * Keep any interleaved keyboard bytes for the relay; only remove the reply.
 * Older terminals that do not answer are left in their existing encoding. */
static int terminal_encoding(struct hu_terminal_decoder *decoder,char *input,int size)
{
    const char *term=getenv("TERM");struct timeval now,until;
    int used=0,i,n;long left;
    if(!term||strncmp(term,"xterm",5)||!isatty(0)||!isatty(1))return 0;
    if(gettimeofday(&until,NULL)<0)return 0;
    until.tv_sec+=2;
    if(write_all(1,"\033[?1020$p",9)<0)return 0;
    while(used<size-2&&!interrupted) {
        fd_set r;struct timeval timeout;
        gettimeofday(&now,NULL);
        left=(until.tv_sec-now.tv_sec)*1000000L+until.tv_usec-now.tv_usec;
        if(left<=0)break;
        timeout.tv_sec=left/1000000;timeout.tv_usec=left%1000000;
        FD_ZERO(&r);FD_SET(0,&r);
        n=select(1,&r,NULL,NULL,&timeout);
        if(n<0&&errno==EINTR)continue;
        if(n<=0)break;
        n=hu_terminal_read(0,decoder,input+used,size-used);
        if(n<0&&(errno==EAGAIN||errno==EINTR))continue;
        if(n<=0)break;
        used+=n;
        for(i=0;i+11<=used;i++) {
            if(!memcmp(input+i,"\033[?1020;",8) &&
               input[i+8]>='0'&&input[i+8]<='4' &&
               !memcmp(input+i+9,"$y",2)) {
                int state=input[i+8]-'0';
                memmove(input+i,input+i+11,used-i-11);used-=11;
                if(state>=1&&state<=4) {
                    saved_encoding=state==1||state==3;
                    write_all(1,"\033%G",3);
                }
                return used;
            }
        }
    }
    return used;
}
static int relay(struct hu_ssh *s,int pty)
{
    char outgoing[4096],incoming[4096];int used=0,pos=0,eof=0,sent_eof=0,read_eof=0;
    int fd=hu_ssh_wait_fd(s),rc,max=fd>0?fd:0;struct hu_ssh_info info;
    struct hu_terminal_decoder decoder={0,0};
    struct stat st;int regular=fstat(0,&st)==0&&S_ISREG(st.st_mode);
    if(fd<0 || fd>=FD_SETSIZE){errno=EINVAL;return 255;}
    if(hu_ssh_status(s,&info)<0)return 255;
    if(info.state==HU_SSH_CLOSED)eof=sent_eof=1;
    if(pty && isatty(0)) {
        if(hu_terminal_raw(0,&saved_terminal)<0){perror("ssh: terminal raw mode");return 255;}
        raw=1;decoder.helios_c1=1;
    }
    old_flags=fcntl(0,F_GETFL);
    if(old_flags<0 || fcntl(0,F_SETFL,old_flags|O_NONBLOCK)<0){perror("ssh: terminal flags");return 255;}
    if(raw)used=terminal_encoding(&decoder,outgoing,sizeof(outgoing));
    resized=1;
    while(!interrupted) {
        fd_set r,w;struct timeval timeout;unsigned rows,columns;
        struct hu_ssh_wait rd,wr;int ms=read_eof?100:-1,input_ready;
        if(pty && resized) {
            resized=0;
            if(hu_terminal_size(0,&rows,&columns)==0 && hu_ssh_resize(s,columns,rows)<0) {
                if(hu_ssh_status(s,&info)<0 || info.state==HU_SSH_READY){perror("ssh: resize");return 255;}
            }
        }
        if(eof&&!used&&!sent_eof){if(hu_ssh_send_eof(s)<0){
            if(hu_ssh_status(s,&info)<0||info.state!=HU_SSH_CLOSED){perror("ssh: EOF");return 255;}
        }sent_eof=1;}
        FD_ZERO(&r);FD_ZERO(&w);
        input_ready=regular&&!eof&&!used&&!read_eof;
        if(!regular&&!eof&&!used&&!read_eof)FD_SET(0,&r);
        memset(&rd,0,sizeof(rd));memset(&wr,0,sizeof(wr));rd.timeout_ms=wr.timeout_ms=-1;
        if(!read_eof) {
            if(hu_ssh_interest(s,HU_SSH_READ,&rd)<0)return 255;
            if(rd.events&HU_SSH_WAIT_READ)FD_SET(fd,&r);
            if(rd.events&HU_SSH_WAIT_WRITE)FD_SET(fd,&w);
            if(rd.timeout_ms>=0&&(ms<0||rd.timeout_ms<ms))ms=rd.timeout_ms;
        }
        if(used) {
            if(hu_ssh_interest(s,HU_SSH_WRITE,&wr)<0)return 255;
            if(wr.events&HU_SSH_WAIT_READ)FD_SET(fd,&r);
            if(wr.events&HU_SSH_WAIT_WRITE)FD_SET(fd,&w);
            if(wr.timeout_ms>=0&&(ms<0||wr.timeout_ms<ms))ms=wr.timeout_ms;
        }
        if(input_ready)ms=0;
        timeout.tv_sec=ms<0?0:ms/1000;timeout.tv_usec=ms<0?0:(ms%1000)*1000;
        rc=select(max+1,&r,&w,NULL,ms<0?NULL:&timeout);
        if(rc<0){if(errno==EINTR)continue;perror("ssh: select");return 255;}
        if(used && (wr.timeout_ms==0 || (!rc&&wr.timeout_ms>=0&&ms>=wr.timeout_ms) || ((wr.events&HU_SSH_WAIT_READ)&&FD_ISSET(fd,&r)) || ((wr.events&HU_SSH_WAIT_WRITE)&&FD_ISSET(fd,&w)))) {
            int n=hu_ssh_write(s,outgoing+pos,used-pos);
            if(n>0){pos+=n;if(pos==used)pos=used=0;}
            else if(n<0&&errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR){
                if(hu_ssh_status(s,&info)==0&&info.state==HU_SSH_CLOSED){used=pos=0;eof=sent_eof=1;}
                else {perror("ssh: write");return 255;}
            }
        }
        if(!read_eof && (rd.timeout_ms==0 || (!rc&&rd.timeout_ms>=0&&ms>=rd.timeout_ms) || ((rd.events&HU_SSH_WAIT_READ)&&FD_ISSET(fd,&r)) || ((rd.events&HU_SSH_WAIT_WRITE)&&FD_ISSET(fd,&w)))) {
            int n=hu_ssh_read(s,incoming,sizeof(incoming));
            if(n>0){if(write_all(1,incoming,n)<0)return 255;}
            else if(n==0)read_eof=1;
            else if(errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR){perror("ssh: read");return 255;}
        }
        if(!used && (input_ready||FD_ISSET(0,&r))) {
            int n=hu_terminal_read(0,&decoder,outgoing,sizeof(outgoing));
            if(n>0)used=n;
            else if(n==0)eof=1;
            else if(errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR){perror("ssh: input");return 255;}
        }
        if(read_eof) {
            if(hu_ssh_status(s,&info)<0){perror("ssh: status");return 255;}
            if(info.state==HU_SSH_FAILED){fprintf(stderr,"ssh: %s\n",info.message);return 255;}
            if(info.state==HU_SSH_CLOSED)return info.exit_valid?info.exit_status:255;
        }
    }
    return 255;
}
static void usage(void)
{fputs("Usage: ssh [-t|-T] [-p port] [-l user] [-i private-key] [-K hosts-file] [user@]host [command ...]\n",stderr);}
int main(int argc,char **argv)
{
    struct hu_ssh_options o;struct hu_ssh_info info;struct hu_ssh *s=NULL;
    char host[256],user[64],hosts[512],command[768],port[16],secret[512];
    char *key=NULL,*identity=NULL,*hosts_file=NULL,*username=NULL,*target,*at,*home;
    int arg=1,tty=-1,fd=-1,status=255,trusted=0,key_tried=0,password_tries=0;long number;
    unsigned key_size=0;
    setvbuf(stdin,NULL,_IONBF,0);
    memset(&o,0,sizeof(o));command[0]=0;strcpy(port,"22");
    while(arg<argc && argv[arg][0]=='-' && argv[arg][1]) {
        char *option=argv[arg++];
        if(!strcmp(option,"--"))break;
        if(!strcmp(option,"-t")){tty=1;continue;}
        if(!strcmp(option,"-T")){tty=0;continue;}
        if(!strcmp(option,"--help")){usage();return 0;}
        if(arg==argc){usage();return 2;}
        if(!strcmp(option,"-l"))username=argv[arg++];
        else if(!strcmp(option,"-i"))identity=argv[arg++];
        else if(!strcmp(option,"-K"))hosts_file=argv[arg++];
        else if(!strcmp(option,"-p")) {
            char *end;number=strtol(argv[arg++],&end,10);
            if(*end||number<1||number>65535){usage();return 2;}sprintf(port,"%ld",number);
        }else {usage();return 2;}
    }
    if(arg==argc){usage();return 2;}
    target=argv[arg++];at=strrchr(target,'@');
    if(at) {
        if(at==target||at-target>=sizeof(user)){usage();return 2;}
        memcpy(user,target,at-target);user[at-target]=0;username=user;target=at+1;
    }
    if(!*target||strlen(target)>=sizeof(host)){usage();return 2;}strcpy(host,target);
    if(!username)username=getenv("USER");if(!username)username=getenv("LOGNAME");
    if(!username||!*username||strlen(username)>=sizeof(user)){fprintf(stderr,"ssh: specify user@host or -l user\n");return 2;}
    if(username!=user)strcpy(user,username);
    while(arg<argc) {
        if(strlen(command)+strlen(argv[arg])+2>sizeof(command)){fprintf(stderr,"ssh: command too long\n");return 2;}
        if(*command)strcat(command," ");strcat(command,argv[arg++]);
    }
    home=getenv("HOME");if(!home)home="/helios/users/guest";
    if(!hosts_file) {
        if(strlen(home)+12>=sizeof(hosts)){fprintf(stderr,"ssh: HOME too long\n");return 2;}
        sprintf(hosts,"%s/.ssh",home);
        if(mkdir(hosts,0700)<0&&errno!=EEXIST){perror("ssh: .ssh");return 255;}
        strcat(hosts,"/hosts");hosts_file=hosts;
    }
    if(identity) {
        FILE *f=fopen(identity,"rb");int n;
        if(!f){perror(identity);return 255;}
        key=malloc(HU_SSH_MAX_KEY+1);if(!key){fclose(f);return 255;}
        n=fread(key,1,HU_SSH_MAX_KEY+1,f);fclose(f);
        if(n<=0||n>HU_SSH_MAX_KEY){fprintf(stderr,"ssh: private key must be at most %d bytes\n",HU_SSH_MAX_KEY);free(key);return 255;}
        key_size=n;
    }
    signal(SIGINT,interrupt);signal(SIGTERM,interrupt);signal(SIGHUP,interrupt);signal(SIGPIPE,SIG_IGN);
#ifdef SIGWINCH
    signal(SIGWINCH,resize_signal);
#endif
    atexit(restore);
    {
        o.host=host;o.user=user;o.port=atoi(port);o.terminal=getenv("TERM");
        if(!o.terminal)o.terminal="vt100";
        o.command=*command?command:NULL;o.pty=tty<0?(!*command&&isatty(0)):tty;
        o.columns=80;o.rows=24;o.timeout_ms=30000;
        if(o.pty)hu_terminal_size(0,&o.rows,&o.columns);
        fd=connect_host(host,port);if(fd<0)goto done;
        s=hu_ssh_open_fd(&o,fd);
        if(!s){perror("ssh: SSH provider (requires an SSH-enabled io-server)");close(fd);goto done;}
        while(!interrupted) {
            if(hu_ssh_status(s,&info)<0){perror("ssh: status");goto done;}
            if(info.state==HU_SSH_HOSTKEY&&!trusted) {
                trusted=host_key(&o,&info,hosts_file);
                if(hu_ssh_trust(s,trusted)<0){perror("ssh: host key");goto done;}
                if(!trusted)goto done;
            }else if(info.state==HU_SSH_AUTH) {
                struct hu_ssh_auth auth;memset(&auth,0,sizeof(auth));secret[0]=0;
                if(key&&!key_tried&&(info.auth_methods&HU_SSH_PUBLICKEY)) {
                    auth.method=HU_SSH_PUBLICKEY;auth.key=key;auth.key_size=key_size;key_tried=1;
                    if(prompt("Private-key passphrase (Return if none): ",secret,sizeof(secret),1)<0)goto done;
                }else if((info.auth_methods&HU_SSH_PASSWORD)&&password_tries++<3) {
                    if(info.auth_attempt)fprintf(stderr,"ssh: %s\n",info.message);
                    auth.method=HU_SSH_PASSWORD;
                    if(prompt("Password: ",secret,sizeof(secret),1)<0)goto done;
                }else {fprintf(stderr,"ssh: no usable authentication method\n");goto done;}
                auth.secret=secret;
                if(hu_ssh_authenticate(s,&auth)<0){memset(secret,0,sizeof(secret));perror("ssh: authentication");goto done;}
                memset(secret,0,sizeof(secret));
            }else if(info.state==HU_SSH_READY || (info.state==HU_SSH_CLOSED&&info.exit_valid)){status=relay(s,o.pty);goto done;}
            else if(info.state==HU_SSH_FAILED||info.state==HU_SSH_CLOSED){fprintf(stderr,"ssh: %s\n",info.message);goto done;}
            pause_ms(100);
        }
    }
done:
    hu_ssh_close(s);if(key){memset(key,0,HU_SSH_MAX_KEY+1);free(key);}restore();raw=0;old_flags=-1;
    return status;
}
