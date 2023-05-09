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

int main(){
    u_int64_t len = 0x2000;
    char* addr = mmap((void *)0x13370000, len, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    puts("Access 2nd!");
    addr[0x1001]=0x1337;
    getchar();
    puts("Access 1st!");
    addr[0]=0x1338;
    getchar();
}