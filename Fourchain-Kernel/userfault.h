#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <linux/userfaultfd.h>
#include <sys/wait.h>
#include <poll.h>
#include <sys/mman.h>
#include <stddef.h>
#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdbool.h>
#include <assert.h>

#define PAGE_SIZE 0x1000

struct userfault_arg
{
    uint32_t ufd;
    uint64_t uf_page;
    void (*func)(void);
};

extern int userfault_fd;
extern void *userfault_page;
extern pthread_t userfault_pthread;
extern uint32_t numPageFault;
extern bool startRace;
extern void (*userEventHandler)();

void userfaultfd_init();
void userfaultfd_register(void *addr, size_t len);
void *userfault_thread(void *);
int ufd_unblock_page_copy(void *unblock_page, void *content_page);

// User define
