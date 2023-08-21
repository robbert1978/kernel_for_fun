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

#define PAGE_SIZE 0x1000
#define PAGE_SIZE 0x1000

#ifdef DEBUG

#define logOK(msg, ...)     fprintf(stderr,"[+] " msg "\n", ##__VA_ARGS__)

#define logInfo(msg, ...)   fprintf(stderr,"[!] " msg "\n", ##__VA_ARGS__)

#define logErr(msg, ...)    fprintf(stderr,"[-] " msg "\n", ##__VA_ARGS__)

#define errExit(msg, ...)   do{ fprintf(stderr,"[-] " msg " ", ##__VA_ARGS__) ; perror("") ; exit(-1) ; }while(0)

#else

#define logOK(msg, ...)     asm("nop");

#define logInfo(msg, ...)   asm("nop");

#define logErr(msg, ...)    asm("nop");

#define errExit(msg, ...)   asm("nop");

#endif


int ufd;
uint64_t uf_page;

char uf_buffer[PAGE_SIZE];

void register_ufd(uint64_t page) {
    int fd = 0;
    uf_page = page;
    struct uffdio_api api = { .api = UFFD_API };

    uf_page = (uint64_t)mmap((void *)uf_page, PAGE_SIZE, PROT_READ|PROT_WRITE, MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE, 0, 0);
    if ((void *)uf_page == MAP_FAILED) {
        perror("mmap uf_page");
        exit(2);
    }

    if ((fd = userfaultfd(O_NONBLOCK)) == -1) {
        errExit("userfaultfd failed");
    }

    if (ioctl(fd, UFFDIO_API, &api)) {
        errExit("+ ioctl(fd, UFFDIO_API, ...) failed");
    }
    if (api.api != UFFD_API) {
        errExit("unexepcted UFFD api version.");
    }

    /* mmap some pages, set them up with the userfaultfd. */
    struct uffdio_register reg = {
        .mode = UFFDIO_REGISTER_MODE_MISSING,
        .range = {
            .start = uf_page,
            .len = PAGE_SIZE
        }
    };

    if (ioctl(fd, UFFDIO_REGISTER,  &reg) == -1) {
        errExit("ioctl(fd, UFFDIO_REGISTER, ...) failed");
    }

    ufd = fd;
}

void *race_userfault(void (*func)()) {
    
    struct pollfd evt = { .fd = ufd, .events = POLLIN };

    while (poll(&evt, 1, -1) > 0) {
        /* unexpected poll events */
        if (evt.revents & POLLERR) {
            perror("poll");
            exit(-1);
        } else if (evt.revents & POLLHUP) {
            perror("pollhup");
            exit(-1);
        }
        struct uffd_msg fault_msg = {0};
        if (read(ufd, &fault_msg, sizeof(fault_msg)) != sizeof(fault_msg)) {
            perror("read");
            exit(-1);
        }
        char *place = (char *)fault_msg.arg.pagefault.address;
        if (fault_msg.event != UFFD_EVENT_PAGEFAULT
                || (place != (void *)uf_page && place != (void *)uf_page + PAGE_SIZE)) {
            fprintf(stderr, "unexpected pagefault?.\n");
            exit(-1);
        }
        if (place == (void *)uf_page) {
            logInfo("Page fault at address %p, nice!\n", place);
            func();
            /* release by copying some data to faulting address */
            struct uffdio_copy copy = {
                .dst = (long) place,
                .src = (long) uf_buffer,
                .len = PAGE_SIZE
            };
            if (ioctl(ufd, UFFDIO_COPY, &copy) < 0) {
                perror("ioctl(UFFDIO_COPY)");
                exit(-1);
            }
            break;
        }
    }
    close(ufd);
    return NULL;
}

int userfaultfd(int flags) {
    return syscall(SYS_userfaultfd, flags);
}