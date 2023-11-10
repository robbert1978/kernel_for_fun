#include "userfault.h"
#define DEBUG

#ifdef DEBUG

#define logOK(msg, ...) dprintf(STDERR_FILENO, "[+] " msg "\n", ##__VA_ARGS__)

#define logInfo(msg, ...) dprintf(STDERR_FILENO, "[*] " msg "\n", ##__VA_ARGS__)

#define logErr(msg, ...) dprintf(STDERR_FILENO, "[!] " msg "\n", ##__VA_ARGS__)

#define errExit(msg, ...)                                      \
    do                                                         \
    {                                                          \
        dprintf(STDERR_FILENO, "[-] " msg " ", ##__VA_ARGS__); \
        perror("");                                            \
        exit(-1);                                              \
    } while (0)

#define WAIT()                                        \
    do                                                \
    {                                                 \
        write(STDERR_FILENO, "[WAITTING ...]\n", 16); \
        getchar();                                    \
    } while (0)

#else

#define logOK(...) \
    do             \
    {              \
    } while (0)
#define logInfo(...) \
    do               \
    {                \
    } while (0)
#define logErr(...) \
    do              \
    {               \
    } while (0)
#define errExit(...) \
    do               \
    {                \
    } while (0)

#endif

#define userfaultfd(flags) syscall(SYS_userfaultfd, flags)

int userfault_fd;
void *userfault_page;
pthread_t userfault_pthread;
uint32_t numPageFault;
void (*userEventHandler)();

static inline int pin_cpu(int cpu)
{
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu, &cpuset);
    return sched_setaffinity(0, sizeof cpuset, &cpuset);
}

// Initialize userfaultfd. Must call this before using the other userfault_*
// functions.
void userfaultfd_init()
{
    for (size_t i = 0; i < 2; i++)
    {
        userfault_fd = syscall(SYS_userfaultfd, O_CLOEXEC);
        if (userfault_fd < 0)
        {
            errExit("userfaultfd");
        }

        // Enable userfaultfd
        struct uffdio_api api = {
            .api = UFFD_API,
            .features = 0,
        };
        if (ioctl(userfault_fd, UFFDIO_API, &api) < 0)
        {
            errExit("ioctl(UFFDIO_API)");
        }
    }

    numPageFault = 0;

    pthread_create(&userfault_pthread, NULL, userfault_thread, NULL);

    logInfo("userfaultfd initialized");
}

void userfaultfd_register(void *addr, size_t len)
{
    assert(((uintptr_t)addr % 0x1000) == 0);
    assert(len >= 0x1000 && len % 0x1000 == 0);

    struct uffdio_register reg = {
        .range = {
            .start = (uintptr_t)addr,
            .len = len,
        },
        .mode = UFFDIO_REGISTER_MODE_MISSING,
    };
    if (ioctl(userfault_fd, UFFDIO_REGISTER, &reg) < 0)
    {
        errExit("ioctl(UFFDIO_REGISTER)");
    }

    numPageFault++;
}
bool startRace = 0;
void *userfault_thread(void *arg)
{
    struct uffd_msg msg;
    struct uffdio_copy copy;

    pin_cpu(0);

    while (startRace == false)
    {
        ;
    }

    if (numPageFault == 0)
    {
        logErr("Nothing to do here!");
        return NULL;
    }

    for (uint i = 0; i < numPageFault; ++i)
    {

        if (read(userfault_fd, &msg, sizeof(msg)) != sizeof(msg))
        {
            errExit("userfault_thread::read");
        }
        else if (msg.event != UFFD_EVENT_PAGEFAULT)
        {
            errExit("unexpected uffd event");
        }

        logInfo("Got userfault block %u (addr %.16p)", i, (void *)msg.arg.pagefault.address);
    }

    numPageFault = 0;
    userEventHandler();

    return NULL;
}

int ufd_unblock_page_copy(void *unblock_page, void *content_page)
{
    size_t copy_out = 0;
    struct uffdio_copy copy = {
        .dst = (uintptr_t)unblock_page,
        .src = (uintptr_t)content_page,
        .len = 0x1000,
        .copy = (uintptr_t)&copy_out,
        .mode = 0};

    logInfo("Unblocking %p ...", unblock_page);
    if (ioctl(userfault_fd, UFFDIO_COPY, &copy))
        errExit("UFFDIO_COPY failed");
    return copy_out;
}
