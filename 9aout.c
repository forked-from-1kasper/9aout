#define _GNU_SOURCE

#include <sys/sysinfo.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <ucontext.h>
#include <stdlib.h>
#include <unistd.h>
#include <libgen.h>
#include <endian.h>
#include <stdint.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <time.h>
#include <elf.h>

#include <sys/resource.h>
#include <linux/sched.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sched.h>

#include "9aout.h"
#include "errstr.h"
#include "syscall.h"

uint64_t millisecs(struct timeval time)
{ return time.tv_sec * 1000L + time.tv_usec / 1000L; }

uint64_t timestamp()
{
    struct timespec spec; clock_gettime(CLOCK_MONOTONIC, &spec);
    return spec.tv_sec * 1000L + spec.tv_nsec / 1e+6L;
}

static char errstr[ERRMAX] = {0};

char * exitmsg = NULL;

int _fd = -1; segment _text, _data = {0}; List * family = NULL;

void nuke() {
    if (_text.begin) munmap(_text.begin, _text.size);
    if (_data.begin) munmap(_data.begin, _data.size);
    if (_fd != -1)   close(_fd);
}

void swap(int fd, segment text, segment data)
{ _fd = fd; _text = text; _data = data; }

void attach_child(int pid, char * msg) {
    List * node = malloc(sizeof(List));

    node->pid            = pid;
    node->next           = family;
    node->data.exitmsg   = msg;
    node->data.timestamp = timestamp();

    family = node;
}

pdata detach_child(int pid) {
    pdata retval = {0};

    List * prev = NULL, * cur = family;

    while (cur != NULL) {
        if (cur->pid == pid) {
            retval = cur->data;

            if (prev) prev->next = cur->next;
            else family = cur->next;

            free(cur);

            return retval;
        } else { prev = cur; cur = cur->next; }
    }

    return retval;
}

void free_list(List * xs) {
    while (xs != NULL) {
        List * next = xs->next;
        free(xs); xs = next;
    }
}

void detach_everything() { free_list(family); family = NULL; }

uint64_t sys_plan9_unimplemented(uint64_t * rsp, greg_t * regs) {
    #ifdef DEBUG
        printf("P9: %lld called but unimplemented!\n", regs[REG_RBP]);
    #endif

    return 0;
}

uint64_t sys_plan9_deprecated(uint64_t * rsp, greg_t * regs) {
    #ifdef DEBUG
        printf("P9: syscall number %lld DEPRECATED!\n", regs[REG_RBP]);
    #endif

    return 0;
}

uint64_t sys_exits(uint64_t * rsp, greg_t * regs) {
    char * buf = (char*) *(++rsp);

    #ifdef DEBUG
        if (buf != NULL) printf("exits: %s\n", buf);
        else printf("exits\n");
    #endif

    int exitcode = (buf == NULL || buf[0] == '\0') ? 0 : -1;

    if (exitmsg && buf) strncpy(exitmsg, buf, ERRLEN);

    detach_everything(); nuke(); exit(exitcode);
}

uint64_t sys_pread(uint64_t * rsp, greg_t * regs) {
    int fd = (int) *(++rsp);
    void * buf = (void*) *(++rsp);
    size_t len = (uint32_t) *(++rsp);
    off_t offset = (uint64_t) *(++rsp);

    #ifdef DEBUG
        printf("PREAD fd = %d len = %ld offset = %ld\n", fd, len, offset);
    #endif

    return (offset == -1) ? read(fd, buf, len) : pread(fd, buf, len, offset);
}

uint64_t sys_pwrite(uint64_t * rsp, greg_t * regs) {
    int fd = (int) *(++rsp);
    void * buf = (void*) *(++rsp);
    size_t len = (uint32_t) *(++rsp);
    off_t offset = (uint64_t) *(++rsp);

    #ifdef DEBUG
        printf("PWRITE fd = %d len = %ld offset = %ld\n", fd, len, offset);
    #endif

    return (offset == -1) ? write(fd, buf, len) : pwrite(fd, buf, len, offset);
}

uint64_t sys_brk(uint64_t * rsp, greg_t * regs) {
    void * addr = (void*) *(++rsp);

    size_t size = addr - _data.begin;
    void * ptr  = mremap(_data.begin, _data.size, size, 0);

    if (ptr == MAP_FAILED) return -1;

    _data.size = size; _data.begin = ptr; return 0;
}

uint64_t seterror(char * err) {
    strncpy(errstr, err, ERRMAX);
    return -1;
}

int plan9mode(int32_t mode) {
    int retval = 0;

    switch (mode & 0x11) {
        case OREAD:  retval = O_RDONLY; break;
        case OWRITE: retval = O_WRONLY; break;
        case ORDWR:  retval = O_RDWR;   break;
        case OEXEC:  retval = O_RDONLY; break;
    }

    if (mode & OTRUNC) retval |= O_TRUNC;
    if (mode & OCEXEC) retval |= O_CLOEXEC;
    if (mode & OEXCL)  retval |= O_EXCL;

    return retval;
}

int modechk(char * file, int32_t mode) {
    if ((mode & 0x11) == OEXEC)
        if (access(file, X_OK))
            return seterror(Eperm);

    if (mode & ORCLOSE) unlink(file);

    return 0;
}

char * geterror(int error) {
    switch (error) {
        case EACCES:       return Eperm;
        case EEXIST:       return Eexist;
        case ENOENT:       return Enonexist;
        case ENAMETOOLONG: return Efilename;
        case ENFILE:       return Enofd;
        case EBADF:        return Edabf;
        case EINTR:        return Eintr;
        case EIO:          return Eio;
        case ENOSPC:       return Enospc;
        case EDQUOT:       return Edquot;
        default:           return strerror(error);
    }
}

int seterrno() { return seterror(geterror(errno)); }

uint64_t sys_open(uint64_t * rsp, greg_t * regs) {
    char * file = (char*) *(++rsp);
    int32_t mode = (int32_t) *(++rsp);

    int fd = open(file, plan9mode(mode));
    if (modechk(file, mode)) return -1;

    #ifdef DEBUG
        printf("OPEN file = %s mode = %d fd = %d\n", file, mode, fd);
    #endif

    return (fd != -1) ? fd : seterrno();
}

uint64_t sys_close(uint64_t * rsp, greg_t * regs) {
    int fd = (int) *(++rsp);

    #ifdef DEBUG
        printf("CLOSE fd = %d\n", fd);
    #endif

    return (close(fd) != -1) ? 0 : seterrno();
}

uint64_t sys_seek(uint64_t * rsp, greg_t * regs) {
    off_t * retp = (off_t*) *(++rsp);

    int fd = (int) *(++rsp);

    off_t offset = (uint64_t) *(++rsp);
    int type = (int) *(++rsp);

    #ifdef DEBUG
        printf("SEEK fd = %d offset = %ld type = %d\n", fd, offset, type);
    #endif

    int whence = 0;
    switch (type) {
        case 0:  whence = SEEK_SET; break;
        case 1:  whence = SEEK_CUR; break;
        case 2:  whence = SEEK_END; break;
        default: seterror(Ebadarg); return -1;
    }

    off_t retval = lseek(fd, offset, whence); *retp = retval;

    return (retval != -1) ? 0 : seterrno();
}

uint64_t sys_create(uint64_t * rsp, greg_t * regs) {
    char * file = (char*) *(++rsp);
    int32_t mode = (int32_t) *(++rsp);
    uint32_t perm = (uint32_t) *(++rsp);

    #ifdef DEBUG
        printf("CREATE file = %s mode = %d perm = %d\n", file, mode, perm);
    #endif

    int fd = open(file, plan9mode(mode) | O_CREAT | O_TRUNC, perm);
    if (modechk(file, mode)) return -1;

    return (fd != -1) ? fd : seterrno();
}

uint64_t sys_remove(uint64_t * rsp, greg_t * regs) {
    char * file = (char*) *(++rsp);
    return remove(file);
}

uint64_t sys_fd2path(uint64_t * rsp, greg_t * regs) {
    int fd = (int) *(++rsp);
    char * buf = (char*) *(++rsp);
    size_t nbuf = (size_t) *(++rsp);

    char filename[255] = {0};
    sprintf(filename, "/proc/self/fd/%d", fd);
    readlink(filename, buf, nbuf);

    return 0;
}

uint64_t generrstr(char *msg, size_t nbuf) {
    char buf[ERRMAX]; if (nbuf == 0) return 0;
    if (nbuf > ERRMAX) nbuf = ERRMAX;

    strncpy(buf, msg, nbuf);
    strncpy(msg, errstr, nbuf);
    strncpy(errstr, buf, nbuf);

    return 0;
}

uint64_t sys_errstr(uint64_t * rsp, greg_t * regs) {
    char * msg = (char*) *(++rsp);
    size_t len = (uint32_t) *(++rsp);

    return generrstr(msg, len);
}

uint64_t sys_dup(uint64_t * rsp, greg_t * regs) {
    int oldfd = (int32_t) *(++rsp);
    int newfd = (int32_t) *(++rsp);

    #ifdef DEBUG
        printf("DUP oldfd = %d newfd = %d\n", oldfd, newfd);
    #endif

    int fd = (newfd == -1) ? dup(oldfd) : dup2(oldfd, newfd);

    return (fd != -1) ? fd : seterrno();
}

uint64_t sys_chdir(uint64_t * rsp, greg_t * regs) {
    char * path = (char*) *(++rsp);

    #ifdef DEBUG
        printf("CHDIR path = %s\n", path);
    #endif

    return (chdir(path) != -1) ? 0 : seterrno();
}

uint64_t sys_sleep(uint64_t * rsp, greg_t * regs) {
    uint32_t millisecs = (uint32_t) *(++rsp);

    #ifdef DEBUG
        printf("SLEEP %d\n", millisecs);
    #endif

    struct timespec time = {0};

    time.tv_sec = millisecs / 1000;
    time.tv_nsec = (millisecs % 1000) * 1e+6;

    return nanosleep(&time, NULL);
}

int init(void);

uint64_t sys_rfork(uint64_t * rsp, greg_t * regs) {
    int flags = (int) *(++rsp);

    #ifdef DEBUG
        printf("RFORK flags = %d\n", flags);
    #endif

    if ((flags & (RFFDG|RFCFDG)) == (RFFDG|RFCFDG))
        return seterror(Ebadarg);
    if ((flags & (RFNAMEG|RFCNAMEG)) == (RFNAMEG|RFCNAMEG))
        return seterror(Ebadarg);
    if ((flags & (RFENVG|RFCENVG)) == (RFENVG|RFCENVG))
        return seterror(Ebadarg);

    if (!(flags & RFPROC)) return seterror("!RFPROC not implemented.");

    if (flags & RFNAMEG)  return seterror("RFNAMEG not implemented.");
    if (flags & RFENVG)   return seterror("RFENVG not implemented.");
    if (flags & RFNOTEG)  return seterror("RFNOTEG not implemented.");
    if (flags & RFMEM)    return seterror("RFMEM not implemented.");
    if (flags & RFNOWAIT) return seterror("RFNOWAIT not implemented.");
    if (flags & RFCNAMEG) return seterror("RFCNAMEG not implemented.");
    if (flags & RFCENVG)  return seterror("RFCENVG not implemented.");
    if (flags & RFCFDG)   return seterror("RFCFDG not implemented.");
    //if (flags & RFREND)   return seterror("RFREND not implemented.");
    if (flags & RFNOMNT)  return seterror("RFNOMNT not implemented.");

    struct clone_args params = {0};
    if (!(flags & RFFDG)) params.flags |= CLONE_FILES;

    params.exit_signal = SIGCHLD;

    char * cexitmsg = NULL;

    if (flags & RFPROC) {
        cexitmsg = mmap(NULL, ERRLEN * sizeof(char), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        memset(cexitmsg, 0, ERRLEN * sizeof(char));
    }

    int pid = syscall(SYS_clone3, &params, sizeof(params));

    if (flags & RFPROC) {
        // https://man7.org/linux/man-pages/man2/prctl.2.html
        // The setting (PR_SET_SYSCALL_USER_DISPATCH) is not preserved
        // across fork(2), clone(2), or execve(2).
        if (pid == 0) { init(); detach_everything(); exitmsg = cexitmsg; }
        else attach_child(pid, cexitmsg);
    }

    return pid;
}

int load(char *, int, char **);

uint64_t sys_exec(uint64_t * rsp, greg_t * regs) {
    char * filename0 = (char*) *(++rsp);

    char ** argv0 = (char**) *(++rsp);

    if (argv0 == NULL || *argv0 == NULL) return seterror(Ebadarg);
    int argc = 0; for (; argv0[argc] != NULL; argc++);

    #ifdef DEBUG
        printf("EXEC filename = %s argc = %d\n", filename0, argc);
    #endif

    // When filename/argv will be used in the new code, current code will
    // already be unloaded, as well as data segment, so we need to copy them
    char * filename = strdup(filename0);
    char ** argv = calloc(argc, sizeof(char*));

    for (size_t i = 0; i < argc; i++)
        argv[i] = strdup(argv0[i]);

    int error = load(filename, argc, argv);

    // Code below will be executed only if something in “load” goes wrong
    free(filename);

    for (size_t i = 0; i < argc; i++)
        free(argv[i]);

    free(argv);

    return seterror(geterror(error));
}

uint64_t sys_await(uint64_t * rsp, greg_t * regs) {
    char * buf = (char*) *(++rsp);
    int n = (int) *(++rsp);

    #ifdef DEBUG
        printf("AWAIT buf = %p n = %d\n", buf, n);
    #endif

    struct rusage usage; int wstatus;
    int pid = wait3(&wstatus, __WALL, &usage);

    if (pid == -1) return seterrno();

    pdata data = detach_child(pid);

    uint64_t user = millisecs(usage.ru_utime);
    uint64_t sys  = millisecs(usage.ru_stime);
    uint64_t real = timestamp() - data.timestamp;

    int written = snprintf(buf, n, "%d %ld %ld %ld '%s'", pid, user, sys, real, data.exitmsg);
    munmap(data.exitmsg, ERRLEN * sizeof(char));

    return written;
}

syscall_handler * systab[] = {
    [SYSR1]         sys_plan9_unimplemented,
    [_ERRSTR]       sys_plan9_deprecated,
    [BIND]          sys_plan9_unimplemented,
    [CHDIR]         sys_chdir,
    [CLOSE]         sys_close,
    [DUP]           sys_dup,
    [ALARM]         sys_plan9_unimplemented,
    [EXEC]          sys_exec,
    [EXITS]         sys_exits,
    [_FSESSION]     sys_plan9_deprecated,
    [FAUTH]         sys_plan9_unimplemented,
    [_FSTAT]        sys_plan9_deprecated,
    [SEGBRK]        sys_plan9_unimplemented,
    [MOUNT]         sys_plan9_unimplemented,
    [OPEN]          sys_open,
    [_READ]         sys_plan9_deprecated,
    [OSEEK]         sys_plan9_unimplemented,
    [SLEEP]         sys_sleep,
    [_STAT]         sys_plan9_deprecated,
    [RFORK]         sys_rfork,
    [_WRITE]        sys_plan9_deprecated,
    [PIPE]          sys_plan9_unimplemented,
    [CREATE]        sys_create,
    [FD2PATH]       sys_fd2path,
    [BRK_]          sys_brk,
    [REMOVE]        sys_remove,
    [_WSTAT]        sys_plan9_deprecated,
    [_FWSTAT]       sys_plan9_deprecated,
    [NOTIFY]        sys_plan9_unimplemented,
    [NOTED]         sys_plan9_unimplemented,
    [SEGATTACH]     sys_plan9_unimplemented,
    [SEGDETACH]     sys_plan9_unimplemented,
    [SEGFREE]       sys_plan9_unimplemented,
    [SEGFLUSH]      sys_plan9_unimplemented,
    [RENDEZVOUS]    sys_plan9_unimplemented,
    [UNMOUNT]       sys_plan9_unimplemented,
    [_WAIT]         sys_plan9_deprecated,
    [SEEK]          sys_seek,
    [FVERSION]      sys_plan9_unimplemented,
    [ERRSTR]        sys_errstr,
    [STAT]          sys_plan9_unimplemented,
    [FSTAT]         sys_plan9_unimplemented,
    [WSTAT]         sys_plan9_unimplemented,
    [FWSTAT]        sys_plan9_unimplemented,
    [PREAD]         sys_pread,
    [PWRITE]        sys_pwrite,
    [AWAIT]         sys_await,
};

static uint8_t selector = SYSCALL_DISPATCH_FILTER_ALLOW;

static void handle_sigsys(int sig, siginfo_t *info, void *ucontext) {
    ucontext_t *context = (ucontext_t *) ucontext;
    greg_t *regs = context->uc_mcontext.gregs;

    // Plan 9 (amd64) passes syscall number through RBP,
    // so “info->si_syscall” would contain garbage.
    uint64_t * rsp = (uint64_t*) regs[REG_RSP];
    uint8_t syscall = regs[REG_RBP];

    if (syscall > PWRITE || systab[syscall] == NULL)
        printf("P9: bad system call\n");
    else regs[REG_RAX] = systab[syscall](rsp, regs);
}

void sigsys(void) {
    struct sigaction act = {0};
    sigset_t mask; sigemptyset(&mask);

    act.sa_sigaction = handle_sigsys;
    act.sa_flags     = SA_SIGINFO;
    act.sa_mask      = mask;

    long ret = sigaction(SIGSYS, &act, NULL);
}

int init(void) {
    Elf64_Phdr *phdrs = (Elf64_Phdr *) getauxval(AT_PHDR);
    if (phdrs == NULL) {
        fprintf(stderr, "getauxval failed\n");
        return -1;
    }

    unsigned long e_phnum = getauxval(AT_PHNUM);
    if (e_phnum == 0) {
        fprintf(stderr, "getauxval failed\n");
        return -1;
    }

    // https://github.com/meme/limbo/blob/main/main.c
    for (uint32_t i = 0; i < e_phnum; i++) {
        Elf64_Phdr phdr = phdrs[i];

        if (phdr.p_type == PT_LOAD && phdr.p_flags & PF_X) {
            if (prctl(PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_ON, phdr.p_vaddr, phdr.p_memsz, &selector)) {
                fprintf(stderr, "Kernel does not support CONFIG_SYSCALL_USER_DISPATCH\n");
                return -1;
            }
        }
    }

    selector = SYSCALL_DISPATCH_FILTER_BLOCK;

    return 0;
}

int load(char * filename, int argc, char ** argv) {
    int fd = open(filename, O_RDONLY);
    if (fd == -1) return errno;

    header hdr; ssize_t readn = read(fd, &hdr, sizeof(header));
    if (readn != sizeof(header)) return errno;

    segment text, data = {0};

    hdr.magic    = be32toh(hdr.magic);
    hdr.text     = be32toh(hdr.text);
    hdr.data     = be32toh(hdr.data);
    hdr.bss      = be32toh(hdr.bss);
    hdr.syms     = be32toh(hdr.syms);
    hdr.reserved = be32toh(hdr.reserved);
    hdr.spsz     = be32toh(hdr.spsz);
    hdr.pcsz     = be32toh(hdr.pcsz);
    hdr.entry    = be64toh(hdr.entry);

    if (hdr.magic != S_MAGIC) return ENOEXEC;
    if (hdr.entry < UTZERO + sizeof(header)) return ENOEXEC;

    text.size = sizeof(header) + hdr.text;
    data.size = hdr.data + hdr.bss;

    uint32_t offset = (text.size / (ALIGN + 1) + 1) * (ALIGN + 1);

    nuke(); // Point of no return (any “return” below will result in crash, since it will eventually return to nowhere)

    // In case when “load” was called by “exec” (Plan 9’s) syscall, “handle_sigsys” will not return
    // and SIGSYS will stay blocked, so the next syscall, according to the behaviour of “sigaction”,
    // will cause the program to crash with SIGSYS; hence we have to unblock it manually.

    // https://man7.org/linux/man-pages/man2/sigprocmask.2.html
    // It is permissible to attempt to unblock a signal which is not blocked.
    sigset_t mask; sigemptyset(&mask); sigaddset(&mask, SIGSYS);
    sigprocmask(SIG_UNBLOCK, &mask, NULL);

    text.begin = mmap((char*) UTZERO, text.size, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_FIXED, fd, 0);
    data.begin = mmap((char*) UTZERO + offset, data.size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);

    swap(fd, text, data);

    if (text.begin == NULL || data.begin == NULL) exit(ENOMEM);

    lseek(fd, text.size, SEEK_SET);
    read(fd, data.begin, hdr.data);
    memset(data.begin + hdr.data, 0, hdr.bss);

    uint64_t * rsp; asm volatile("mov %%rsp, %0" : "=r"(rsp));
    rsp -= TOS_SIZE; uint64_t * tos = rsp;

    rsp -= argc + 1; *(--rsp) = argc;

    for (size_t i = 0; i < argc; i++)
        rsp[i + 1] = (uint64_t) argv[i];

    rsp[argc + 1] = 0;

    // FIXME: “argv” leaks here

    asm volatile(
        "mov %0, %%rax;"
        "mov %1, %%rsp;"
        "jmp *%2;"
        :: "r"(tos), "r"(rsp), "r"((void*) hdr.entry)
    );

    __builtin_unreachable();
}

int main(int argc, char * argv[]) {
    if (argc < 2) {
        printf("usage: %s [file] [option ...]\n", basename(argv[0]));
        return -EINVAL;
    }

    sigsys(); if (init()) return -1;
    return load(argv[1], argc - 1, argv + 1);
}