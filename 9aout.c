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
#include <elf.h>

#include "9aout.h"
#include "errstr.h"
#include "syscall.h"

char errstr[ERRMAX];

int fd; segment text, data = {0};

uint64_t sys_plan9_unimplemented(uint64_t * rsp, greg_t * regs)
{
    #ifdef DEBUG
        printf("P9: %lld called but unimplemented!\n", regs[REG_RBP]);
    #endif

    return 0;
}

uint64_t sysexits(uint64_t * rsp, greg_t * regs)
{
    char * buf = (char*) *(++rsp);

    #ifdef DEBUG
        if (buf != NULL) printf("exits: %s\n", buf);
    #endif

    int exitcode = (buf == NULL || buf[0] == '\0') ? 0 : -1;

    munmap(text.begin, text.size);
    munmap(data.begin, data.size);
    close(fd);

    exit(exitcode);
}

uint64_t syspread(uint64_t * rsp, greg_t * regs)
{
    int fd = (int) *(++rsp);
    void * buf = (void*) *(++rsp);
    size_t len = (uint32_t) *(++rsp);
    off_t offset = (uint64_t) *(++rsp);

    return (offset == -1) ? read(fd, buf, len) : pread(fd, buf, len, offset);
}

uint64_t syspwrite(uint64_t * rsp, greg_t * regs)
{
    int fd = (int) *(++rsp);
    void * buf = (void*) *(++rsp);
    size_t len = (uint32_t) *(++rsp);
    off_t offset = (uint64_t) *(++rsp);

    return (offset == -1) ? write(fd, buf, len) : pwrite(fd, buf, len, offset);
}

uint64_t sysbrk(uint64_t * rsp, greg_t * regs)
{
    void * addr = (void*) *(++rsp);

    size_t size = addr - data.begin;
    void * ptr  = mremap(data.begin, data.size, size, 0);

    if (ptr == MAP_FAILED) return -1;

    data.size = size; data.begin = ptr; return 0;
}

uint64_t seterror(char * err)
{
    strncpy(errstr, err, ERRMAX);
    return -1;
}

uint64_t sysopen(uint64_t * rsp, greg_t * regs)
{
    char * file = (char*) *(++rsp);
    uint64_t omode = (uint32_t) *(++rsp);

    int fd = open(file, omode);

    if (fd != -1) return fd;

    switch (errno) {
        case EACCES:       return seterror(Eperm);
        case EEXIST:       return seterror(Eexist);
        case ENOENT:       return seterror(Enonexist);
        case ENAMETOOLONG: return seterror(Efilename);
        case ENFILE:       return seterror(Enofd);
        default:           return seterror(strerror(errno));
    }
}

uint64_t sysclose(uint64_t * rsp, greg_t * regs)
{
    int fd = (int) *(++rsp);
    int retval = close(fd);

    switch (errno) {
        case EBADF:  return seterror(Edabf);
        case EINTR:  return seterror(Eintr);
        case EIO:    return seterror(Eio);
        case ENOSPC: return seterror(Enospc);
        case EDQUOT: return seterror(Edquot);
        default:     return retval;
    }
}

uint64_t sysseek(uint64_t * rsp, greg_t * regs)
{
    off_t * retp = (off_t*) *(++rsp);

    int fd = (int) *(++rsp);

    off_t offset = (uint64_t) *(++rsp);
    int type = (int) *(++rsp);

    int whence = 0;
    switch (type) {
        case 0:  whence = SEEK_SET; break;
        case 1:  whence = SEEK_CUR; break;
        case 2:  whence = SEEK_END; break;
        default: seterror(Ebadarg); return 0;
    }

    *retp = lseek(fd, offset, whence);
    return 0;
}

uint64_t syscreate(uint64_t * rsp, greg_t * regs)
{
    char * file = (char*) *(++rsp);
    uint64_t omode = (uint32_t) *(++rsp);
    mode_t perm = (uint32_t) *(++rsp);

    return open(file, omode | O_CREAT, perm);
}

uint64_t sysremove(uint64_t * rsp, greg_t * regs)
{
    char * file = (char*) *(++rsp);
    return unlink(file);
}

uint64_t sysfd2path(uint64_t * rsp, greg_t * regs)
{
    int fd = (int) *(++rsp);
    char * buf = (char*) *(++rsp);
    size_t nbuf = (size_t) *(++rsp);

    char filename[255] = {0};
    sprintf(filename, "/proc/self/fd/%d", fd);
    readlink(filename, buf, nbuf);

    return 0;
}

uint64_t generrstr(char *msg, size_t nbuf)
{
    char buf[ERRMAX]; if (nbuf == 0) return 0;
    if (nbuf > ERRMAX) nbuf = ERRMAX;

    strncpy(buf, msg, nbuf);
    strncpy(msg, errstr, nbuf);
    strncpy(errstr, buf, nbuf);

    return 0;
}

uint64_t syserrstr(uint64_t * rsp, greg_t * regs)
{
    char * msg = (char*) *(++rsp);
    size_t len = (uint32_t) *(++rsp);

    return generrstr(msg, len);
}

uint64_t sys_errstr(uint64_t * rsp, greg_t * regs)
{
    return generrstr((char*) *(++rsp), 64);
}

syscall_handler * systab[] = {
    [SYSR1]         sys_plan9_unimplemented,
    [_ERRSTR]       sys_errstr,
    [BIND]          sys_plan9_unimplemented,
    [CHDIR]         sys_plan9_unimplemented,
    [CLOSE]         sysclose,
    [DUP]           sys_plan9_unimplemented,
    [ALARM]         sys_plan9_unimplemented,
    [EXEC]          sys_plan9_unimplemented,
    [EXITS]         sysexits,
    [_FSESSION]     sys_plan9_unimplemented,
    [FAUTH]         sys_plan9_unimplemented,
    [_FSTAT]        sys_plan9_unimplemented,
    [SEGBRK]        sys_plan9_unimplemented,
    [MOUNT]         sys_plan9_unimplemented,
    [OPEN]          sysopen,
    [_READ]         sys_plan9_unimplemented,
    [OSEEK]         sys_plan9_unimplemented,
    [SLEEP]         sys_plan9_unimplemented,
    [_STAT]         sys_plan9_unimplemented,
    [RFORK]         sys_plan9_unimplemented,
    [_WRITE]        sys_plan9_unimplemented,
    [PIPE]          sys_plan9_unimplemented,
    [CREATE]        syscreate,
    [FD2PATH]       sysfd2path,
    [BRK_]          sysbrk,
    [REMOVE]        sysremove,
    [_WSTAT]        sys_plan9_unimplemented,
    [_FWSTAT]       sys_plan9_unimplemented,
    [NOTIFY]        sys_plan9_unimplemented,
    [NOTED]         sys_plan9_unimplemented,
    [SEGATTACH]     sys_plan9_unimplemented,
    [SEGDETACH]     sys_plan9_unimplemented,
    [SEGFREE]       sys_plan9_unimplemented,
    [SEGFLUSH]      sys_plan9_unimplemented,
    [RENDEZVOUS]    sys_plan9_unimplemented,
    [UNMOUNT]       sys_plan9_unimplemented,
    [_WAIT]         sys_plan9_unimplemented,
    [SEEK]          sysseek,
    [FVERSION]      sys_plan9_unimplemented,
    [ERRSTR]        syserrstr,
    [STAT]          sys_plan9_unimplemented,
    [FSTAT]         sys_plan9_unimplemented,
    [WSTAT]         sys_plan9_unimplemented,
    [FWSTAT]        sys_plan9_unimplemented,
    [PREAD]         syspread,
    [PWRITE]        syspwrite,
    [AWAIT]         sys_plan9_unimplemented,
};

static uint8_t glob_sel = SYSCALL_DISPATCH_FILTER_ALLOW;

static void handle_sigsys(int sig, siginfo_t *info, void *ucontext)
{
    ucontext_t *context = (ucontext_t *) ucontext;
    greg_t *regs = context->uc_mcontext.gregs;

    uint64_t * rsp = (uint64_t*) regs[REG_RSP];
    uint8_t syscall = regs[REG_RBP];

    if (syscall > PWRITE || systab[syscall] == NULL)
        printf("Bad system call\n");
    else regs[REG_RAX] = systab[syscall](rsp, regs);
}

int main(int argc, char * argv[]) {
    if (argc < 2) {
        printf("usage: %s [file] [option ...]\n", basename(argv[0]));
        return -EINVAL;
    }

    fd = open(argv[1], O_RDONLY);
    header hdr; read(fd, &hdr, sizeof(header));

    hdr.magic    = be32toh(hdr.magic);
    hdr.text     = be32toh(hdr.text);
    hdr.data     = be32toh(hdr.data);
    hdr.bss      = be32toh(hdr.bss);
    hdr.syms     = be32toh(hdr.syms);
    hdr.reserved = be32toh(hdr.reserved);
    hdr.spsz     = be32toh(hdr.spsz);
    hdr.pcsz     = be32toh(hdr.pcsz);
    hdr.entry    = be64toh(hdr.entry);

    if (hdr.magic != S_MAGIC) return -ENOEXEC;
    if (hdr.entry < UTZERO + sizeof(header)) return -ENOEXEC;

    int si_code, si_errno; long ret;
    struct sigaction act; sigset_t mask;

    glob_sel = 0;
    si_code  = 0;
    si_errno = 0;

    memset(&act, 0, sizeof(act));
    sigemptyset(&mask);

    act.sa_sigaction = handle_sigsys;
    act.sa_flags     = SA_SIGINFO;
    act.sa_mask      = mask;

    ret = sigaction(SIGSYS, &act, NULL);

    Elf64_Phdr *phdrs = (Elf64_Phdr *) getauxval(AT_PHDR);
    if (phdrs == NULL) {
        printf("getauxval failed\n");
        return 1;
    }

    unsigned long e_phnum = getauxval(AT_PHNUM);
    if (e_phnum == 0) {
        fprintf(stderr, "getauxval failed\n");
        return 1;
    }

    // https://github.com/meme/limbo/blob/main/main.c
    for (uint32_t i = 0; i < e_phnum; i++) {
        Elf64_Phdr phdr = phdrs[i];

        if (phdr.p_type == PT_LOAD && phdr.p_flags & PF_X) {
            if (prctl(PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_ON, phdr.p_vaddr, phdr.p_memsz, &glob_sel)) {
                fprintf(stderr, "Kernel does not support CONFIG_SYSCALL_USER_DISPATCH\n");
                return 1;
            }
        }
    }

    text.size = sizeof(header) + hdr.text;
    data.size = hdr.data + hdr.bss;

    uint32_t offset = (text.size / (ALIGN + 1) + 1) * (ALIGN + 1);

    text.begin = mmap((char*) UTZERO, text.size, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_FIXED, fd, 0);
    data.begin = mmap((char*) UTZERO + offset, data.size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);

    if (text.begin == NULL || data.begin == NULL) return -ENOMEM;

    lseek(fd, text.size, SEEK_SET); read(fd, data.begin, hdr.data);
    memset(data.begin + hdr.data, 0, hdr.bss);

    uint64_t * rsp; asm volatile("mov %%rsp, %0" : "=r"(rsp));
    rsp -= TOS_SIZE; uint64_t * tos = rsp;

    argc--; argv++; rsp -= argc; *(--rsp) = argc;
    for (size_t i = 0; i < argc; i++) rsp[i + 1] = (uint64_t) argv[i];

    glob_sel = SYSCALL_DISPATCH_FILTER_BLOCK;

    asm volatile(
        "mov %0, %%rax;"
        "mov %1, %%rsp;"
        "jmp *%2;"
        :: "r"(tos), "r"(rsp), "r"((void*) hdr.entry)
    );

    __builtin_unreachable();
}