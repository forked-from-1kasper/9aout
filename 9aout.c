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
#include "syscall.h"

size_t data_size = 0; void *text, *data;

uint64_t sys_plan9_unimplemented(greg_t * regs)
{
    printf("P9: %lld called but unimplemented!\n", regs[REG_RBP]);
    return 0;
}

uint64_t sysexits(greg_t * regs)
{
    exit(0);
}

uint64_t syspread(greg_t * regs)
{
    uint64_t * rsp = (uint64_t*) regs[REG_RSP];

    int fd = (int) *(++rsp);
    void * buf = (void*) *(++rsp);
    size_t len = (size_t) *(++rsp);
    off_t offset = (off_t) *(++rsp);

    if (offset == -1) return read(fd, buf, len);
    else return pread(fd, buf, len, offset);
}

uint64_t syspwrite(greg_t * regs)
{
    uint64_t * rsp = (uint64_t*) regs[REG_RSP];

    int fd = (int) *(++rsp);
    void * buf = (void*) *(++rsp);
    size_t len = (size_t) *(++rsp);
    off_t offset = (off_t) *(++rsp);

    if (offset == -1) return write(fd, buf, len);
    else return pwrite(fd, buf, len, offset);
}

uint64_t sysbrk(greg_t * regs)
{
    uint64_t * rsp = (uint64_t*) regs[REG_RSP];
    void * addr = (void*) *(++rsp);

    size_t size = addr - data;
    data        = mremap(data, data_size, size, 0);
    data_size   = size;

    return (data == NULL) ? -1 : 0;
}

syscall_handler * systab[] = {
    [SYSR1]         sys_plan9_unimplemented,
    [_ERRSTR]       sys_plan9_unimplemented,
    [BIND]          sys_plan9_unimplemented,
    [CHDIR]         sys_plan9_unimplemented,
    [CLOSE]         sys_plan9_unimplemented,
    [DUP]           sys_plan9_unimplemented,
    [ALARM]         sys_plan9_unimplemented,
    [EXEC]          sys_plan9_unimplemented,
    [EXITS]         sysexits,
    [_FSESSION]     sys_plan9_unimplemented,
    [FAUTH]         sys_plan9_unimplemented,
    [_FSTAT]        sys_plan9_unimplemented,
    [SEGBRK]        sys_plan9_unimplemented,
    [MOUNT]         sys_plan9_unimplemented,
    [OPEN]          sys_plan9_unimplemented,
    [_READ]         sys_plan9_unimplemented,
    [OSEEK]         sys_plan9_unimplemented,
    [SLEEP]         sys_plan9_unimplemented,
    [_STAT]         sys_plan9_unimplemented,
    [RFORK]         sys_plan9_unimplemented,
    [_WRITE]        sys_plan9_unimplemented,
    [PIPE]          sys_plan9_unimplemented,
    [CREATE]        sys_plan9_unimplemented,
    [FD2PATH]       sys_plan9_unimplemented,
    [BRK_]          sysbrk,
    [REMOVE]        sys_plan9_unimplemented,
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
    [SEEK]          sys_plan9_unimplemented,
    [FVERSION]      sys_plan9_unimplemented,
    [ERRSTR]        sys_plan9_unimplemented,
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

    uint8_t syscall = regs[REG_RBP];

    if (syscall > PWRITE || systab[syscall] == NULL)
        printf("Bad system call\n");
    else regs[REG_RAX] = systab[syscall](regs);
}

int main(int argc, char * argv[]) {
    if (argc < 2) {
        printf("usage: %s [file] [option ...]\n", basename(argv[0]));
        return -EINVAL;
    }

    int fd = open(argv[1], O_RDONLY);
    aout header; read(fd, &header, sizeof(header));

    header.magic    = be32toh(header.magic);
    header.text     = be32toh(header.text);
    header.data     = be32toh(header.data);
    header.bss      = be32toh(header.bss);
    header.syms     = be32toh(header.syms);
    header.reserved = be32toh(header.reserved);
    header.spsz     = be32toh(header.spsz);
    header.pcsz     = be32toh(header.pcsz);
    header.entry    = be64toh(header.entry);

    if (header.magic != S_MAGIC) return -ENOEXEC;
    if (header.entry < UTZERO + sizeof(aout)) return -ENOEXEC;

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
        perror("getauxval failed\n");
        return 1;
    }

    // https://github.com/meme/limbo/blob/main/main.c
    for (uint32_t i = 0; i < e_phnum; i++) {
        Elf64_Phdr phdr = phdrs[i];

        if (phdr.p_type == PT_LOAD && phdr.p_flags & PF_X) {
            if (prctl(PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_ON, phdr.p_vaddr, phdr.p_memsz, &glob_sel)) {
                perror("Kernel does not support CONFIG_SYSCALL_USER_DISPATCH\n");
                return 1;
            }
        }
    }

    uint32_t text_size   = sizeof(aout) + header.text;
    uint32_t data_offset = (text_size / ALIGN + 1) * ALIGN + 1;

    data_size = header.data + header.bss;

    text = mmap((char*) UTZERO, text_size, PROT_READ | PROT_EXEC, MAP_SHARED | MAP_FIXED, fd, 0);
    data = mmap((char*) UTZERO + data_offset, data_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED, -1, 0);

    if (text == NULL || data == NULL) return -ENOMEM;

    lseek(fd, text_size, SEEK_SET); read(fd, data, header.data);
    memset(data + header.data + 1, 0, header.bss);

    uint64_t * rsp; asm volatile("mov %%rsp, %0" : "=r"(rsp));
    rsp -= TOS_SIZE; uint64_t * tos = rsp;

    argc--; argv++; rsp -= argc; *(--rsp) = argc;
    for (size_t i = 0; i < argc; i++) rsp[i + 1] = (uint64_t) argv[i];

    asm volatile("mov %0, %%rax" ::"r"(tos));
    asm volatile("mov %0, %%rsp" ::"r"(rsp));

    glob_sel = SYSCALL_DISPATCH_FILTER_BLOCK;
    asm volatile("jmp *%0" ::"r"((void*) header.entry));

    __builtin_unreachable();
}