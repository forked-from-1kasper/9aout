#define _GNU_SOURCE

#include <stdio.h>

#include <sys/prctl.h>
#include <sys/auxv.h>
#include <sys/mman.h>

#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <link.h>

#include <bootstrap.h>
#include <namespace.h>
#include <a.out.h>
#include <error.h>

#ifndef PR_SET_SYSCALL_USER_DISPATCH
    #error "PR_SET_SYSCALL_USER_DISPATCH is not defined. Make sure you are using Linux 5.11 or later."
#endif

#define MIN(x, y) (((x) < (y)) ? (x) : (y))
#define MAX(x, y) (((x) > (y)) ? (x) : (y))

// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/x86/include/asm/trap_pf.h
enum x86_pf_error_code {
    X86_PF_PROT  = 1 << 0,
    X86_PF_WRITE = 1 << 1,
    X86_PF_USER  = 1 << 2,
    X86_PF_RSVD  = 1 << 3,
    X86_PF_INSTR = 1 << 4,
    X86_PF_PK    = 1 << 5,
    X86_PF_SGX   = 1 << 15,
};

Conf config;

void revertconf(Conf * c) {
    c->sudselector  = SYSCALL_DISPATCH_FILTER_ALLOW;
    c->execfallback = 0;
}

void sigsegv(int sig, siginfo_t * info, void * ucontext) {
    ucontext_t * context = (ucontext_t *) ucontext;
    greg_t       regerr  = context->uc_mcontext.gregs[REG_ERR];
    void *       regpc   = (void*) context->uc_mcontext.gregs[REG_RIP];

    void * addr = info->si_addr;
    off_t  size = lseek(self.data.memfd, 0, SEEK_END);

    // If shared memory is out of sync
    if (self.data.begin + self.data.size <= addr && addr < self.data.begin + size) {
        if (mremap(self.data.begin, self.data.size, size, 0) == MAP_FAILED)
            panic("sys: trap: %s pc=%p", geterror(errno), regpc);

        self.data.size = size; return;
    }

    panic("sys: trap: fault %s addr=%p pc=%p", regerr & X86_PF_WRITE ? "write" : "read", addr, regpc);
}

int siginit(sighandler sudfunc) {
    struct sigaction act = {0};
    sigset_t mask; sigemptyset(&mask);

    act.sa_sigaction = sudfunc;
    act.sa_flags     = SA_SIGINFO;
    act.sa_mask      = mask;

    if (sigaction(SIGSYS, &act, NULL)) return errno;

    act.sa_sigaction = sigsegv;
    act.sa_flags     = SA_SIGINFO;

    if (sigaction(SIGSEGV, &act, NULL)) return errno;

    return 0;
}

static Region region;

static int lookphdr(struct dl_phdr_info * info, size_t size, void * data) {
    for (size_t i = 0; i < info->dlpi_phnum; i++) {
        Elf64_Phdr phdr = info->dlpi_phdr[i];

        if (phdr.p_flags & PF_X) {
            uint64_t addr = info->dlpi_addr + phdr.p_vaddr;

            region.begin = MIN(region.begin, addr);
            region.end   = MAX(region.end,   addr + phdr.p_memsz);
        }
    }

    return 0;
}

int elfinit(void) {
    region.begin = -1L; region.end = +0L;
    return dl_iterate_phdr(lookphdr, NULL);
}

int sudinit(void) {
    // https://github.com/torvalds/linux/blob/master/kernel/entry/syscall_user_dispatch.c
    // It looks like that there can be *only one* [offset; offset + len) region per thread,
    // so we select one (very) large region containing everything (program text + all dynamic libraries).

    // also look at https://github.com/meme/limbo

    if (prctl(PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_ON, region.begin, region.end - region.begin, &config.sudselector)) {
        fprintf(stderr, "Kernel does not support CONFIG_SYSCALL_USER_DISPATCH\n");
        return -1;
    }

    config.sudselector = SYSCALL_DISPATCH_FILTER_BLOCK; return 0;
}

// “loadaout” assumes that “argv” is null-terminated
int loadaout(int fd, int argc, char ** argv) {
    header hdr; ssize_t readn = read(fd, &hdr, sizeof(header));
    if (readn != sizeof(header)) return errno;

    hdr.magic    = be32toh(hdr.magic);
    hdr.text     = be32toh(hdr.text);
    hdr.data     = be32toh(hdr.data);
    hdr.bss      = be32toh(hdr.bss);
    hdr.syms     = be32toh(hdr.syms);
    hdr.reserved = be32toh(hdr.reserved);
    hdr.spsz     = be32toh(hdr.spsz);
    hdr.pcsz     = be32toh(hdr.pcsz);
    hdr.entry    = be64toh(hdr.entry);

    if (hdr.magic != S_MAGIC || hdr.entry < UTZERO + sizeof(header)) {
        if (config.execfallback) { execvp(argv[0], argv); return errno; }
        else return ENOEXEC;
    }

    nuke(); // Point of no return (any “return” below will result in crash, since it will eventually return to nowhere)

    self.text.size = sizeof(header) + hdr.text;
    self.data.size = hdr.data + hdr.bss;

    uint32_t offset = (self.text.size / ALIGN1 + 1) * ALIGN1;

    // In case when “load” was called by “exec” (Plan 9’s) syscall, “handle_sigsys” will not return
    // and SIGSYS will stay blocked, so the next syscall, according to the behaviour of “sigaction”,
    // will cause the program to crash with SIGSYS; hence we have to unblock it manually. Also:
    // https://man7.org/linux/man-pages/man2/sigprocmask.2.html
    // It is permissible to attempt to unblock a signal which is not blocked.
    sigset_t mask; sigemptyset(&mask); sigaddset(&mask, SIGSYS);
    sigprocmask(SIG_UNBLOCK, &mask, NULL);

    if (self.name) free(self.name); char * copy = strdup(argv[0]);
    self.name = strdup(basename(copy)); free(copy);

    self.text.begin = mmap((char*) UTZERO, self.text.size, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_FIXED, fd, 0);
    if (self.text.begin == MAP_FAILED) panic("sys: %s", geterror(errno));

    self.data.begin = (void*) (UTZERO + offset);

    int errmem = 0;

    if (errmem = memnewfd(&self.data))    panic("sys: %s", geterror(errmem));
    if (errmem = memnewmutex(&self.data)) panic("sys: %s", geterror(errmem));
    if (errmem = memnewmap(&self.data))   panic("sys: %s", geterror(errmem));

    lseek(fd, self.text.size, SEEK_SET);
    read(fd, self.data.begin, hdr.data);
    memset(self.data.begin + hdr.data, 0, hdr.bss);

    close(fd);

    uint64_t * rsp; asm volatile("mov %%rsp, %0" : "=r"(rsp));
    rsp -= TOS_SIZE; uint64_t * tos = rsp;

    rsp -= argc; *(--rsp) = argc;

    for (size_t i = 0; i <= argc; i++)
        rsp[i + 1] = (uint64_t) argv[i];

    // FIXME: “argv” leaks here

    asm volatile(
        "mov %0, %%rax;"
        "mov %1, %%rsp;"
        "jmp *%2;"
        :: "r"(tos), "r"(rsp), "r"((void*) hdr.entry)
    );

    __builtin_unreachable();
}