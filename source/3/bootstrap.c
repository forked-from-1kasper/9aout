
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

#include <bootstrap.h>
#include <shared.h>
#include <aout.h>

static uint8_t selector = SYSCALL_DISPATCH_FILTER_ALLOW;

int sigsys(sighandler func) {
    struct sigaction act = {0};
    sigset_t mask; sigemptyset(&mask);

    act.sa_sigaction = func;
    act.sa_flags     = SA_SIGINFO;
    act.sa_mask      = mask;

    return sigaction(SIGSYS, &act, NULL);
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