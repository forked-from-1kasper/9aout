#define _GNU_SOURCE

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>

#include <bootstrap.h>
#include <namespace.h>
#include <error.h>
#include <a.out.h>

#include <plan9/sysproc.h>
#include <plan9/syscall.h>
#include <plan9/common.h>
#include <plan9/sysfs.h>

syscall_handler * systab[] = {
    [SYSR1]         sysr1,
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
    [STAT]          sys_stat,
    [FSTAT]         sys_fstat,
    [WSTAT]         sys_plan9_unimplemented,
    [FWSTAT]        sys_plan9_unimplemented,
    [PREAD]         sys_pread,
    [PWRITE]        sys_pwrite,
    [AWAIT]         sys_await,
};

void handle_sigsys(int sig, siginfo_t * info, void * ucontext) {
    ucontext_t * context = (ucontext_t *) ucontext;
    greg_t *regs = context->uc_mcontext.gregs;

    // Plan 9 (amd64) passes syscall number through RBP,
    // so “info->si_syscall” would contain garbage.
    uint64_t * rsp = (uint64_t*) regs[REG_RSP];
    uint8_t syscall = regs[REG_RBP];

    if (syscall > PWRITE || systab[syscall] == NULL)
        printf("P9: bad system call\n");
    else regs[REG_RAX] = systab[syscall](rsp, regs);
}

int main(int argc, char * argv[]) {
    if (argc < 2) {
        printf("usage: %s [file] [option ...]\n", basename(argv[0]));
        return -EINVAL;
    }

    int fd = open(argv[1], O_RDONLY);
    if (fd == -1) return errno;

    if (sigsys(handle_sigsys)) return -1;
    if (elfinit()) return -1;
    if (sudinit()) return -1;

    return loadaout(fd, argc - 1, argv + 1);
}