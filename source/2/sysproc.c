#define _GNU_SOURCE

#include <sys/resource.h>
#include <sys/syscall.h>
#include <linux/sched.h>
#include <sys/mman.h>
#include <sys/wait.h>

#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <error.h>
#include <stdio.h>

#include <plan9/sysproc.h>
#include <shared.h>

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
    //if (flags & RFREND)   return seterror("RFREND not implemented.");
    if (flags & RFNOMNT)  return seterror("RFNOMNT not implemented.");

    struct clone_args params = {0};

    if (!(flags & RFFDG) && !(flags & RFCFDG))
        params.flags |= CLONE_FILES;

    params.exit_signal = SIGCHLD;

    char * cexitmsg = NULL;

    if (flags & RFPROC) {
        cexitmsg = mmap(NULL, ERRLEN * sizeof(char), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        memset(cexitmsg, 0, ERRLEN * sizeof(char));
    }

    int pid = syscall(SYS_clone3, &params, sizeof(params));

    if (flags & RFPROC) {
        if (pid == 0) {
            // https://man7.org/linux/man-pages/man2/prctl.2.html
            // The setting (PR_SET_SYSCALL_USER_DISPATCH) is not preserved
            // across fork(2), clone(2), or execve(2).
            init();

            detach_everything(); exitmsg = cexitmsg;
            if (flags & RFCFDG) close_range(0L, -1L, 0);
        }
        else attach_child(pid, cexitmsg);
    }

    return pid;
}

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

    // TODO: quote “'” to “''”
    int written = snprintf(buf, n, "%d %ld %ld %ld '%s'", pid, user, sys, real, data.exitmsg);
    munmap(data.exitmsg, ERRLEN * sizeof(char));

    return written;
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

uint64_t sys_brk(uint64_t * rsp, greg_t * regs) {
    void * addr = (void*) *(++rsp);

    size_t size = addr - _data.begin;
    void * ptr  = mremap(_data.begin, _data.size, size, 0);

    if (ptr == MAP_FAILED) return -1;

    _data.size = size; _data.begin = ptr; return 0;
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