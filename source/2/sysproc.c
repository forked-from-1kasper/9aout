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
#include <fcntl.h>
#include <errno.h>

#include <plan9/sysproc.h>
#include <namespace.h>
#include <a.out.h>

uint64_t sys_sleep(uint64_t * rsp, greg_t * regs) {
    uint32_t millisecs = (uint32_t) *(++rsp);

    #ifdef DEBUG
        printf("%s %d: sleep(%d)\n", self.name, self.pid, millisecs);
    #endif

    struct timespec time = {0};

    time.tv_sec = millisecs / 1000;
    time.tv_nsec = (millisecs % 1000) * 1e+6;

    return nanosleep(&time, NULL);
}

uint64_t sys_rfork(uint64_t * rsp, greg_t * regs) {
    int flags = (int) *(++rsp);

    #ifdef DEBUG
        printf("%s %d: rfork(flags = %d)\n", self.name, self.pid, flags);
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
    if (flags & RFNOWAIT) return seterror("RFNOWAIT not implemented.");
    if (flags & RFCNAMEG) return seterror("RFCNAMEG not implemented.");
    if (flags & RFCENVG)  return seterror("RFCENVG not implemented.");
    //if (flags & RFREND)   return seterror("RFREND not implemented.");
    if (flags & RFNOMNT)  return seterror("RFNOMNT not implemented.");

    struct clone_args params = {0};

    if (!(flags & RFFDG) && !(flags & RFCFDG))
        params.flags |= CLONE_FILES;

    params.exit_signal = SIGCHLD;

    if (flags & RFPROC) {
        char * exitmsg = mmap(NULL, ERRLEN * sizeof(char), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        memset(exitmsg, 0, ERRLEN * sizeof(char));

        if (!(flags & RFMEM)) memlock(&self.data);
        int pid = syscall(SYS_clone3, &params, sizeof(params));

        switch (pid) {
        case -1:
            seterrno(); munmap(exitmsg, ERRLEN * sizeof(char));
            if (!(flags & RFMEM)) memunlock(&self.data);
            break;

        case 0:
            self.pid = getpid();

            // https://man7.org/linux/man-pages/man2/prctl.2.html
            // The setting (PR_SET_SYSCALL_USER_DISPATCH) is not preserved
            // across fork(2), clone(2), or execve(2).
            sudinit();

            dropq(&self.wq); self.exitmsg = exitmsg;

            if (!(flags & RFMEM)) {
                int memfd = self.data.memfd; int errmem = memnewfd(&self.data);
                if (errmem) { memunlock(&self.data); panic("sys: %s", geterror(errmem)); }

                // Don’t know whether it really performs copy-on-write with
                // memfd_create fd’s, but documentation says something about it.
                // Anyway, it looks faster than just naive “memcpy”
                // and typical Plan 9 program is relatively small.
                // https://man7.org/linux/man-pages/man2/copy_file_range.2.html
                // copy_file_range() gives filesystems an opportunity to implement
                // "copy acceleration" techniques, such as the use of reflinks
                // (i.e., two or more inodes that share pointers to the same copy-
                // on-write disk blocks) or server-side-copy (in the case of NFS).
                off64_t offin = 0, offout = 0;
                ssize_t nbytes = copy_file_range(memfd, &offin, self.data.memfd, &offout, self.data.size, 0);

                memunlock(&self.data);

                if (nbytes == -1) panic("sys: %s", geterror(errno));

                if (errmem = memnewmutex(&self.data)) panic("sys: %s", geterror(errmem));
                if (errmem = memnewmap(&self.data))   panic("sys: %s", geterror(errmem));
            }

            if (flags & RFCFDG) {
                close_range(0L, self.data.memfd - 1L, 0);
                close_range(self.data.memfd + 1L, -1L, 0);
            }

            break;

        default:
            if (!(flags & RFMEM)) memwait(&self.data);
            insertq(&self.wq, pid, exitmsg); break;
        }

        return pid;
    } else return 0;
}

// TODO: NULL tests for calloc’s everywhere
int shargs(char * begin, char * end, int argc, char *** argv) {
    int n = 0; char * curr = begin + 2; // ignore shebang itself

    for (;;) {
        while (curr < end && (*curr == ' ' || *curr == '\t')) curr++;
        if (*curr == '\n') break; n++;

        while (curr < end && *curr != ' ' && *curr != '\t' && *curr != '\n') curr++;
        if (*curr == '\n') break;
    }

    *argv = calloc(argc + n + 1, sizeof(char*));

    curr = begin + 2;

    for (size_t i = 0;; i++) {
        while (curr < end && (*curr == ' ' || *curr == '\t')) curr++;
        if (*curr == '\n') break;

        char * offset = curr;

        while (curr < end && *curr != ' ' && *curr != '\t' && *curr != '\n') curr++;

        size_t length = curr - offset;

        *argv[i] = calloc(length + 1, sizeof(char*));
        strncpy(*argv[i], offset, length); (*argv + i)[length] = '\0';

        if (*curr == '\n') break;
    }

    return n;
}

uint64_t shebang(int fd, int argc, char ** argv0) {
    int error = 0;

    off_t size = lseek(fd, 0, SEEK_END);
    if (size == -1) { close(fd); error = errno; goto error; }

    char * text = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);

    if (text == NULL) return seterrno();

    char ** argv; int n = shargs(text, text + size, argc, &argv);
    if (n == -1) return seterrno();

    for (size_t i = 0; i < argc; i++)
        argv[n + i] = strdup(argv0[i]);

    argv[n + argc] = NULL;

    munmap(text, size); close(fd);

    int newfd = open(argv[0], O_RDONLY);
    if (fd == -1) { error = errno; goto error; }

    error = loadaout(newfd, n + argc, argv);

error:
    for (size_t i = 0; i < n + argc; i++)
        free(argv[i]);

    free(argv);

    return seterror(geterror(error));
}

uint64_t sys_exec(uint64_t * rsp, greg_t * regs) {
    char *  filename0 = (char*)  *(++rsp);
    char ** argv0     = (char**) *(++rsp);

    if (argv0 == NULL || *argv0 == NULL) return seterror(Ebadarg);
    int argc = 0; for (; argv0[argc] != NULL; argc++);

    #ifdef DEBUG
        printf("%s %d: exec(filename = %s, argc = %d)\n", self.name, self.pid, filename0, argc);
    #endif

    int fd = open(filename0, O_RDONLY);
    if (fd == -1) return seterrno();

    char buf[2] = {0}; if (read(fd, &buf, 2) != 2) return seterrno();

    if (buf[0] == '#' && buf[1] == '!')
        return shebang(fd, argc, argv0);

    lseek(fd, 0, SEEK_SET);

    // When filename/argv will be used in the new code, current code will
    // already be unloaded, as well as data segment, so we need to copy them
    char * filename = strdup(filename0);
    char ** argv = calloc(argc + 1, sizeof(char*));

    for (size_t i = 0; i < argc; i++)
        argv[i] = strdup(argv0[i]);

    argv[argc] = NULL;

    int error = loadaout(fd, argc, argv);

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
        printf("%s %d: await(buf = %p, n = %d)\n", self.name, self.pid, buf, n);
    #endif

    struct rusage usage; int wstatus;
    int pid = wait3(&wstatus, __WALL, &usage);

    if (pid == -1) return seterrno();

    Waitmsg msg = awaitq(&self.wq, pid);

    uint64_t user = millisecs(usage.ru_utime);
    uint64_t sys  = millisecs(usage.ru_stime);
    uint64_t real = timestamp() - msg.timestamp;

    // TODO: quote “'” to “''”
    int written = snprintf(buf, n, "%d %ld %ld %ld '%.*s'", pid, user, sys, real, ERRLEN, msg.exitmsg);
    munmap(msg.exitmsg, ERRLEN * sizeof(char));

    return written;
}

uint64_t sys_exits(uint64_t * rsp, greg_t * regs) {
    char * buf = (char*) *(++rsp);

    #ifdef DEBUG
        if (buf != NULL) printf("%s %d: exits(buf = %.*s)\n", self.name, self.pid, ERRLEN, buf);
        else printf("%s %d: exits(NULL)\n", self.name, self.pid);
    #endif

    int exitcode = (buf == NULL || buf[0] == '\0') ? EXIT_SUCCESS : EXIT_FAILURE;

    if (self.exitmsg && buf) strncpy(self.exitmsg, buf, ERRLEN);

    dropq(&self.wq); nuke(); exit(exitcode);
}

uint64_t sys_brk(uint64_t * rsp, greg_t * regs) {
    void * addr = (void*) *(++rsp);

    #ifdef DEBUG
        printf("%s %d: brk(addr = %p)\n", self.name, self.pid, addr);
    #endif

    memlock(&self.data);

    size_t newsize = addr - self.data.begin;
    ftruncate(self.data.memfd, newsize);

    void * ptr = mremap(self.data.begin, self.data.size, newsize, 0);
    if (ptr != MAP_FAILED) self.data.size = newsize;

    memunlock(&self.data);

    return (ptr == MAP_FAILED) ? seterrno() : 0;
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
    char * msg = (char*)   *(++rsp);
    size_t len = (uint32_t) *(++rsp);

    #ifdef DEBUG
        printf("%s %d: errstr(msg = %.*s, len = %lu)\n", self.name, self.pid, (uint32_t) len, msg, len);
    #endif

    return generrstr(msg, len);
}