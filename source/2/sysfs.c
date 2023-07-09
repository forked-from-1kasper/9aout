#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

#include <plan9/sysfs.h>
#include <error.h>

static int plan9mode(int32_t mode) {
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

static int modechk(char * file, int32_t mode) {
    if ((mode & 0x11) == OEXEC)
        if (access(file, X_OK))
            return seterror(Eperm);

    if (mode & ORCLOSE) unlink(file);

    return 0;
}

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

uint64_t sys_fd2path(uint64_t * rsp, greg_t * regs) {
    int fd = (int) *(++rsp);
    char * buf = (char*) *(++rsp);
    size_t nbuf = (size_t) *(++rsp);

    char filename[255] = {0};
    sprintf(filename, "/proc/self/fd/%d", fd);
    readlink(filename, buf, nbuf);

    return 0;
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