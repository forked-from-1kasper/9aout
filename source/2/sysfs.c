#include <linux/limits.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <unistd.h>
#include <string.h>
#include <libgen.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <pwd.h>
#include <grp.h>

#include <plan9/sysfs.h>
#include <error.h>

#define htole8(x) (x)

static int plan9mode(int32_t mode) {
    int retval = 0;

    switch (mode & 0b11) {
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
    if ((mode & 0b11) == OEXEC)
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

int fd2path(int fd, char * buf, size_t nbuf) {
    char linkname[26] = {0};

    sprintf(linkname, "/proc/self/fd/%d", fd);
    return readlink(linkname, buf, nbuf);
}

uint64_t sys_fd2path(uint64_t * rsp, greg_t * regs) {
    int fd = (int) *(++rsp);
    char * buf = (char*) *(++rsp);
    size_t nbuf = (size_t) *(++rsp);

    if (fd2path(fd, buf, nbuf) == -1)
        return seterrno();
    else return 0;
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
    char * filepath = (char*) *(++rsp);

    #ifdef DEBUG
        printf("CHDIR filepath = %s\n", filepath);
    #endif

    return (chdir(filepath) != -1) ? 0 : seterrno();
}

typedef struct Qid Qid;

struct Qid {
    uint8_t  type;
    uint32_t vers;
    uint64_t path;
} __attribute__((__packed__));

typedef struct Stat Stat;

struct Stat {
    uint16_t type;
    uint32_t dev;
    Qid      qid;
    uint32_t mode;
    uint32_t atime;
    uint32_t mtime;
    uint64_t length;
} __attribute__((__packed__));

void plan9stat(const struct stat * inbuf, Stat * outbuf) {
    outbuf->type     = 'M';
    outbuf->dev      = 0;
    outbuf->qid.type = 0;
    outbuf->qid.vers = inbuf->st_mtime + inbuf->st_ctime;
    outbuf->qid.path = inbuf->st_ino;
    outbuf->mode     = inbuf->st_mode & 0777;
    outbuf->atime    = inbuf->st_atime;
    outbuf->mtime    = inbuf->st_mtime;
    outbuf->length   = inbuf->st_size;

    if (S_ISDIR(inbuf->st_mode)) { outbuf->length = 0; outbuf->mode |= DMDIR; outbuf->qid.type = QTDIR; }
}

char * write16(char * chan, uint16_t value)
{ *((uint16_t*) chan) = htole16(value); return chan + sizeof(uint16_t); }

char * writenstr(char * chan, const char * buf, size_t len) {
    chan = write16(chan, len);
    if (buf) strncpy(chan, buf, len);
    return chan + len;
}

char * writestat(char * chan, Stat * inbuf) {
    Stat * outbuf = (Stat*) chan;

    outbuf->type     = htole16(inbuf->type);
    outbuf->dev      = htole32(inbuf->dev);
    outbuf->qid.type = htole8(inbuf->qid.type);
    outbuf->qid.vers = htole32(inbuf->qid.vers);
    outbuf->qid.path = htole64(inbuf->qid.path);
    outbuf->mode     = htole32(inbuf->mode);
    outbuf->atime    = htole32(inbuf->atime);
    outbuf->mtime    = htole32(inbuf->mtime);
    outbuf->length   = htole64(inbuf->length);

    return chan + sizeof(Stat);
}

int rstat(char * filename, struct stat * buf, char * edir, int nedir) {
    Stat stat; plan9stat(buf, &stat);

    struct passwd * pw = getpwuid(buf->st_uid);
    if (pw == NULL) return seterrno();

    struct group * gr = getgrgid(buf->st_gid);
    if (gr == NULL) return seterrno();

    size_t nfilename = strlen(filename);
    size_t npw       = strlen(pw->pw_name);
    size_t ngr       = strlen(gr->gr_name);

    uint16_t size = sizeof(Stat)
                  + (sizeof(uint16_t) + nfilename)
                  + (sizeof(uint16_t) + npw)
                  + (sizeof(uint16_t) + ngr)
                  + (sizeof(uint16_t) + 0);

    if (nedir < BIT16SZ) return 0;
    if (nedir < size) { write16(edir, size); return BIT16SZ; }

    edir = write16(edir, size);
    edir = writestat(edir, &stat);
    edir = writenstr(edir, filename, nfilename);
    edir = writenstr(edir, pw->pw_name, npw);
    edir = writenstr(edir, gr->gr_name, ngr);
    edir = writenstr(edir, NULL, 0);

    return sizeof(uint16_t) + size;
}

uint64_t sys_stat(uint64_t * rsp, greg_t * regs) {
    char * filepath = (char*) *(++rsp);
    char * edir = (char*) *(++rsp);
    int nedir = (int) *(++rsp);

    #ifdef DEBUG
        printf("STAT filepath = %s edir = %p nedir = %d\n", filepath, edir, nedir);
    #endif

    struct stat sbuf = {0}; char buf[PATH_MAX + 1];

    if (stat(filepath, &sbuf)) return seterrno();
    if (realpath(filepath, buf) == NULL) return seterrno();

    return rstat(basename(buf), &sbuf, edir, nedir);
}

uint64_t sys_fstat(uint64_t * rsp, greg_t * regs) {
    int fd = (int) *(++rsp);
    char * edir = (char*) *(++rsp);
    int nedir = (int) *(++rsp);

    #ifdef DEBUG
        printf("FSTAT fd = %d edir = %p nedir = %d\n", fd, edir, nedir);
    #endif

    struct stat sbuf = {0}; char filepath[PATH_MAX + 1]; char buf[PATH_MAX + 1];

    if (fstat(fd, &sbuf)) return seterrno();
    if (fd2path(fd, filepath, PATH_MAX + 1) == -1) return seterrno();
    if (realpath(filepath, buf) == NULL) return seterrno();

    return rstat(basename(buf), &sbuf, edir, nedir);
}