#include <string.h>
#include <errno.h>

#include <error.h>

char errstr[ERRMAX] = {0};

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

uint64_t seterror(char * err) {
    strncpy(errstr, err, ERRMAX);
    return -1;
}

int seterrno() { return seterror(geterror(errno)); }

char Eperm[]     = "permission denied";
char Eexist[]    = "file already exists";
char Enonexist[] = "file does not exist";
char Efilename[] = "file name syntax";
char Enofd[]     = "no free file descriptors";
char Ebadarg[]   = "bad arg in system call";
char Eio[]       = "I/O error";
char Edabf[]     = "fd out of range or not open";
char Eintr[]     = "interrupted";
char Enospc[]    = "file system full";
char Edquot[]    = "disk quota exceeded";