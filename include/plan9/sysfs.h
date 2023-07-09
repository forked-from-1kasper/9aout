#pragma once

#include <bootstrap.h>

/* open & create */
#define OREAD   0      /* open for read */
#define OWRITE  1      /* write */
#define ORDWR   2      /* read and write */
#define OEXEC   3      /* execute, == read but check execute permission */
#define OTRUNC  16     /* or'ed in (except for exec), truncate file first */
#define OCEXEC  32     /* or'ed in (per file descriptor), close on exec */
#define ORCLOSE 64     /* or'ed in, remove on close */
#define OEXCL   0x1000 /* or'ed in, exclusive create */

#define AEXIST  0 /* accessible: exists */
#define AEXEC   1 /* execute access */
#define AWRITE  2 /* write access */
#define AREAD   4 /* read access */

/* bits in Qid.type */
#define QTDIR    0x80 /* type bit for directories */
#define QTAPPEND 0x40 /* type bit for append only files */
#define QTEXCL   0x20 /* type bit for exclusive use files */
#define QTMOUNT  0x10 /* type bit for mounted channel */
#define QTAUTH   0x08 /* type bit for authentication file */
#define QTTMP    0x04 /* type bit for not-backed-up file */
#define QTFILE   0x00 /* plain file */

/* bits in Dir.mode */
#define DMDIR    0x80000000 /* mode bit for directories */
#define DMAPPEND 0x40000000 /* mode bit for append only files */
#define DMEXCL   0x20000000 /* mode bit for exclusive use files */
#define DMMOUNT  0x10000000 /* mode bit for mounted channel */
#define DMAUTH   0x08000000 /* mode bit for authentication file */
#define DMTMP    0x04000000 /* mode bit for non-backed-up files */
#define DMREAD   0x4        /* mode bit for read permission */
#define DMWRITE  0x2        /* mode bit for write permission */
#define DMEXEC   0x1        /* mode bit for execute permission */

#define BIT8SZ  1
#define BIT16SZ 2
#define BIT32SZ 4
#define BIT64SZ 8

syscall_handler sys_open;
syscall_handler sys_close;
syscall_handler sys_create;
syscall_handler sys_remove;
syscall_handler sys_pread;
syscall_handler sys_pwrite;
syscall_handler sys_seek;
syscall_handler sys_fd2path;
syscall_handler sys_dup;
syscall_handler sys_chdir;
syscall_handler sys_stat;
syscall_handler sys_fstat;