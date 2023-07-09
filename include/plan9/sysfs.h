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