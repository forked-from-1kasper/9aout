#pragma once

#include <9aout.h>

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