#pragma once

#include <bootstrap.h>

/* rfork */
enum
{
    RFNAMEG  = (1 << 0),
    RFENVG   = (1 << 1),
    RFFDG    = (1 << 2),
    RFNOTEG  = (1 << 3),
    RFPROC   = (1 << 4),
    RFMEM    = (1 << 5),
    RFNOWAIT = (1 << 6),
    RFCNAMEG = (1 << 10),
    RFCENVG  = (1 << 11),
    RFCFDG   = (1 << 12),
    RFREND   = (1 << 13),
    RFNOMNT  = (1 << 14)
};

#define ERRLEN 64 /* max length of string passed by Exits */

syscall_handler sys_sleep;
syscall_handler sys_rfork;
syscall_handler sys_exec;
syscall_handler sys_await;
syscall_handler sys_exits;
syscall_handler sys_brk;
syscall_handler sys_errstr;