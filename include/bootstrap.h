#pragma once

#include <ucontext.h>
#include <stdint.h>
#include <signal.h>

typedef uint64_t syscall_handler(uint64_t *, greg_t *);
typedef void (*sighandler)(int, siginfo_t *, void *);

int load(char *, int, char **);
void sigsys(sighandler);
int init(void);