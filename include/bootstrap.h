#pragma once

#include <ucontext.h>
#include <stdint.h>
#include <signal.h>

typedef struct Region Region;
struct Region { uint64_t begin, end; };

typedef uint64_t syscall_handler(uint64_t *, greg_t *);
typedef void (*sighandler)(int, siginfo_t *, void *);

int load(char *, int, char **);
int sigsys(sighandler);
int elfinit(void);
int sudinit(void);