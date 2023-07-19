#pragma once

#include <ucontext.h>
#include <stdint.h>
#include <signal.h>

typedef struct Region Region;
struct Region { uint64_t begin, end; };

typedef uint64_t syscall_handler(uint64_t *, greg_t *);
typedef void (*sighandler)(int, siginfo_t *, void *);

typedef struct Conf Conf;
struct Conf {
    uint8_t sudselector;
    uint8_t execfallback;
} __attribute__((__packed__));

void revertconf(Conf *);
int     siginit(sighandler);
int     elfinit(void);
int     sudinit(void);
int    loadaout(int, int, char **);

extern Conf config;