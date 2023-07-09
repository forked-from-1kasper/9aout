#pragma once

#include <signal.h>

typedef void (*sighandler)(int, siginfo_t *, void *);

int load(char *, int, char **);
void sigsys(sighandler);
int init(void);