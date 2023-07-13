#pragma once

#include <stdint.h>
#include <time.h>

typedef struct segment segment;

struct segment {
    void *   begin;
    uint32_t size;
};

typedef struct Waitmsg Waitmsg;

struct Waitmsg {
    uint64_t timestamp;
    char *   exitmsg;
};

typedef struct Waitq Waitq;

struct Waitq {
    int      pid;
    Waitmsg  msg;
    Waitq *  next;
};

typedef struct Proc Proc;

struct Proc {
    char *  exitmsg;
    int     fd;
    segment text, data;
    Waitq * wq;
};

extern Proc self;

void swap(int, segment, segment);
void nuke();

void    insertq(Waitq **, int, char *);
Waitmsg awaitq(Waitq **, int);
void    dropq(Waitq **);

uint64_t timestamp(void);
uint64_t millisecs(struct timeval);