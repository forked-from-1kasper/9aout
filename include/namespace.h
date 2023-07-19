#pragma once

#include <pthread.h>
#include <stdint.h>
#include <time.h>

typedef struct Segment Segment;

struct Segment {
    void *   begin;
    uint32_t size;
};

typedef struct SharedMem SharedMem;

struct SharedMem {
    int               memfd;
    void *            begin;
    uint32_t          size;
    pthread_mutex_t * mutex;
};

int    memnewmap(SharedMem *, void *);
int     memnewfd(SharedMem *);
int  memnewmutex(SharedMem *);
void     memlock(SharedMem *);
void   memunlock(SharedMem *);
void     memwait(SharedMem *);

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
    pid_t     pid;
    char *    name;
    char *    exitmsg;
    int       fd;
    Segment   text;
    SharedMem data;
    Waitq *   wq;
};

extern Proc self;

void swap(Segment, SharedMem);
void nuke();

void    insertq(Waitq **, int, char *);
Waitmsg  awaitq(Waitq **, int);
void      dropq(Waitq **);

uint64_t timestamp(void);
uint64_t millisecs(struct timeval);

void panic(const char *, ...);