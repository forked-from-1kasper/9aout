#pragma once

#include <stdint.h>
#include <time.h>

typedef struct segment segment;

struct segment {
    void *   begin;
    uint32_t size;
};

typedef struct pdata pdata;

struct pdata {
    uint64_t timestamp;
    char *   exitmsg;
};

typedef struct List List;

struct List {
    int    pid;
    pdata  data;
    List * next;
};

extern List * family;

extern char * exitmsg;
extern int _fd;
extern segment _text, _data;

void swap(int, segment, segment);
void nuke();

void  attach_child(int, char *);
pdata detach_child(int);
void  detach_everything(void);

uint64_t timestamp(void);
uint64_t millisecs(struct timeval);