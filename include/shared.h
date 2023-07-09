#pragma once

#include <stdint.h>
#include <time.h>

#include <9aout.h>

extern List * family;

extern char * exitmsg;
extern int _fd;
extern segment _text, _data;

void swap(int, segment, segment);
void nuke();

void attach_child(int, char *);
pdata detach_child(int);
void detach_everything(void);

uint64_t timestamp(void);
uint64_t millisecs(struct timeval);