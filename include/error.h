#pragma once

#include <stdint.h>

#define ERRMAX 128 /* max length of error string */

extern char errstr[];
char * geterror(int);
uint64_t seterror(char *);
int seterrno(void);

extern char Eperm[];
extern char Eexist[];
extern char Enonexist[];
extern char Efilename[];
extern char Enofd[];
extern char Ebadarg[];
extern char Eio[];
extern char Edabf[];
extern char Eintr[];
extern char Enospc[];
extern char Edquot[];