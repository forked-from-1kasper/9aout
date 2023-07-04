#ifndef NINEAOUT_H
#define NINEAOUT_H

#define OREAD   0      /* open for read */
#define OWRITE  1      /* write */
#define ORDWR   2      /* read and write */
#define OEXEC   3      /* execute, == read but check execute permission */
#define OTRUNC  16     /* or'ed in (except for exec), truncate file first */
#define OCEXEC  32     /* or'ed in (per file descriptor), close on exec */
#define ORCLOSE 64     /* or'ed in, remove on close */
#define OEXCL   0x1000 /* or'ed in, exclusive create */

#define ERRMAX 128 /* max length of error string */
#define ERRLEN  64 /* max length of string passed by Exits */

typedef struct header header;

struct header
{
    uint32_t magic;    /* magic number */
    uint32_t text;     /* size of text segment */
    uint32_t data;     /* size of initialized text */
    uint32_t bss;      /* size of uninitialized text */
    uint32_t syms;     /* size of symbol table */
    uint32_t reserved; /* reserved for physical kernel entry point (on 64 bit platforms) */
    uint32_t spsz;     /* size of pc/sp offset table */
    uint32_t pcsz;     /* size of pc/line number table */
    uint64_t entry;    /* entry point */
};

typedef struct segment segment;

struct segment
{
    void * begin;
    uint32_t size;
};

#define HDR_MAGIC 0x00008000 /* header expansion */

#define _MAGIC(f, b) ((f)|((((4*(b))+0)*(b))+7))

#define A_MAGIC _MAGIC(0, 8)          /* 68020 */
#define I_MAGIC _MAGIC(0, 11)         /* intel 386 */
#define J_MAGIC _MAGIC(0, 12)         /* intel 960 (retired) */
#define K_MAGIC _MAGIC(0, 13)         /* sparc */
#define V_MAGIC _MAGIC(0, 16)         /* mips 3000 BE */
#define X_MAGIC _MAGIC(0, 17)         /* att dsp 3210 (retired) */
#define M_MAGIC _MAGIC(0, 18)         /* mips 4000 BE */
#define D_MAGIC _MAGIC(0, 19)         /* amd 29000 (retired) */
#define E_MAGIC _MAGIC(0, 20)         /* arm */
#define Q_MAGIC _MAGIC(0, 21)         /* powerpc */
#define N_MAGIC _MAGIC(0, 22)         /* mips 4000 LE */
#define L_MAGIC _MAGIC(0, 23)         /* dec alpha (retired) */
#define P_MAGIC _MAGIC(0, 24)         /* mips 3000 LE */
#define U_MAGIC _MAGIC(0, 25)         /* sparc64 */
#define S_MAGIC _MAGIC(HDR_MAGIC, 26) /* amd64 */
#define T_MAGIC _MAGIC(HDR_MAGIC, 27) /* powerpc64 */
#define R_MAGIC _MAGIC(HDR_MAGIC, 28) /* arm64 */

#define MIN_MAGIC 8
#define MAX_MAGIC 28 /* <= 90 */

#define TOS_SIZE 14
#define ALIGN    0x1fffff

#define KiB 1024u                  /* Kibi 0x0000000000000400 */
#define MiB 1048576u               /* Mebi 0x0000000000100000 */
#define GiB 1073741824u            /* Gibi 000000000040000000 */
#define TiB 1099511627776ull       /* Tebi 0x0000010000000000 */
#define PiB 1125899906842624ull    /* Pebi 0x0004000000000000 */
#define EiB 1152921504606846976ull /* Exbi 0x1000000000000000 */

// Address spaces.
#define UTZERO    (0x0000000000200000ull)  /* first address in user text */
#define UADDRMASK (0x00007fffffffffffull)  /* canonical address mask */
#define USTKTOP   (0x00007ffffffff000ull)  /* top of stack */
#define USTKSIZE  (16*MiB)                 /* size of user stack */

typedef uint64_t syscall_handler(uint64_t *, greg_t *);

#endif