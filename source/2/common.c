#define _GNU_SOURCE

#include <ucontext.h>
#include <stdio.h>

#include <plan9/common.h>

uint64_t sys_plan9_unimplemented(uint64_t * rsp, greg_t * regs) {
    #ifdef DEBUG
        printf("P9: %lld called but unimplemented!\n", regs[REG_RBP]);
    #endif

    return 0;
}

uint64_t sys_plan9_deprecated(uint64_t * rsp, greg_t * regs) {
    #ifdef DEBUG
        printf("P9: syscall number %lld DEPRECATED!\n", regs[REG_RBP]);
    #endif

    return 0;
}

uint64_t sysr1(uint64_t * rsp, greg_t * regs) {
    // TODO: return true if current user is eve
    return 0;
}