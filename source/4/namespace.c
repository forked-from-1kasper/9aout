#define _GNU_SOURCE

#include <sys/mman.h>
#include <unistd.h>

#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>

#include <namespace.h>
#include <error.h>
#include <errno.h>

Proc self = {0};

void nuke() {
    if (self.text.begin) munmap(self.text.begin, self.text.size);
    if (self.data.begin) munmap(self.data.begin, self.data.size);
}

int memnewfd(SharedMem * mem) {
    mem->memfd = memfd_create("9data", 0);

    if (mem->memfd == -1) return errno;
    if (ftruncate(mem->memfd, mem->size) == -1) return errno;

    return 0;
}

int memnewmap(SharedMem * mem) {
    if (mem->begin)
        if (munmap(mem->begin, mem->size) == -1)
            return errno;

    mem->begin = mmap(mem->begin, mem->size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, mem->memfd, 0);
    return (mem->begin == MAP_FAILED) ? errno : 0;
}

int memnewmutex(SharedMem * mem) {
    if (mem->mutex)
        if (munmap(mem->mutex, sizeof(pthread_mutex_t)) == -1)
            return errno;

    mem->mutex = mmap(NULL, sizeof(pthread_mutex_t), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (mem->mutex == MAP_FAILED) return errno;

    pthread_mutexattr_t mutexattr; pthread_mutexattr_init(&mutexattr);
    pthread_mutexattr_setpshared(&mutexattr, PTHREAD_PROCESS_SHARED);
    return pthread_mutex_init(mem->mutex, &mutexattr);
}

void memlock(SharedMem * mem) {
    pthread_mutex_lock(mem->mutex);
}

void memunlock(SharedMem * mem) {
    pthread_mutex_unlock(mem->mutex);
}

void memwait(SharedMem * mem) {
    pthread_mutex_lock(mem->mutex);
    pthread_mutex_unlock(mem->mutex);
}

void insertq(Waitq ** wq, int pid, char * exitmsg) {
    Waitq * wqnew = malloc(sizeof(Waitq));

    wqnew->pid           = pid;
    wqnew->next          = *wq;
    wqnew->msg.exitmsg   = exitmsg;
    wqnew->msg.timestamp = timestamp();

    *wq = wqnew;
}

Waitmsg awaitq(Waitq ** wq, int pid) {
    Waitmsg retval = {0};

    Waitq * prev = NULL, * cur = *wq;

    while (cur != NULL) {
        if (cur->pid == pid) {
            retval = cur->msg;

            if (prev) prev->next = cur->next;
            else *wq = cur->next;

            free(cur);

            return retval;
        } else { prev = cur; cur = cur->next; }
    }

    return retval;
}

void dropq(Waitq ** wq) {
    while (*wq != NULL) {
        Waitq * next = (*wq)->next;
        free(*wq); *wq = next;
    }
}

uint64_t millisecs(struct timeval time)
{ return time.tv_sec * 1000L + time.tv_usec / 1000L; }

uint64_t timestamp() {
    struct timespec spec; clock_gettime(CLOCK_MONOTONIC, &spec);
    return spec.tv_sec * 1000L + spec.tv_nsec / 1e+6L;
}

void panic(const char * fmt, ...) {
    va_list varargs;

    va_start(varargs, fmt);

    char * buf = self.exitmsg, * end = buf + ERRLEN;

    buf += snprintf(buf, end - buf, "%s %d: suicide: ", self.name, self.pid);
    buf += vsnprintf(buf, end - buf, fmt, varargs);
    if (buf < end) *(buf++) = '\n';
    if (buf < end) memset(buf, 0, end - buf);

    va_end(varargs);

    fprintf(stderr, "%.*s", ERRLEN, self.exitmsg);

    _exit(EXIT_FAILURE);
}