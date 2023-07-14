#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>

#include <namespace.h>

Proc self = {0};

void nuke() {
    if (self.text.begin) munmap(self.text.begin, self.text.size);
    if (self.data.begin) munmap(self.data.begin, self.data.size);
}

void swap(segment text, segment data)
{ self.text = text; self.data = data; }

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