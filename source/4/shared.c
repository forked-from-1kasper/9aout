#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>

#include <shared.h>

List * family = NULL;

char * exitmsg = NULL;
int _fd = -1;

segment _text = {0};
segment _data = {0};

void nuke() {
    if (_text.begin) munmap(_text.begin, _text.size);
    if (_data.begin) munmap(_data.begin, _data.size);
    if (_fd != -1)   close(_fd);
}

void swap(int fd, segment text, segment data)
{ _fd = fd; _text = text; _data = data; }

void attach_child(int pid, char * msg) {
    List * node = malloc(sizeof(List));

    node->pid            = pid;
    node->next           = family;
    node->data.exitmsg   = msg;
    node->data.timestamp = timestamp();

    family = node;
}

pdata detach_child(int pid) {
    pdata retval = {0};

    List * prev = NULL, * cur = family;

    while (cur != NULL) {
        if (cur->pid == pid) {
            retval = cur->data;

            if (prev) prev->next = cur->next;
            else family = cur->next;

            free(cur);

            return retval;
        } else { prev = cur; cur = cur->next; }
    }

    return retval;
}

void free_list(List * xs) {
    while (xs != NULL) {
        List * next = xs->next;
        free(xs); xs = next;
    }
}

void detach_everything() { free_list(family); family = NULL; }

uint64_t millisecs(struct timeval time)
{ return time.tv_sec * 1000L + time.tv_usec / 1000L; }

uint64_t timestamp() {
    struct timespec spec; clock_gettime(CLOCK_MONOTONIC, &spec);
    return spec.tv_sec * 1000L + spec.tv_nsec / 1e+6L;
}