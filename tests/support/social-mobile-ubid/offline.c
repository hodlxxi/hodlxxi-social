
#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/un.h>
#include <stddef.h>
#include <errno.h>
#include <dlfcn.h>
#include <string.h>
#include <stdlib.h>
int connect(int fd, const struct sockaddr *a, socklen_t n) {
    const char *allowed = getenv("UBID_TEST_ALLOWED_SOCKET");
    if (a && a->sa_family == AF_UNIX && n > offsetof(struct sockaddr_un, sun_path) && allowed) {
        const struct sockaddr_un *u = (const struct sockaddr_un *)a;
        if (u->sun_path[0] && strnlen(u->sun_path, sizeof u->sun_path) < sizeof u->sun_path
            ) {
            char *copy = strdup(allowed), *save = NULL;
            int match = 0;
            for (char *part = strtok_r(copy, "|", &save); part; part = strtok_r(NULL, "|", &save))
                if (strcmp(u->sun_path, part) == 0) match = 1;
            free(copy);
            if (match) {
                int (*real)(int,const struct sockaddr*,socklen_t) = dlsym(RTLD_NEXT,"connect");
                return real(fd,a,n);
            }
        }
    }
    errno = EPERM;
    return -1;
}
ssize_t sendto(int fd,const void *b,size_t l,int f,const struct sockaddr *a,socklen_t n) {
    if (a) { errno=EPERM; return -1; }
    ssize_t (*real)(int,const void*,size_t,int,const struct sockaddr*,socklen_t)=dlsym(RTLD_NEXT,"sendto");
    return real(fd,b,l,f,a,n);
}
