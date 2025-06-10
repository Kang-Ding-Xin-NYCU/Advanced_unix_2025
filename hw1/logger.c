#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>

typedef int64_t (*syscall_hook_fn_t)(int64_t, int64_t, int64_t,
                                     int64_t, int64_t, int64_t, int64_t);

static syscall_hook_fn_t original_syscall = NULL;

static void escape_and_print(const char *buf, int len)
{
    int limit = len > 32 ? 32 : len;
    fputc('"', stderr);
    for (int i = 0; i < limit; ++i) {
        unsigned char c = buf[i];
        if (c == '\n') {
            fputs("\\n", stderr);
        } else if (c == '\r') {
            fputs("\\r", stderr);
        } else if (c == '\t') {
            fputs("\\t", stderr);
        } else if (c >= 32 && c <= 126) {
            fputc(c, stderr);
        } else {
            fprintf(stderr, "\\x%02x", c);
        }
    }
    fputc('"', stderr);
    if (len > 32) {
        fputs("...", stderr);
    }
}

static int64_t syscall_hook_fn(int64_t rdi, int64_t rsi, int64_t rdx,
                               int64_t r10, int64_t r8, int64_t r9,
                               int64_t rax)
{
    if (rax == 59 /* execve */) {
        const char *pathname = (const char *)rdi;
        void *argv = (void *)rsi;
        void *envp = (void *)rdx;
        fprintf(stderr, "[logger] execve(\"%s\", %p, %p)\n", pathname, argv, envp);
    }

    int64_t ret = original_syscall(rdi, rsi, rdx, r10, r8, r9, rax);

    if (rax == 257 /* openat */) {
        int dirfd = (int)rdi;
        const char *pathname = (const char *)rsi;
        int flags = (int)rdx;
        int mode = (int)r10;
        fprintf(stderr, "[logger] openat(");
        if (dirfd == -100) {
            fprintf(stderr, "AT_FDCWD");
        } else {
            fprintf(stderr, "%d", dirfd);
        }
        fprintf(stderr, ", \"%s\", 0x%x, %#o) = %ld\n", pathname, flags, mode, ret);

    } else if (rax == 0 /* read */) {
        int fd = (int)rdi;
        const char *buf = (const char *)rsi;
        int count = (int)rdx;
        fprintf(stderr, "[logger] read(%d, ", fd);
        escape_and_print(buf, ret > 0 ? ret : 0);
        fprintf(stderr, ", %d) = %ld\n", count, ret);

    } else if (rax == 1 /* write */) {
        int fd = (int)rdi;
        const char *buf = (const char *)rsi;
        int count = (int)rdx;
        if (fd == 2) {
            return ret;
        }
        fprintf(stderr, "[logger] write(%d, ", fd);
        escape_and_print(buf, ret > 0 ? ret : 0);
        fprintf(stderr, ", %d) = %ld\n", count, ret);

    } else if (rax == 42 /* connect */) {
        int fd = (int)rdi;
        struct sockaddr *addr = (struct sockaddr *)rsi;
        socklen_t addrlen = (socklen_t)rdx;
        fprintf(stderr, "[logger] connect(%d, ", fd);

        if (addr->sa_family == AF_INET) {
            struct sockaddr_in *in = (struct sockaddr_in *)addr;
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(in->sin_addr), ip, sizeof(ip));
            int port = ntohs(in->sin_port);
            fprintf(stderr, "\"%s:%d\"", ip, port);

        } else if (addr->sa_family == AF_INET6) {
            struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)addr;
            char ip[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &(in6->sin6_addr), ip, sizeof(ip));
            int port = ntohs(in6->sin6_port);
            fprintf(stderr, "\"%s:%d\"", ip, port);

        } else if (addr->sa_family == AF_UNIX) {
            struct sockaddr_un *un = (struct sockaddr_un *)addr;
            fprintf(stderr, "\"UNIX:%s\"", un->sun_path);

        } else {
            fprintf(stderr, "\"UNKNOWN\"");
        }

        fprintf(stderr, ", %d) = %ld\n", addrlen, ret);
    }

    return ret;
}

int __hook_init(const syscall_hook_fn_t trigger_syscall,
                 syscall_hook_fn_t *hooked_syscall)
{
    original_syscall = trigger_syscall;
    *hooked_syscall = syscall_hook_fn;
    return 0;
}
