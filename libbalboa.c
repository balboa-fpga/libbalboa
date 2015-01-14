/*
 * libbalboa - glue library for Balboa FPGA acceleration
 * library to do useful computation on an FPGA.
 *
 * Copyright (C) 2014-2015 Andrew Isaacson <adi@hexapodia.org>
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * Provided AS IS with no warranty.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <errno.h>

#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <fcntl.h>

#include <balboa.h>
#include <balboa-int.h>

// XXX use thread local storage?
static char errbuf[1024];

static int daemon_send(int fd, char *cmd)
{
    int ret, n;
    struct iovec iov[2];

    iov[0].iov_base = cmd;
    iov[0].iov_len = strlen(cmd);
    iov[1].iov_base = "\n";
    iov[1].iov_len = 1;

    n = iov[0].iov_len + iov[1].iov_len;

    ret = writev(fd, iov, 2);
    if (ret != n) {
        snprintf(errbuf, sizeof(errbuf), "writev to daemon socket: %s",
                strerror(errno));
        return 0;
    }
    return 1;
}

static int daemon_recv(int fd, char *buf, size_t buflen)
{
    int ret;

    ret = read(fd, buf, buflen - 1);
    if (ret < 1) {
        snprintf(errbuf, sizeof(errbuf), "read from daemon socket: %s",
                ret == 0 ? "EOF" : strerror(errno));
        return 0;
    }
    buf[ret] = '\0';
    return 1;
}

static int get_socket(const char *port)
{
    int fd, ret;
    char buf[100];
    int bufsz = sizeof(buf);
    struct sockaddr_un sa;
    int socklen;

    fd = socket(AF_LOCAL, SOCK_STREAM, 0);
    if (fd == -1) {
        snprintf(errbuf, sizeof(errbuf), "socket: %s", strerror(errno));
        return -1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    strcpy(sa.sun_path, port);
    socklen = offsetof(struct sockaddr_un, sun_path) + strlen(port) + 1;

    ret = connect(fd, (struct sockaddr *)&sa, socklen);
    if (ret == -1) {
        snprintf(errbuf, sizeof(errbuf), "connect: %s", strerror(errno));
        goto fail;
    }
    ret = daemon_send(fd, "hi");
    if (ret == 0)
        goto fail;
    ret = daemon_recv(fd, buf, bufsz);
    if (ret == 0)
        goto fail;
    if (strcmp(buf, "ok\n")) {
        snprintf(errbuf, sizeof(errbuf), "protocol error, got '%s'", buf);
        goto fail;
    }
    return fd;
fail:
    close(fd);
    return -1;
}

balboa *balboa_open(const char *port)
{
    balboa *b = calloc(1, sizeof *b);
    char *p = 0;

    if (!b) {
        snprintf(errbuf, sizeof(errbuf), "calloc(%d) failed",
                (int)(sizeof *b));
        return 0;
    }

    if (!port) {
        port = BALBOA_DEFAULT_PORT;
    }
    if (port[0] == '/') {
        p = strdup(port);
    } else {
        const char *base = "/tmp/";
        int n = strlen(base) + strlen(port) + 1;

        p = malloc(n);
        if (!p) {
            snprintf(errbuf, sizeof(errbuf), "malloc(%d) failed", n);
            goto fail;
        }
        snprintf(p, n, "%s%s", base, port);
    }
    b->daemon_fd = get_socket(p);
    if (b->daemon_fd <= 0) {
        goto fail;
    }
    return b;
fail:
    free(p);
    free(b);
    return 0;
}

const char *balboa_last_error(balboa *b)
{
    if (b && b->last_err)
        return b->last_err;
    return errbuf;
}

balboa_core *balboa_get_core(balboa *b, const char *corename)
{
    char buf[1024];
    int ret;
    long long window, size;
    balboa_core *c = calloc(sizeof *c, 1);
    char name[1024];

    if (!c) {
        snprintf(errbuf, sizeof errbuf, "calloc failed");
        return 0;
    }
    snprintf(buf, sizeof buf, "core %s", corename);
    ret = daemon_send(b->daemon_fd, buf);
    if (ret == 0)
        return 0;
    ret = daemon_recv(b->daemon_fd, buf, sizeof buf);
    if (ret == 0)
        return 0;
    ret = sscanf(buf, "ok core %1023s mem 0x%llx size 0x%llx",
            name, &window, &size);
    if (ret != 3) {
        snprintf(errbuf, sizeof errbuf, "Bad response to 'core': '%s'", buf);
        return 0;
    }
    c->window = window;
    c->mem_size = size;
    return c;
}

void *balboa_core_get_win(balboa_core *c, int n)
{
    void *p;
    int fd;

    if (c->mem)
        return c->mem;

    fd = open("/dev/mem", O_RDWR);

    if (fd == -1) {
        snprintf(errbuf, sizeof errbuf, "/dev/mem: %s", strerror(errno));
        goto fail;
    }
    p = mmap(0, c->mem_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, c->window);
    if (p == MAP_FAILED) {
        snprintf(errbuf, sizeof errbuf, "mmap(0x%llx, 0x%llx): %s",
                (long long)c->mem_size, c->window, strerror(errno));
        goto fail;
    }
    close(fd);
    c->mem = p;
    return p;
fail:
    close(fd);
    return 0;
}

void b_memcpy(volatile void *dest, const volatile void *src, size_t n)
{
    size_t i;
    volatile b_u8 *a = dest;
    const volatile b_u8 *b = src;

    for (i = 0; i < n; i++) {
        a[i] = b[i];
    }
}
