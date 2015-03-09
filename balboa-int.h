#ifndef BALBOA_INT_H_
#define BALBOA_INT_H_

#define BALBOA_DEFAULT_PORT "/tmp/balboa-sock"

struct balboa {
    const char *last_err;
    int daemon_fd;
};

struct balboa_core {
    void *mem;          // virtual address mapped in this proc
    const char *devpath; // path to device file for mmap (normally /dev/mem)
    long long window;   // physical address in devpath
    size_t mem_size;
};

#endif /* BALBOA_INT_H_ */
