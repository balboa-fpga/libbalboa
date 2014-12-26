#ifndef BALBOA_H_
#define BALBOA_H_

struct balboa;
struct balboa_core;

typedef struct balboa balboa;
typedef struct balboa_core balboa_core;

typedef volatile unsigned char b_u8;
typedef volatile unsigned short b_u16;
typedef volatile unsigned int b_u32;
typedef volatile unsigned long long b_u64;

balboa *balboa_open(const char *port);

const char *balboa_last_error(balboa *b);

balboa_core *balboa_get_core(balboa *b, const char *corename);

void *balboa_core_get_win(balboa_core *c, int n);

void b_memcpy(volatile void *dest, const volatile void *src, size_t n);

#endif /* BALBOA_H_ */
