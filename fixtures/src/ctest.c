/*
 * libctest.so - libc/bionic fixture for raxdbg.
 *
 * Minimal in P0 (one libc call); grown in P5/P7/P13 to cover malloc/printf/
 * fopen/pthread/system properties/dlopens.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int hello_value(void) {
    return 42;
}

int hello(void) {
    printf("hello %d\n", hello_value());
    return 0;
}

int ctest_malloc_ok(void) {
    void *p = malloc(1024);
    if (p == NULL) {
        return 0;
    }
    free(p);
    return 1;
}
