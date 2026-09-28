/*
 * libhooktest.so - hook engine fixture for raxdbg.
 *
 * Minimal in P0 (one target function called through a local pointer); grown in
 * P8/P13 to exercise Dobby, HookZz and xHook against its own and imported code.
 */
#include <stdint.h>

int target_fn(int a, int b) {
    return a + b;
}

int (*volatile target_fn_ptr)(int, int) = target_fn;

int run(void) {
    return target_fn_ptr(1, 2);
}
