/*
 * libhooktest.so - hook engine fixture for raxdbg.
 *
 * Exercises the P8 hook surfaces that the test suite verifies:
 *  - A real exported target function `target_fn(int,int) -> int` that
 *    Dobby/xHook can replace.
 *  - `run()` - baseline call to target_fn.
 *  - `dobby_run()` - dlopen("libdobby.so") + DobbyHook + call target_fn.
 *  - `zz_run()`    - dlopen("libhookzz.so") + ZzReplace on a 2nd function.
 *  - `xhook_run()` - dlopen("libxhook.so") + xhook_register + refresh.
 *  - `imported_target()` - calls a libc symbol through the PLT so the
 *    xhook test can target an imported symbol if it wants to.
 *
 * Hook engine prototypes are declared locally as extern; calls go through
 * dlsym so a missing engine fails loudly (returns NULL from dlsym -> the
 * fixture reports a sentinel value rather than crashing).
 */
#include <dlfcn.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Hook engine prototypes.                                              */
/*                                                                      */
/* These match the public surface each engine exposes. We declare them  */
/* ourselves (rather than including engine headers) so this fixture has */
/* no header dependency on the bundled .so binaries.                    */
/* ------------------------------------------------------------------ */

/* Dobby: returns 0 on success. */
typedef int (*dobby_hook_fn)(void *func_addr, void *replace_fn, void **original);
extern int  DobbyHook(void *func_addr, void *replace_fn, void **original);

/* HookZz (ZzReplace): returns 0 on success. */
typedef int (*zz_replace_fn)(void *func_addr, void *replace_fn, void **original);
extern int  ZzReplace(void *func_addr, void *replace_fn, void **original);

/* xHook: regex (POSIX extended) -> symbol replacement. */
typedef int (*xhook_register_fn)(const char *pathname_regex,
                                 const char *symbol,
                                 void *replace_fn,
                                 void **original);
typedef int (*xhook_refresh_fn)(int async);
extern int  xhook_register(const char *pathname_regex,
                           const char *symbol,
                           void *replace_fn,
                           void **original);
extern int  xhook_refresh(int async);

/* ------------------------------------------------------------------ */
/* Target functions.                                                    */
/* Exported (kept externally visible) so a hook can rewrite the        */
/* function's prologue. The `volatile` function-pointer aliases force   */
/* the compiler to emit real call instructions through the PLT/GOT.     */
/* ------------------------------------------------------------------ */

int target_fn(int a, int b) {
    return a + b;
}

int second_fn(int a, int b) {
    return a * b + 1;
}

/* Force externally-linked call sites through volatile function pointers. */
int    (*volatile target_fn_ptr)(int, int)   = target_fn;
int    (*volatile second_fn_ptr)(int, int)   = second_fn;
size_t (*volatile strlen_ptr)(const char *)  =
    (size_t (*)(const char *))(uintptr_t)strlen;

/* ------------------------------------------------------------------ */
/* Baseline call: returns target_fn(1,2) = 3.                           */
/* ------------------------------------------------------------------ */

int run(void) {
    return target_fn_ptr(1, 2);
}

/* ------------------------------------------------------------------ */
/* Replacements used by Dobby / HookZz / xHook.                        */
/* ------------------------------------------------------------------ */

static int target_fn_replacement_dobby(int a, int b) {
    (void)a;
    (void)b;
    return 100;
}

static int second_fn_replacement_zz(int a, int b) {
    (void)a;
    (void)b;
    return 200;
}

static int target_fn_replacement_xhook(int a, int b) {
    (void)a;
    (void)b;
    return 300;
}

/* ------------------------------------------------------------------ */
/* Dobby path.                                                          */
/* ------------------------------------------------------------------ */

int dobby_run(void) {
    void *h = dlopen("libdobby.so", RTLD_NOW);
    if (h == NULL) return -1;

    dobby_hook_fn hook = (dobby_hook_fn)dlsym(h, "DobbyHook");
    if (hook == NULL) { dlclose(h); return -2; }

    void *original = NULL;
    int rc = hook((void *)(uintptr_t)target_fn,
                  (void *)target_fn_replacement_dobby,
                  &original);
    if (rc != 0) { dlclose(h); return -3; }

    int v = target_fn_ptr(1, 2);
    dlclose(h);
    return v; /* should be 100 after the hook takes effect. */
}

/* ------------------------------------------------------------------ */
/* HookZz path.                                                         */
/* ------------------------------------------------------------------ */

int zz_run(void) {
    void *h = dlopen("libhookzz.so", RTLD_NOW);
    if (h == NULL) return -1;

    zz_replace_fn replace = (zz_replace_fn)dlsym(h, "ZzReplace");
    if (replace == NULL) { dlclose(h); return -2; }

    void *original = NULL;
    int rc = replace((void *)(uintptr_t)second_fn,
                     (void *)second_fn_replacement_zz,
                     &original);
    if (rc != 0) { dlclose(h); return -3; }

    int v = second_fn_ptr(3, 4); /* would be 13 unhooked, 200 hooked. */
    dlclose(h);
    return v;
}

/* ------------------------------------------------------------------ */
/* xHook path.                                                          */
/* ------------------------------------------------------------------ */

int xhook_run(void) {
    void *h = dlopen("libxhook.so", RTLD_NOW);
    if (h == NULL) return -1;

    xhook_register_fn reg = (xhook_register_fn)dlsym(h, "xhook_register");
    xhook_refresh_fn   ref = (xhook_refresh_fn)dlsym(h, "xhook_refresh");
    if (reg == NULL || ref == NULL) { dlclose(h); return -2; }

    void *original = NULL;
    int rc = reg(".*libhooktest\\.so$",
                 "target_fn",
                 (void *)target_fn_replacement_xhook,
                 &original);
    if (rc != 0) { dlclose(h); return -3; }
    rc = ref(0 /* synchronous */);
    if (rc != 0) { dlclose(h); return -4; }

    int v = target_fn_ptr(1, 2); /* should be 300. */
    dlclose(h);
    return v;
}

/* ------------------------------------------------------------------ */
/* Imported-symbol caller.                                              */
/* Goes through the PLT for strlen, so xHook can target the PLT slot. */
/* ------------------------------------------------------------------ */

size_t imported_target(const char *s) {
    if (s == NULL) return 0;
    return strlen_ptr(s);
}

#ifdef __cplusplus
} /* extern "C" */
#endif