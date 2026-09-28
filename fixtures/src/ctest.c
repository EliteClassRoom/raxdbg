/*
 * libctest.so - libc/bionic fixture for raxdbg.
 *
 * Covers the libc surface that P5/P7/P13 tests check:
 *  - printf("hello %d\n", 42)
 *  - malloc/free round trip
 *  - getpid, clock_gettime
 *  - __system_property_get
 *  - pthread: counter, single value, cond handshake, __thread TLS, errno
 *  - dlopen("libm.so") + dlsym("sin") + sin(0.5)
 *  - atexit / __cxa_atexit
 *  - __android_log_print
 *
 * All functions are extern "C" so the loader finds them by name.
 */
#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <math.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Local prototypes for symbols not always exposed by every libc combo. */
extern int  __cxa_atexit(void (*func)(void *), void *arg, void *dso_handle);
extern int  __system_property_get(const char *name, char *value);
extern int  __android_log_print(int prio, const char *tag, const char *fmt, ...);

/* ------------------------------------------------------------------ */
/* hello()V - printf("hello %d\n", 42).                                  */
/* ------------------------------------------------------------------ */

void hello(void) {
    printf("hello %d\n", 42);
    fflush(stdout);
}

/* ------------------------------------------------------------------ */
/* ctest_malloc_ok()I - malloc/free round trip; returns 1 on success.    */
/* ------------------------------------------------------------------ */

int ctest_malloc_ok(void) {
    void *p = malloc(1024);
    if (p == NULL) return 0;
    /* touch the memory to make sure the page is committed. */
    memset(p, 0x5A, 1024);
    free(p);
    return 1;
}

/* ------------------------------------------------------------------ */
/* pid()I - getpid().                                                    */
/* ------------------------------------------------------------------ */

int pid(void) {
    return (int)getpid();
}

/* ------------------------------------------------------------------ */
/* sdk()I - __system_property_get("ro.build.version.sdk") -> atoi.        */
/* ------------------------------------------------------------------ */

int sdk(void) {
    char buf[92];
    int n = __system_property_get("ro.build.version.sdk", buf);
    if (n <= 0) return -1;
    return atoi(buf);
}

/* ------------------------------------------------------------------ */
/* Shared thread helper for counter()I.                                  */
/* ------------------------------------------------------------------ */

static pthread_mutex_t g_counter_mu = PTHREAD_MUTEX_INITIALIZER;
static int g_counter = 0;

static void *counter_worker(void *arg) {
    int iters = (int)(intptr_t)arg;
    for (int i = 0; i < iters; ++i) {
        pthread_mutex_lock(&g_counter_mu);
        g_counter++;
        pthread_mutex_unlock(&g_counter_mu);
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* counter()I - two threads, each increments g_counter 100 times.        */
/* ------------------------------------------------------------------ */

int counter(void) {
    g_counter = 0;
    pthread_t t1, t2;
    pthread_create(&t1, NULL, counter_worker, (void *)(intptr_t)100);
    pthread_create(&t2, NULL, counter_worker, (void *)(intptr_t)100);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    return g_counter;
}

/* ------------------------------------------------------------------ */
/* thread_value()I - thread returning 7.                                */
/* ------------------------------------------------------------------ */

static void *thread_return_seven(void *arg) {
    (void)arg;
    return (void *)(intptr_t)7;
}

int thread_value(void) {
    pthread_t t;
    void *ret = NULL;
    pthread_create(&t, NULL, thread_return_seven, NULL);
    pthread_join(t, &ret);
    return (int)(intptr_t)ret;
}

/* ------------------------------------------------------------------ */
/* cond_handshake()I - cond wait/signal handshake across threads.       */
/* ------------------------------------------------------------------ */

static pthread_mutex_t g_handshake_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_handshake_cv = PTHREAD_COND_INITIALIZER;
static int             g_handshake_done = 0;

static void *handshake_waiter(void *arg) {
    (void)arg;
    pthread_mutex_lock(&g_handshake_mu);
    while (!g_handshake_done) {
        pthread_cond_wait(&g_handshake_cv, &g_handshake_mu);
    }
    pthread_mutex_unlock(&g_handshake_mu);
    return (void *)(intptr_t)1;
}

int cond_handshake(void) {
    g_handshake_done = 0;
    pthread_t t;
    pthread_create(&t, NULL, handshake_waiter, NULL);

    /* give the waiter a moment to enter pthread_cond_wait. */
    struct timespec ts = { 0, 5 * 1000 * 1000 }; /* 5 ms */
    nanosleep(&ts, NULL);

    pthread_mutex_lock(&g_handshake_mu);
    g_handshake_done = 1;
    pthread_cond_signal(&g_handshake_cv);
    pthread_mutex_unlock(&g_handshake_mu);

    void *ret = NULL;
    pthread_join(t, &ret);
    return (int)(intptr_t)ret;
}

/* ------------------------------------------------------------------ */
/* tls_diff()I - two threads, each has its own __thread int; returns 1  */
/* if the addresses differ (i.e. TLS works).                            */
/* ------------------------------------------------------------------ */

static __thread int g_tls_slot = 0;

static void *tls_read(void *arg) {
    int *expected = (int *)arg;
    /* wait until the host gave us an address to compare against. */
    while ((uintptr_t)expected == 0u) {
        struct timespec ts = { 0, 1 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
    return (void *)(intptr_t)(&g_tls_slot == expected ? 0 : 1);
}

int tls_diff(void) {
    int *main_addr = NULL;
    pthread_t t;
    pthread_create(&t, NULL, tls_read, &main_addr);

    /* set main's TLS address, the worker will see it. */
    main_addr = &g_tls_slot;
    /* small spin so the worker can sample. */
    struct timespec ts = { 0, 5 * 1000 * 1000 };
    nanosleep(&ts, NULL);

    void *ret = NULL;
    pthread_join(t, &ret);
    /* ret == 1 means worker's &g_tls_slot was different from main's. */
    return (int)(intptr_t)ret;
}

/* ------------------------------------------------------------------ */
/* errno_per_thread()I - per-thread errno after a failing syscall.      */
/* Each thread runs close(-1) which fails with EBADF, then stores its   */
/* own errno. Returns 1 if both threads captured a non-zero errno.      */
/* ------------------------------------------------------------------ */

static int g_errno_a = 0;
static int g_errno_b = 0;

static void *errno_worker(void *arg) {
    int *out = (int *)arg;
    errno = 0;
    close(-1);
    close(-2);
    *out = errno;
    return NULL;
}

int errno_per_thread(void) {
    g_errno_a = 0;
    g_errno_b = 0;
    pthread_t t1, t2;
    pthread_create(&t1, NULL, errno_worker, &g_errno_a);
    pthread_create(&t2, NULL, errno_worker, &g_errno_b);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    if (g_errno_a == 0 || g_errno_b == 0) return 0;
    return 1;
}

/* ------------------------------------------------------------------ */
/* clock_now()V - clock_gettime + printf.                               */
/* ------------------------------------------------------------------ */

void clock_now(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
        printf("monotonic=%lld.%09ld\n", (long long)ts.tv_sec, ts.tv_nsec);
    } else {
        printf("monotonic=err\n");
    }
    fflush(stdout);
}

/* ------------------------------------------------------------------ */
/* dlopen_sin()D - dlopen("libm.so") + dlsym("sin") + sin(0.5).          */
/* Returns sin(0.5) on success, or a negative sentinel on failure.     */
/* ------------------------------------------------------------------ */

double dlopen_sin(void) {
    void *h = dlopen("libm.so", RTLD_NOW);
    if (h == NULL) {
        return -1.0;
    }
    double (*sin_fn)(double) = (double (*)(double))dlsym(h, "sin");
    if (sin_fn == NULL) {
        dlclose(h);
        return -2.0;
    }
    double v = sin_fn(0.5);
    dlclose(h);
    return v;
}

/* ------------------------------------------------------------------ */
/* atexit_ok()I - registers one atexit + one __cxa_atexit handler.      */
/* Returns 1 if both registrations succeeded.                          */
/* ------------------------------------------------------------------ */

static int g_atexit_a = 0;
static int g_atexit_b = 0;

static void atexit_a(void) { g_atexit_a++; }
static void atexit_b(void *arg) { (void)arg; g_atexit_b++; }

int atexit_ok(void) {
    g_atexit_a = 0;
    g_atexit_b = 0;
    if (atexit(atexit_a) != 0) return 0;
    if (__cxa_atexit(atexit_b, NULL, NULL) != 0) return 0;
    return 1;
}

/* ------------------------------------------------------------------ */
/* log_print()V - __android_log_print with a formatted message.          */
/* ------------------------------------------------------------------ */

void log_print(void) {
    __android_log_print(4 /* ANDROID_LOG_INFO */, "raxdbg-fixture",
        "ctest log message %d", 42);
}

#ifdef __cplusplus
} /* extern "C" */
#endif