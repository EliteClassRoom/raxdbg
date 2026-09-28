/*
 * libjnitest.so - JNI fixture for raxdbg.
 *
 * Exercises the JNI invocation API surface that the P6/P13 tests check:
 *  - JNI_OnLoad: GetEnv, FindClass, RegisterNatives.
 *  - Java_<mangled> exports: symbol-lookup path.
 *  - String in/out, NewStringUTF, ThrowNew + ExceptionCheck.
 *  - NewGlobalRef / DeleteLocalRef.
 *  - Static Java callbacks: FindClass + GetStaticMethodID + CallStaticIntMethod.
 *  - Arrays, NewObject + CallIntMethod, fields.
 *  - A small intentional leak so --leak-check sees a live allocation.
 *
 * All functions use C linkage (no C++ name mangling) so the raxdbg loader
 * finds them by name. JNI's <jni.h> macros use `extern "C"` already, which
 * we re-affirm by wrapping this whole file in extern "C".
 */
#include <jni.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* helpers                                                            */
/* ------------------------------------------------------------------ */

static jint native_add(JNIEnv *env, jclass clazz, jint a, jint b) {
    (void)env;
    (void)clazz;
    return a + b;
}

/* ------------------------------------------------------------------ */
/* JNI_OnLoad: GetEnv + FindClass + RegisterNatives                   */
/* ------------------------------------------------------------------ */

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)reserved;
    JNIEnv *env = NULL;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    jclass clazz = (*env)->FindClass(env, "com/raxdbg/test/JniTest");
    if (clazz == NULL) {
        return JNI_ERR;
    }
    static const JNINativeMethod methods[] = {
        {"add", "(II)I", (void *)native_add},
    };
    if ((*env)->RegisterNatives(env, clazz, methods, 1) != JNI_OK) {
        return JNI_ERR;
    }
    return JNI_VERSION_1_6;
}

/* ------------------------------------------------------------------ */
/* Symbol-lookup path: Java_<mangled>_<mangled>.                      */
/* ------------------------------------------------------------------ */

JNIEXPORT jint JNICALL
Java_com_raxdbg_test_JniTest_add2(JNIEnv *env, jclass clazz, jint a, jint b) {
    (void)env;
    (void)clazz;
    return a + b;
}

/* ------------------------------------------------------------------ */
/* String round trip.                                                   */
/* ------------------------------------------------------------------ */

JNIEXPORT jstring JNICALL
Java_com_raxdbg_test_JniTest_echo(JNIEnv *env, jclass clazz, jstring s) {
    (void)clazz;
    if (s == NULL) return NULL;
    const char *in = (*env)->GetStringUTFChars(env, s, NULL);
    if (in == NULL) return NULL;
    jstring out = (*env)->NewStringUTF(env, in);
    (*env)->ReleaseStringUTFChars(env, s, in);
    return out;
}

/* ------------------------------------------------------------------ */
/* Native -> Java callback: FindClass + GetStaticMethodID + Call...    */
/* ------------------------------------------------------------------ */

JNIEXPORT jint JNICALL
Java_com_raxdbg_test_JniTest_seedPlusOne(JNIEnv *env, jclass clazz) {
    (void)clazz;
    jclass helper = (*env)->FindClass(env, "com/raxdbg/test/JniTest");
    if (helper == NULL) return -1;
    jmethodID mid = (*env)->GetStaticMethodID(env, helper, "getSeed", "()I");
    if (mid == NULL) return -1;
    jint seed = (*env)->CallStaticIntMethod(env, helper, mid);
    if ((*env)->ExceptionCheck(env)) return -2;
    return seed + 1;
}

/* ------------------------------------------------------------------ */
/* Array argument (int[] sum).                                         */
/* ------------------------------------------------------------------ */

JNIEXPORT jint JNICALL
Java_com_raxdbg_test_JniTest_sumArray(JNIEnv *env, jclass clazz, jintArray arr) {
    (void)clazz;
    if (arr == NULL) return 0;
    jsize len = (*env)->GetArrayLength(env, arr);
    jint *body = (*env)->GetIntArrayElements(env, arr, NULL);
    if (body == NULL) return 0;
    jint total = 0;
    for (jsize i = 0; i < len; ++i) total += body[i];
    (*env)->ReleaseIntArrayElements(env, arr, body, JNI_ABORT);
    return total;
}

/* ------------------------------------------------------------------ */
/* NewStringUTF from a constant.                                       */
/* ------------------------------------------------------------------ */

JNIEXPORT jstring JNICALL
Java_com_raxdbg_test_JniTest_newString(JNIEnv *env, jclass clazz) {
    (void)clazz;
    return (*env)->NewStringUTF(env, "hello from native");
}

/* ------------------------------------------------------------------ */
/* Exception flow: ThrowNew + ExceptionCheck.                          */
/* ------------------------------------------------------------------ */

JNIEXPORT void JNICALL
Java_com_raxdbg_test_JniTest_throwIt(JNIEnv *env, jclass clazz) {
    (void)clazz;
    jclass ex = (*env)->FindClass(env, "java/lang/IllegalStateException");
    if (ex == NULL) return;
    (*env)->ThrowNew(env, ex, "boom");
}

/* ------------------------------------------------------------------ */
/* NewGlobalRef -> DeleteLocalRef -> return the global.                 */
/* ------------------------------------------------------------------ */

JNIEXPORT jobject JNICALL
Java_com_raxdbg_test_JniTest_globalRef(JNIEnv *env, jclass clazz, jobject in) {
    (void)clazz;
    if (in == NULL) return NULL;
    jobject g = (*env)->NewGlobalRef(env, in);
    (*env)->DeleteLocalRef(env, in);
    return g;
}

/* ------------------------------------------------------------------ */
/* GetVersion.                                                          */
/* ------------------------------------------------------------------ */

JNIEXPORT jint JNICALL
Java_com_raxdbg_test_JniTest_getVersion(JNIEnv *env, jclass clazz) {
    (void)env;
    (void)clazz;
    return (*env)->GetVersion(env);
}

/* ------------------------------------------------------------------ */
/* Intentional leak: malloc 4096, never free.                          */
/* ------------------------------------------------------------------ */

JNIEXPORT void JNICALL
Java_com_raxdbg_test_JniTest_leak(JNIEnv *env, jclass clazz) {
    (void)env;
    (void)clazz;
    void *p = malloc(4096);
    if (p != NULL) {
        /* write a marker so leak reports show this fixture owned it. */
        memset(p, 0xAB, 4096);
    }
}

/* ------------------------------------------------------------------ */
/* NewObject + CallIntMethod on an instance method.                    */
/* ------------------------------------------------------------------ */

JNIEXPORT jint JNICALL
Java_com_raxdbg_test_JniTest_callInstance(JNIEnv *env, jclass clazz) {
    (void)clazz;
    jclass helper = (*env)->FindClass(env, "com/raxdbg/test/JniTest");
    if (helper == NULL) return -1;
    jmethodID ctor = (*env)->GetMethodID(env, helper, "<init>", "()V");
    if (ctor == NULL) return -2;
    jobject obj = (*env)->NewObject(env, helper, ctor);
    if (obj == NULL) return -3;
    jmethodID valm = (*env)->GetMethodID(env, helper, "value", "()I");
    if (valm == NULL) {
        (*env)->DeleteLocalRef(env, obj);
        return -4;
    }
    jint v = (*env)->CallIntMethod(env, obj, valm);
    (*env)->DeleteLocalRef(env, obj);
    if ((*env)->ExceptionCheck(env)) return -5;
    return v;
}

#ifdef __cplusplus
} /* extern "C" */
#endif