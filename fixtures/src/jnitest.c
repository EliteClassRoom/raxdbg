/*
 * libjnitest.so - JNI fixture for raxdbg.
 *
 * Minimal in P0 (one registered native + one Java_ export); grown in P6/P13 to
 * cover strings, arrays, objects, fields, exceptions and references.
 */
#include <jni.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static jint native_add(JNIEnv *env, jclass clazz, jint a, jint b) {
    (void)env;
    (void)clazz;
    return a + b;
}

/* Exported through the Java_<mangled> symbol path (not RegisterNatives). */
JNIEXPORT jint JNICALL
Java_com_raxdbg_test_JniTest_add2(JNIEnv *env, jclass clazz, jint a, jint b) {
    (void)env;
    (void)clazz;
    return a + b;
}

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
