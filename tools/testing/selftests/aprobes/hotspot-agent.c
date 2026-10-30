// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2026 Isovalent, Inc.
#define _GNU_SOURCE
#include <jni.h>
#include <jvmti.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static _Atomic uintptr_t target_code;
static _Atomic int target_size;

static void JNICALL compiled(jvmtiEnv *jvmti, jmethodID method, jint size,
                            const void *address, jint count,
                            const jvmtiAddrLocationMap *map, const void *info)
{
    (void)count; (void)map; (void)info;
    char *name = NULL, *signature = NULL;
    jclass klass;
    if ((*jvmti)->GetMethodName(jvmti, method, &name, NULL, NULL) != JVMTI_ERROR_NONE)
        return;
    if (!strcmp(name, "target") &&
        (*jvmti)->GetMethodDeclaringClass(jvmti, method, &klass) == JVMTI_ERROR_NONE &&
        (*jvmti)->GetClassSignature(jvmti, klass, &signature, NULL) == JVMTI_ERROR_NONE &&
        !strcmp(signature, "LAprobeHotSpot;")) {
        atomic_store(&target_size, size);
        atomic_store(&target_code, (uintptr_t)address);
    }
    if (signature) (*jvmti)->Deallocate(jvmti, (unsigned char *)signature);
    (*jvmti)->Deallocate(jvmti, (unsigned char *)name);
}

JNIEXPORT jint JNICALL Agent_OnLoad(JavaVM *vm, char *options, void *reserved)
{
    (void)options; (void)reserved;
    jvmtiEnv *jvmti;
    if ((*vm)->GetEnv(vm, (void **)&jvmti, JVMTI_VERSION_1_2) != JNI_OK) return JNI_ERR;
    jvmtiCapabilities caps = {.can_generate_compiled_method_load_events = 1};
    jvmtiEventCallbacks callbacks = {.CompiledMethodLoad = compiled};
    if ((*jvmti)->AddCapabilities(jvmti, &caps) != JVMTI_ERROR_NONE ||
        (*jvmti)->SetEventCallbacks(jvmti, &callbacks, sizeof(callbacks)) != JVMTI_ERROR_NONE ||
        (*jvmti)->SetEventNotificationMode(jvmti, JVMTI_ENABLE, JVMTI_EVENT_COMPILED_METHOD_LOAD, NULL) != JVMTI_ERROR_NONE)
        return JNI_ERR;
    return JNI_OK;
}

static void wait_file(const char *path)
{
    for (int i = 0; i < 3000; i++) {
        if (!access(path, F_OK)) return;
        usleep(10000);
    }
    fprintf(stderr, "HotSpot fixture timed out waiting for %s\n", path);
    abort();
}

JNIEXPORT void JNICALL Java_AprobeHotSpot_prepare(JNIEnv *env, jclass klass)
{
    (void)env; (void)klass;
    uintptr_t address = atomic_load(&target_code);
    if (!address) { fputs("target was not JIT compiled\n", stderr); abort(); }
    FILE *ready = fopen("/tmp/hotspot-ready", "w");
    if (!ready) abort();
    fprintf(ready, "%lx %d\n", (unsigned long)address, atomic_load(&target_size));
    fclose(ready);
    printf("HOTSPOT_COMPILED_ADDRESS=%lx size=%d\n", (unsigned long)address, atomic_load(&target_size));
    fflush(stdout);
    wait_file("/tmp/hotspot-go");
}

JNIEXPORT void JNICALL Java_AprobeHotSpot_complete(JNIEnv *env, jclass klass)
{
    (void)env; (void)klass;
    FILE *done = fopen("/tmp/hotspot-done", "w");
    if (!done) abort();
    fputs("done\n", done); fclose(done);
    wait_file("/tmp/hotspot-detached");
}
