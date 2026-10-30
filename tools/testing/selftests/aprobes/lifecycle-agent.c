// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2026 Isovalent, Inc.
#include <jni.h>
#include <stdio.h>
#include <unistd.h>
JNIEXPORT jint JNICALL Agent_OnLoad(JavaVM *vm, char *options, void *reserved)
{
	(void)vm;
	(void)options;
	(void)reserved;
	FILE *ready = fopen("/tmp/lifecycle-ready", "w");
	if (!ready)
		return JNI_ERR;
	fputs("ready\n", ready);
	fclose(ready);
	for (int i = 0; i < 3000; i++) {
		if (!access("/tmp/lifecycle-go", F_OK))
			return JNI_OK;
		usleep(10000);
	}
	return JNI_ERR;
}
