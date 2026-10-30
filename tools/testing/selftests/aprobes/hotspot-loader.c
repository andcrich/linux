// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2026 Isovalent, Inc.
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "hotspot-symbols.h"
#include "hotspot-stats.h"
#ifndef BPF_F_UPROBE_MULTI_APROBE_FACTORY
#define BPF_F_UPROBE_MULTI_APROBE_FACTORY (1U << 3)
#endif
#define CHECK(x)                                                                \
	do {                                                                    \
		if (!(x)) {                                                     \
			fprintf(stderr,                                         \
				"HOTSPOT_LIFECYCLE_FAIL line=%d %s errno=%d\n", \
				__LINE__, #x, errno);                           \
			exit(1);                                                \
		}                                                               \
	} while (0)
int main(int argc, char **argv)
{
	const char *gc = argc > 1 && !strcmp(argv[1], "zgc") ? "-XX:+UseZGC" :
							       "-XX:+UseG1GC";
	setbuf(stdout, NULL);
	printf("HOTSPOT_LIFECYCLE_GC=%s\n", gc);
	unlink("/tmp/lifecycle-ready");
	unlink("/tmp/lifecycle-go");
	struct bpf_object *obj = bpf_object__open_file("/hotspot.bpf.o", NULL);
	CHECK(obj && !libbpf_get_error(obj));
	struct bpf_program *prog =
		bpf_object__find_program_by_name(obj, "hotspot_lifecycle");
	CHECK(prog);
	bpf_program__set_type(prog, BPF_PROG_TYPE_KPROBE);
	bpf_program__set_expected_attach_type(prog, BPF_TRACE_UPROBE_MULTI);
	bpf_program__set_flags(prog, BPF_F_SLEEPABLE);
	CHECK(bpf_object__load(obj) == 0);
	pid_t child = fork();
	CHECK(child >= 0);
	if (!child) {
		execl("/jdk/bin/java", "java", "-Xms64m", "-Xmx128m",
		      "-XX:ReservedCodeCacheSize=32m", gc, "-Xbatch",
		      "-XX:CompileThresholdScaling=0.1",
		      "-XX:CompileCommand=quiet",
		      "-XX:CompileCommand=dontinline,AprobeLifecycle$Payload::target",
		      "-Xlog:class+unload=info",
		      "-agentpath:/libaprobe-lifecycle.so", "-cp", "/",
		      "AprobeLifecycle", NULL);
		_exit(127);
	}
	for (int i = 0; access("/tmp/lifecycle-ready", F_OK); i++) {
		int status;
		CHECK(i < 3000 && waitpid(child, &status, WNOHANG) == 0);
		usleep(10000);
	}
	__u64 cookies[] = { PUBLISH, OSR, INVALIDATE, UNLINK, FREE };
	union bpf_attr attr = {};
	attr.link_create.prog_fd = bpf_program__fd(prog);
	attr.link_create.attach_type = BPF_TRACE_UPROBE_MULTI;
	attr.link_create.uprobe_multi.path =
		(uintptr_t)"/jdk/lib/server/libjvm.so";
	attr.link_create.uprobe_multi.pid = child;
	attr.link_create.uprobe_multi.cnt =
		sizeof(cookies) / sizeof(cookies[0]);
	attr.link_create.uprobe_multi.offsets = (uintptr_t)lifecycle_offsets;
	attr.link_create.uprobe_multi.cookies = (uintptr_t)cookies;
	attr.link_create.uprobe_multi.flags = BPF_F_UPROBE_MULTI_APROBE_FACTORY;
	int link = syscall(__NR_bpf, BPF_LINK_CREATE, &attr, sizeof(attr));
	CHECK(link >= 0);
	FILE *go = fopen("/tmp/lifecycle-go", "w");
	CHECK(go);
	fputs("go\n", go);
	CHECK(fclose(go) == 0);
	int status = 0, finished = 0;
	for (int i = 0; i < 12000; i++) {
		pid_t result = waitpid(child, &status, WNOHANG);
		CHECK(result >= 0);
		if (result == child) {
			finished = 1;
			break;
		}
		usleep(10000);
	}
	CHECK(finished && WIFEXITED(status) && WEXITSTATUS(status) == 0);
	struct hotspot_stats s = {};
	__u32 zero = 0;
	int stats_fd = bpf_object__find_map_fd_by_name(obj, "stats");
	CHECK(stats_fd >= 0);
	CHECK(bpf_map_lookup_elem(stats_fd, &zero, &s) == 0);
	printf("HOTSPOT_LIFECYCLE_STATS publications=%llu hits=%llu c1=%llu c2=%llu invalidations=%llu unloads=%llu frees=%llu removed=%llu errors=%llu read_errors=%llu stale_hits=%llu\n",
	       (unsigned long long)s.publications, (unsigned long long)s.hits,
	       (unsigned long long)s.c1, (unsigned long long)s.c2,
	       (unsigned long long)s.invalidations,
	       (unsigned long long)s.unloads, (unsigned long long)s.frees,
	       (unsigned long long)s.removed, (unsigned long long)s.errors,
	       (unsigned long long)s.read_errors,
	       (unsigned long long)s.stale_hits);
	__u64 key = 0, next = 0;
	int history = bpf_object__find_map_fd_by_name(obj, "history");
	CHECK(history >= 0);
	int ret = bpf_map_get_next_key(history, NULL, &key);
	unsigned int generations = 0, reused = 0;
	__u64 addresses[4096];
	while (!ret) {
		struct generation g = {};
		CHECK(bpf_map_lookup_elem(history, &key, &g) == 0);
		printf("HOTSPOT_GENERATION id=%llu nm=%llx entry=%llx level=%u hits=%llu phase=%u\n",
		       (unsigned long long)(key & ~HIT_COOKIE),
		       (unsigned long long)g.nmethod,
		       (unsigned long long)g.entry, g.level,
		       (unsigned long long)g.hits, g.phase);
		CHECK(generations < 4096);
		for (unsigned int i = 0; i < generations; i++)
			if (addresses[i] == g.nmethod) {
				reused++;
				break;
			}
		addresses[generations++] = g.nmethod;
		ret = bpf_map_get_next_key(history, &key, &next);
		key = next;
	}
	int live = bpf_object__find_map_fd_by_name(obj, "live");
	CHECK(live >= 0);
	CHECK(bpf_map_get_next_key(live, NULL, &key) < 0 && errno == ENOENT);
	CHECK(s.publications >= 24 && s.hits > 1000 && s.c1 > 0 && s.c2 > 0);
	CHECK(s.invalidations > 0 && s.unloads >= 24 &&
	      s.frees == s.publications);
	CHECK(s.errors == 0 && s.read_errors == 0 && s.stale_hits == 0);
	CHECK(generations == s.publications && s.removed == s.publications);
	close(link);
	bpf_object__close(obj);
	printf("HOTSPOT_LIFECYCLE_PASS generations=%u reused_addresses=%u\n",
	       generations, reused);
	return 0;
}
