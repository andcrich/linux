// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2026 Isovalent, Inc.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <linux/bpf.h>
#include <linux/capability.h>
#include <linux/kernel.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <linux/userfaultfd.h>
#include <sched.h>
#include <signal.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include "../kselftest.h"
#include <unistd.h>

#if defined(__x86_64__)

static int map_fd, prog_fd;
static unsigned int tests;
static const unsigned char original[] = { 0x89, 0xf8, 0x83, 0xc0, 7, 0xc3 };
typedef int (*code_fn)(int);

#define CHECK(x)                                                          \
	do {                                                              \
		if (!(x)) {                                               \
			ksft_exit_fail_msg("line %d: %s errno=%d (%s)\n", \
					   __LINE__, #x, errno,           \
					   strerror(errno));              \
		}                                                         \
	} while (0)
#define PASS(s)                                   \
	do {                                      \
		tests++;                          \
		ksft_test_result_pass("%s\n", s); \
	} while (0)
#define INSN(c, d, s, o, i)                 \
	((struct bpf_insn){ .code = (c),    \
			    .dst_reg = (d), \
			    .src_reg = (s), \
			    .off = (o),     \
			    .imm = (i) })

static int bpf_call(enum bpf_cmd cmd, union bpf_attr *attr)
{
	return syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

static uint64_t hits(void)
{
	uint32_t key = 0;
	uint64_t value = 0;
	union bpf_attr a = { .map_fd = map_fd,
			     .key = (uintptr_t)&key,
			     .value = (uintptr_t)&value };
	CHECK(bpf_call(BPF_MAP_LOOKUP_ELEM, &a) == 0);
	return value;
}

static void setup_bpf(void)
{
	union bpf_attr a = { .map_type = BPF_MAP_TYPE_ARRAY,
			     .key_size = 4,
			     .value_size = 8,
			     .max_entries = 1 };
	map_fd = bpf_call(BPF_MAP_CREATE, &a);
	if (map_fd < 0 &&
	    (errno == EPERM || errno == EACCES || errno == ENOSYS))
		ksft_exit_skip("BPF unavailable or insufficient privilege\n");
	CHECK(map_fd >= 0);
	struct bpf_insn p[] = {
		INSN(BPF_LD | BPF_DW | BPF_IMM, BPF_REG_1, BPF_PSEUDO_MAP_FD, 0,
		     map_fd),
		INSN(0, 0, 0, 0, 0),
		INSN(BPF_ST | BPF_W | BPF_MEM, BPF_REG_10, 0, -4, 0),
		INSN(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_2, BPF_REG_10, 0, 0),
		INSN(BPF_ALU64 | BPF_ADD | BPF_K, BPF_REG_2, 0, 0, -4),
		INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
		INSN(BPF_JMP | BPF_JEQ | BPF_K, BPF_REG_0, 0, 2, 0),
		INSN(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_1, 0, 0, 1),
		INSN(BPF_STX | BPF_DW | BPF_ATOMIC, BPF_REG_0, BPF_REG_1, 0,
		     BPF_ADD),
		INSN(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_0, 0, 0, 0),
		INSN(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
	};
	char log[65536] = {};

	memset(&a, 0, sizeof(a));
	a.prog_type = BPF_PROG_TYPE_KPROBE;
	a.expected_attach_type = BPF_TRACE_UPROBE_MULTI;
	a.insn_cnt = ARRAY_SIZE(p);
	a.insns = (uintptr_t)p;
	a.license = (uintptr_t)"GPL";
	a.log_buf = (uintptr_t)log;
	a.log_size = sizeof(log);
	a.log_level = 1;
	prog_fd = bpf_call(BPF_PROG_LOAD, &a);
	if (prog_fd < 0)
		fprintf(stderr, "Verifier: %s\n", log);
	CHECK(prog_fd >= 0);
}

static int attach(pid_t pid, void *address, uint32_t flags, const char *path)
{
	uint64_t offset = (uintptr_t)address;
	union bpf_attr a = {};

	a.link_create.prog_fd = prog_fd;
	a.link_create.attach_type = BPF_TRACE_UPROBE_MULTI;
	a.link_create.uprobe_multi.flags = flags;
	a.link_create.uprobe_multi.pid = pid;
	a.link_create.uprobe_multi.cnt = 1;
	a.link_create.uprobe_multi.offsets = (uintptr_t)&offset;
	a.link_create.uprobe_multi.path = (uintptr_t)path;
	return bpf_call(BPF_LINK_CREATE, &a);
}

static int attach_many(pid_t pid, uint64_t *addresses, uint32_t count)
{
	union bpf_attr a = {};

	a.link_create.prog_fd = prog_fd;
	a.link_create.attach_type = BPF_TRACE_UPROBE_MULTI;
	a.link_create.uprobe_multi.flags = BPF_F_UPROBE_MULTI_APROBE;
	a.link_create.uprobe_multi.pid = pid;
	a.link_create.uprobe_multi.cnt = count;
	a.link_create.uprobe_multi.offsets = (uintptr_t)addresses;
	return bpf_call(BPF_LINK_CREATE, &a);
}

static unsigned char *code_create(int flags)
{
	unsigned char *p =
		mmap(NULL, 4096, PROT_READ | PROT_WRITE, flags, -1, 0);
	CHECK(p != MAP_FAILED);
	memcpy(p, original, sizeof(original));
	CHECK(mprotect(p, 4096, PROT_READ | PROT_EXEC) == 0);
	return p;
}

static void child_ok(pid_t child)
{
	int status;

	CHECK(waitpid(child, &status, 0) == child);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void basic_and_fork(void)
{
	unsigned char *p = code_create(MAP_PRIVATE | MAP_ANONYMOUS);
	code_fn fn = (code_fn)p;
	uint64_t before = hits();
	int fd = attach(getpid(), p, BPF_F_UPROBE_MULTI_APROBE, NULL);

	CHECK(fd >= 0);
	CHECK(p[0] == 0xcc);
	CHECK(fn(5) == 12);
	CHECK(hits() == before + 1);
	PASS("entry hit and displaced MOV execute correctly");
	pid_t child = fork();

	CHECK(child >= 0);
	if (!child)
		_exit(p[0] == original[0] && fn(9) == 16 ? 0 : 1);
	child_ok(child);
	CHECK(hits() == before + 1);
	CHECK(fn(9) == 16);
	CHECK(hits() == before + 2);
	PASS("fork child has original instruction and no inherited callback");
	int fd2 = attach(getpid(), p, BPF_F_UPROBE_MULTI_APROBE, NULL);

	CHECK(fd2 >= 0);
	CHECK(fn(1) == 8);
	CHECK(hits() == before + 4);
	close(fd2);
	CHECK(p[0] == 0xcc);
	CHECK(fn(1) == 8);
	CHECK(hits() == before + 5);
	PASS("multiple consumers retain the breakpoint until last detach");
	close(fd);
	CHECK(memcmp(p, original, sizeof(original)) == 0);
	CHECK(fn(5) == 12);
	CHECK(hits() == before + 5);
	PASS("last detach restores bytes and stops callbacks");
	fd = attach(getpid(), p + 2, BPF_F_UPROBE_MULTI_APROBE, NULL);
	CHECK(fd >= 0);
	CHECK(fn(3) == 10);
	CHECK(hits() == before + 6);
	close(fd);
	CHECK(memcmp(p, original, sizeof(original)) == 0);
	PASS("probe at a non-entry instruction preserves ADD semantics");
	munmap(p, 4096);
}

static void reject_bad_mappings(void)
{
	unsigned char *p = code_create(MAP_PRIVATE | MAP_ANONYMOUS);

	CHECK(mprotect(p, 4096, PROT_READ | PROT_WRITE | PROT_EXEC) == 0);
	int writable = attach(getpid(), p, BPF_F_UPROBE_MULTI_APROBE, NULL);

	CHECK(writable >= 0);
	uint64_t before = hits();

	CHECK(((code_fn)p)(1) == 8);
	CHECK(hits() == before + 1);
	close(writable);
	CHECK(memcmp(p, original, sizeof(original)) == 0);
	CHECK(mprotect(p, 4096, PROT_READ | PROT_EXEC) == 0);
	CHECK(attach(getpid(), p,
		     BPF_F_UPROBE_MULTI_APROBE | BPF_F_UPROBE_MULTI_RETURN,
		     NULL) < 0);
	CHECK(attach(getpid(), p, BPF_F_UPROBE_MULTI_APROBE | (1U << 3), NULL) <
	      0);
	CHECK(attach(0, p, BPF_F_UPROBE_MULTI_APROBE, NULL) < 0);
	CHECK(attach(getpid(), p + 4095, BPF_F_UPROBE_MULTI_APROBE, NULL) < 0);
	CHECK(mprotect(p, 4096, PROT_NONE) == 0);
	CHECK(attach(getpid(), p, BPF_F_UPROBE_MULTI_APROBE, NULL) < 0);
	munmap(p, 4096);
	p = code_create(MAP_SHARED | MAP_ANONYMOUS);
	CHECK(attach(getpid(), p, BPF_F_UPROBE_MULTI_APROBE, NULL) < 0);
	CHECK(p[0] == original[0]);
	munmap(p, 4096);
	PASS("RWX code works; invalid mapping and attachment options are rejected");
}

static void pc_relative_instructions(void)
{
	unsigned char *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	CHECK(p != MAP_FAILED);
	unsigned char load[] = { 0x8b, 0x05, 0x7a, 0, 0, 0, 0xc3 };

	memcpy(p, load, sizeof(load));
	*(int *)(p + 128) = 12345;
	CHECK(mprotect(p, 4096, PROT_READ | PROT_EXEC) == 0);
	uint64_t before = hits();
	int fd = attach(getpid(), p, BPF_F_UPROBE_MULTI_APROBE, NULL);

	CHECK(fd >= 0);
	CHECK(((code_fn)p)(0) == 12345);
	CHECK(hits() == before + 1);
	close(fd);
	CHECK(memcmp(p, load, sizeof(load)) == 0);
	CHECK(mprotect(p, 4096, PROT_READ | PROT_WRITE) == 0);
	unsigned char call[] = { 0xe8, 0x7b, 0, 0, 0, 0xc3 };
	unsigned char callee[] = { 0xb8, 42, 0, 0, 0, 0xc3 };

	memcpy(p, call, sizeof(call));
	memcpy(p + 128, callee, sizeof(callee));
	CHECK(mprotect(p, 4096, PROT_READ | PROT_EXEC) == 0);
	fd = attach(getpid(), p, BPF_F_UPROBE_MULTI_APROBE, NULL);
	CHECK(fd >= 0);
	CHECK(((code_fn)p)(0) == 42);
	CHECK(hits() == before + 2);
	close(fd);
	CHECK(memcmp(p, call, sizeof(call)) == 0);
	munmap(p, 4096);
	PASS("RIP-relative load and displaced CALL preserve address and return semantics");
}

static void move_mapping(void)
{
	unsigned char *p = code_create(MAP_PRIVATE | MAP_ANONYMOUS);
	void *dest =
		mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	CHECK(dest != MAP_FAILED);
	CHECK(munmap(dest, 4096) == 0);
	int fd = attach(getpid(), p, BPF_F_UPROBE_MULTI_APROBE, NULL);

	CHECK(fd >= 0);
	uint64_t before = hits();
	unsigned char *moved =
		mremap(p, 4096, 4096, MREMAP_MAYMOVE | MREMAP_FIXED, dest);
	CHECK(moved == dest);
	CHECK(moved[0] == original[0]);
	CHECK(((code_fn)moved)(4) == 11);
	CHECK(hits() == before);
	close(fd);
	munmap(moved, 4096);
	PASS("mremap retires the old address without leaving an orphan breakpoint");
}

static void reuse_address(void)
{
	unsigned char *p = code_create(MAP_PRIVATE | MAP_ANONYMOUS);
	uint64_t before = hits();
	int fd = attach(getpid(), p, BPF_F_UPROBE_MULTI_APROBE, NULL);

	CHECK(fd >= 0);
	CHECK(((code_fn)p)(1) == 8);
	CHECK(hits() == before + 1);
	CHECK(munmap(p, 4096) == 0);
	CHECK(mmap(p, 4096, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) == p);
	memcpy(p, original, sizeof(original));
	p[4] = 99;
	CHECK(mprotect(p, 4096, PROT_READ | PROT_EXEC) == 0);
	CHECK(((code_fn)p)(1) == 100);
	CHECK(hits() == before + 1);
	int fresh = attach(getpid(), p, BPF_F_UPROBE_MULTI_APROBE, NULL);

	CHECK(fresh >= 0);
	CHECK(((code_fn)p)(1) == 100);
	CHECK(hits() == before + 2);
	close(fd);
	CHECK(p[0] == 0xcc && p[4] == 99);
	CHECK(((code_fn)p)(1) == 100);
	CHECK(hits() == before + 3);
	close(fresh);
	CHECK(p[0] == original[0] && p[4] == 99);
	munmap(p, 4096);
	PASS("unmap retires old attachment and address reuse captures new instruction");
}

static void writable_transition(void)
{
	unsigned char *p = code_create(MAP_PRIVATE | MAP_ANONYMOUS);
	int fd = attach(getpid(), p, BPF_F_UPROBE_MULTI_APROBE, NULL);

	CHECK(fd >= 0);
	uint64_t before = hits();

	CHECK(mprotect(p, 4096, PROT_READ | PROT_WRITE) == 0);
	CHECK(memcmp(p, original, sizeof(original)) == 0);
	p[4] = 88;
	CHECK(mprotect(p, 4096, PROT_READ | PROT_EXEC) == 0);
	int fresh = attach(getpid(), p, BPF_F_UPROBE_MULTI_APROBE, NULL);

	CHECK(fresh >= 0);
	close(fd);
	CHECK(p[0] == 0xcc);
	CHECK(((code_fn)p)(1) == 89);
	CHECK(hits() == before + 1);
	close(fresh);
	CHECK(p[0] == original[0] && p[4] == 88);
	munmap(p, 4096);
	PASS("making code writable disarms before mutation and permits fresh attachment");
}

static void batch_rollback_and_info(void)
{
	unsigned char *p = code_create(MAP_PRIVATE | MAP_ANONYMOUS);
	uint64_t addresses[] = { (uintptr_t)p, (uintptr_t)p + 4095 };
	uint64_t before = hits();

	CHECK(attach_many(getpid(), addresses, 2) < 0);
	CHECK(memcmp(p, original, sizeof(original)) == 0);
	CHECK(((code_fn)p)(1) == 8);
	CHECK(hits() == before);
	addresses[1] = (uintptr_t)p + 2;
	int fd = attach_many(getpid(), addresses, 2);

	CHECK(fd >= 0);
	CHECK(((code_fn)p)(1) == 8);
	CHECK(hits() == before + 2);
	struct bpf_link_info info = {};
	union bpf_attr a = { .info = { .bpf_fd = fd,
				       .info_len = sizeof(info),
				       .info = (uintptr_t)&info } };
	CHECK(bpf_call(BPF_OBJ_GET_INFO_BY_FD, &a) == 0);
	CHECK(info.type == BPF_LINK_TYPE_UPROBE_MULTI);
	CHECK(info.uprobe_multi.flags == BPF_F_UPROBE_MULTI_APROBE);
	CHECK(info.uprobe_multi.count == 2 &&
	      info.uprobe_multi.pid == (uint32_t)getpid());
	CHECK(info.uprobe_multi.path_size == 0);
	uint64_t reported[2] = {};

	info.uprobe_multi.count = 2;
	info.uprobe_multi.offsets = (uintptr_t)reported;
	CHECK(bpf_call(BPF_OBJ_GET_INFO_BY_FD, &a) == 0);
	CHECK(reported[0] == addresses[0] && reported[1] == addresses[1]);
	close(fd);
	CHECK(memcmp(p, original, sizeof(original)) == 0);
	munmap(p, 4096);
	PASS("multi-address partial failure rolls back; link info reports address attachment");
}

static void permission_check(void)
{
	int ready[2], done[2];

	CHECK(pipe(ready) == 0 && pipe(done) == 0);
	unsigned char *p = code_create(MAP_PRIVATE | MAP_ANONYMOUS);
	pid_t child = fork();

	CHECK(child >= 0);
	if (!child) {
		close(ready[0]);
		close(done[1]);
		if (setgid(65534) || setuid(65534))
			_exit(2);
		if (write(ready[1], "x", 1) != 1)
			_exit(3);
		char c;

		if (read(done[0], &c, 1) != 1)
			_exit(4);
		_exit(((code_fn)p)(1) == 8 ? 0 : 5);
	}
	close(ready[1]);
	close(done[0]);
	char c;

	CHECK(read(ready[0], &c, 1) == 1);
	struct __user_cap_header_struct header = {
		.version = _LINUX_CAPABILITY_VERSION_3
	};
	struct __user_cap_data_struct saved[2], reduced[2];

	CHECK(syscall(SYS_capget, &header, saved) == 0);
	memcpy(reduced, saved, sizeof(saved));
	reduced[CAP_SYS_PTRACE / 32].effective &=
		~(1U << (CAP_SYS_PTRACE % 32));
	CHECK(syscall(SYS_capset, &header, reduced) == 0);
	int fd = attach(child, p, BPF_F_UPROBE_MULTI_APROBE, NULL);
	int denied = errno;

	CHECK(syscall(SYS_capset, &header, saved) == 0);
	CHECK(fd < 0 && (denied == EPERM || denied == EACCES));
	uint64_t before = hits();

	fd = attach(child, p, BPF_F_UPROBE_MULTI_APROBE, NULL);
	CHECK(fd >= 0);
	CHECK(write(done[1], "x", 1) == 1);
	child_ok(child);
	CHECK(hits() == before + 1);
	close(fd);
	close(ready[0]);
	close(done[1]);
	munmap(p, 4096);
	PASS("ptrace authorization denies other UID without CAP_SYS_PTRACE");
}

static void external_target(int do_exec)
{
	int cmd[2], reply[2];

	CHECK(pipe(cmd) == 0 && pipe(reply) == 0);
	unsigned char *p = code_create(MAP_PRIVATE | MAP_ANONYMOUS);
	pid_t child = fork();

	CHECK(child >= 0);
	if (!child) {
		close(cmd[1]);
		close(reply[0]);
		char c;

		if (read(cmd[0], &c, 1) != 1)
			_exit(2);
		int result = ((code_fn)p)(13);

		if (write(reply[1], &result, sizeof(result)) != sizeof(result))
			_exit(3);
		if (do_exec)
			execl("/proc/self/exe", "test_aprobes", "--exec-child",
			      NULL);
		_exit(result == 20 ? 0 : 4);
	}
	close(cmd[0]);
	close(reply[1]);
	uint64_t before = hits();
	int fd = attach(child, p, BPF_F_UPROBE_MULTI_APROBE, NULL);

	CHECK(fd >= 0);
	CHECK(p[0] == original[0]);
	CHECK(((code_fn)p)(13) == 20);
	CHECK(hits() == before);
	CHECK(write(cmd[1], "x", 1) == 1);
	int result = 0;

	CHECK(read(reply[0], &result, sizeof(result)) == sizeof(result) &&
	      result == 20);
	child_ok(child);
	CHECK(hits() == before + 1);
	close(fd);
	close(cmd[1]);
	close(reply[0]);
	munmap(p, 4096);
	PASS(do_exec ?
		     "exec and target exit leave retained link safely detachable" :
		     "external target isolated from same-address parent; exit cleanup safe");
}

static _Atomic int running, errors;
static code_fn threaded_fn;
static void *worker(void *unused)
{
	(void)unused;
	while (atomic_load(&running))
		if (threaded_fn(17) != 24)
			atomic_fetch_add(&errors, 1);
	return NULL;
}

static void concurrent_detach(void)
{
	unsigned char *p = code_create(MAP_PRIVATE | MAP_ANONYMOUS);

	threaded_fn = (code_fn)p;
	atomic_store(&running, 1);
	pthread_t threads[4];

	for (int i = 0; i < 4; i++)
		CHECK(pthread_create(&threads[i], NULL, worker, NULL) == 0);
	for (int i = 0; i < 40; i++) {
		int fd = attach(getpid(), p, BPF_F_UPROBE_MULTI_APROBE, NULL);

		CHECK(fd >= 0);
		usleep(1000);
		close(fd);
	}
	atomic_store(&running, 0);
	for (int i = 0; i < 4; i++)
		CHECK(pthread_join(threads[i], NULL) == 0);
	CHECK(atomic_load(&errors) == 0);
	CHECK(memcmp(p, original, sizeof(original)) == 0);
	munmap(p, 4096);
	PASS("four executing threads survive repeated attach and detach");
}

int file_target(int x)
{
	asm volatile("" ::: "memory");
	return x + 11;
}

static void file_uprobe_regression(void)
{
	FILE *f = fopen("/proc/self/maps", "r");

	CHECK(f != NULL);
	char line[1024];
	unsigned long start, end, off, offset = 0;

	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "%lx-%lx %*s %lx", &start, &end, &off) == 3 &&
		    (uintptr_t)file_target >= start &&
		    (uintptr_t)file_target < end) {
			offset = off + (uintptr_t)file_target - start;
			break;
		}
	}
	fclose(f);
	CHECK(offset != 0);
	uint64_t before = hits();
	char path[PATH_MAX];
	ssize_t n = readlink("/proc/self/exe", path, sizeof(path) - 1);

	CHECK(n > 0);
	path[n] = 0;
	int fd = attach(getpid(), (void *)offset, 0, path);

	CHECK(fd >= 0);
	code_fn fn = file_target;

	asm volatile("" : "+r"(fn));

	CHECK(fn(3) == 14);
	CHECK(hits() == before + 1);
	close(fd);
	CHECK(fn(3) == 14);
	CHECK(hits() == before + 1);
	PASS("ordinary file-backed uprobes still work");
}

static void independent_clients(void)
{
	unsigned char *p = code_create(MAP_PRIVATE | MAP_ANONYMOUS);
	int commands[2], replies[2];

	CHECK(pipe(commands) == 0 && pipe(replies) == 0);
	int first = attach(getpid(), p, BPF_F_UPROBE_MULTI_APROBE, NULL);

	CHECK(first >= 0);
	pid_t target = getpid();
	pid_t tracer = fork();

	CHECK(tracer >= 0);
	if (!tracer) {
		close(first);
		close(commands[1]);
		close(replies[0]);
		int second = attach(target, p, BPF_F_UPROBE_MULTI_APROBE, NULL);

		if (second < 0 || write(replies[1], "x", 1) != 1)
			_exit(2);
		char c;

		if (read(commands[0], &c, 1) != 1)
			_exit(3);
		close(second);
		_exit(0);
	}
	close(commands[0]);
	close(replies[1]);
	char c;

	CHECK(read(replies[0], &c, 1) == 1);
	uint64_t before = hits();

	CHECK(((code_fn)p)(5) == 12);
	CHECK(hits() == before + 2);
	close(first);
	CHECK(p[0] == 0xcc);
	CHECK(((code_fn)p)(5) == 12);
	CHECK(hits() == before + 3);
	CHECK(write(commands[1], "x", 1) == 1);
	child_ok(tracer);
	CHECK(memcmp(p, original, sizeof(original)) == 0);
	close(commands[1]);
	close(replies[0]);
	munmap(p, 4096);
	PASS("detaching one tracing process preserves another client's breakpoint");
}

static void new_instruction(void)
{
	unsigned char replacement[] = { 0x8d, 0x47, 32, 0xc3 };
	unsigned char *p = code_create(MAP_PRIVATE | MAP_ANONYMOUS);
	int old = attach(getpid(), p, BPF_F_UPROBE_MULTI_APROBE, NULL);

	CHECK(old >= 0);
	CHECK(mprotect(p, 4096, PROT_READ | PROT_WRITE) == 0);
	memcpy(p, replacement, sizeof(replacement));
	CHECK(mprotect(p, 4096, PROT_READ | PROT_EXEC) == 0);
	int fresh = attach(getpid(), p, BPF_F_UPROBE_MULTI_APROBE, NULL);

	CHECK(fresh >= 0);
	close(old);
	CHECK(p[0] == 0xcc);
	uint64_t before = hits();

	CHECK(((code_fn)p)(9) == 41);
	CHECK(hits() == before + 1);
	close(fresh);
	CHECK(memcmp(p, replacement, sizeof(replacement)) == 0);
	munmap(p, 4096);
	PASS("a fresh registration decodes new bytes and an old link cannot overwrite them");
}

static int shared_mm_child(void *arg)
{
	return ((code_fn)arg)(9) == 16 ? 0 : 1;
}

static void shared_address_space(void)
{
	unsigned char *p = code_create(MAP_PRIVATE | MAP_ANONYMOUS);
	void *stack = mmap(NULL, 65536, PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	CHECK(stack != MAP_FAILED);
	int fd = attach(getpid(), p, BPF_F_UPROBE_MULTI_APROBE, NULL);

	CHECK(fd >= 0);
	uint64_t before = hits();
	pid_t child = clone(shared_mm_child, (char *)stack + 65536,
			    CLONE_VM | SIGCHLD, p);
	CHECK(child >= 0);
	child_ok(child);
	CHECK(hits() == before && p[0] == 0xcc);
	CHECK(((code_fn)p)(9) == 16 && hits() == before + 1);
	close(fd);
	munmap(stack, 65536);
	munmap(p, 4096);
	PASS("CLONE_VM task executes the breakpoint correctly without matching the TGID filter");
}

static void uffd_move(void)
{
	int uffd = syscall(__NR_userfaultfd,
			   O_CLOEXEC | O_NONBLOCK | UFFD_USER_MODE_ONLY);
	if (uffd < 0 && (errno == ENOSYS || errno == EPERM)) {
		tests++;
		ksft_test_result_skip("userfaultfd unavailable\n");
		return;
	}
	CHECK(uffd >= 0);
	struct uffdio_api api = { .api = UFFD_API,
				  .features = UFFD_FEATURE_MOVE };
	if (ioctl(uffd, UFFDIO_API, &api) < 0 && errno == EINVAL) {
		close(uffd);
		tests++;
		ksft_test_result_skip("UFFDIO_MOVE unavailable\n");
		return;
	}
	CHECK(api.features & UFFD_FEATURE_MOVE);
	unsigned char *src = code_create(MAP_PRIVATE | MAP_ANONYMOUS);

	CHECK(mprotect(src, 4096, PROT_READ | PROT_WRITE | PROT_EXEC) == 0);
	void *dst = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
			 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	CHECK(dst != MAP_FAILED);
	struct uffdio_register registration = {
		.range = { .start = (uintptr_t)dst, .len = 4096 },
		.mode = UFFDIO_REGISTER_MODE_MISSING
	};
	CHECK(ioctl(uffd, UFFDIO_REGISTER, &registration) == 0);
	int fd = attach(getpid(), src, BPF_F_UPROBE_MULTI_APROBE, NULL);

	CHECK(fd >= 0);
	struct uffdio_move move = { .src = (uintptr_t)src,
				    .dst = (uintptr_t)dst,
				    .len = 4096 };
	errno = 0;
	CHECK(ioctl(uffd, UFFDIO_MOVE, &move) < 0 && errno == EBUSY);
	CHECK(src[0] == 0xcc);
	uint64_t before = hits();

	CHECK(((code_fn)src)(3) == 10 && hits() == before + 1);
	close(fd);
	CHECK(src[0] == original[0]);
	CHECK(ioctl(uffd, UFFDIO_MOVE, &move) == 0 && move.move == 4096);
	CHECK(memcmp(dst, original, sizeof(original)) == 0);
	CHECK(((code_fn)dst)(4) == 11 && hits() == before + 1);
	close(uffd);
	munmap(src, 4096);
	munmap(dst, 4096);
	PASS("UFFDIO_MOVE cannot relocate an installed breakpoint and succeeds after detach");
}

static void allocation_limit(void)
{
	enum { sites = 4096, batch = 64, groups = sites / batch };
	const size_t length = (sites + 1) * 16 + 4096;
	unsigned char *p = mmap(NULL, length, PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	CHECK(p != MAP_FAILED);
	memset(p, 0x90, length);
	CHECK(mprotect(p, length, PROT_READ | PROT_EXEC) == 0);
	int links[groups];

	for (int i = 0; i < groups; i++) {
		uint64_t addresses[batch];

		for (int j = 0; j < batch; j++)
			addresses[j] = (uintptr_t)p + (i * batch + j) * 16;
		int retry;

		for (retry = 0; retry < 200; retry++) {
			links[i] = attach_many(getpid(), addresses, batch);
			if (links[i] >= 0 || errno != E2BIG)
				break;
			usleep(10000);
		}
		CHECK(links[i] >= 0);
	}
	int duplicate = attach(getpid(), p, BPF_F_UPROBE_MULTI_APROBE, NULL);

	CHECK(duplicate >= 0);
	close(duplicate);
	CHECK(p[0] == 0xcc);
	errno = 0;
	CHECK(attach(getpid(), p + sites * 16, BPF_F_UPROBE_MULTI_APROBE,
		     NULL) < 0 &&
	      errno == E2BIG);
	for (int i = 0; i < groups; i++)
		close(links[i]);
	for (int i = 0; i < sites; i++)
		CHECK(p[i * 16] == 0x90);
	int fresh = -1;

	for (int i = 0; i < 300; i++) {
		fresh = attach(getpid(), p + sites * 16,
			       BPF_F_UPROBE_MULTI_APROBE, NULL);
		if (fresh >= 0 || errno != E2BIG)
			break;
		usleep(10000);
	}
	CHECK(fresh >= 0);
	close(fresh);
	munmap(p, length);
	PASS("per-mm allocation limit includes deferred sites and permits reuse after reclamation");
}

int main(int argc, char **argv)
{
	if (argc == 2 && !strcmp(argv[1], "--exec-child"))
		return 0;
	setbuf(stdout, NULL);
	ksft_print_header();
	if (geteuid())
		ksft_exit_skip("requires privileged BPF and ptrace access\n");
	bool one = argc == 2 && (!strcmp(argv[1], "--uffd-move") ||
				 !strcmp(argv[1], "--allocation-limit"));
	ksft_set_plan(one ? 1 : 21);
	setup_bpf();
	unsigned char *probe = code_create(MAP_PRIVATE | MAP_ANONYMOUS);
	int feature = attach(getpid(), probe, BPF_F_UPROBE_MULTI_APROBE, NULL);

	if (feature < 0 && (errno == EINVAL || errno == EOPNOTSUPP))
		ksft_exit_skip("anonymous address probes unavailable\n");
	CHECK(feature >= 0);
	close(feature);
	munmap(probe, 4096);
	if (argc == 2 && !strcmp(argv[1], "--uffd-move")) {
		uffd_move();
	} else if (argc == 2 && !strcmp(argv[1], "--allocation-limit")) {
		allocation_limit();
	} else {
		basic_and_fork();
		reject_bad_mappings();
		pc_relative_instructions();
		reuse_address();
		move_mapping();
		writable_transition();
		batch_rollback_and_info();
		permission_check();
		external_target(0);
		external_target(1);
		concurrent_detach();
		file_uprobe_regression();
		independent_clients();
		new_instruction();
		shared_address_space();
		uffd_move();
		allocation_limit();
	}
	printf("# APROBES_TEST_PASS tests=%u hits=%llu\n", tests,
	       (unsigned long long)hits());
	close(prog_fd);
	close(map_fd);
	ksft_exit_pass();
}

#else
int main(void)
{
	ksft_exit_skip("x86-64 instruction fixtures required\n");
}
#endif
