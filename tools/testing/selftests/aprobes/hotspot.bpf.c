// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2026 Isovalent, Inc.
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "hotspot-layout.h"
#include "hotspot-stats.h"

extern int bpf_aprobe_attach(__u64 address, __u64 cookie) __ksym;
extern int bpf_aprobe_detach(__u64 address, __u64 length) __ksym;
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct hotspot_stats);
} stats SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, struct generation);
} history SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u64);
	__type(value, __u64);
} live SEC(".maps");

static __always_inline int read64(__u64 base, __u32 off, __u64 *value)
{
	return bpf_probe_read_user(value, sizeof(*value), (void *)(base + off));
}

static __always_inline int selected(__u64 nm)
{
	__u64 method = 0, cm = 0, cp = 0, klass = 0, symbol = 0;
	__u16 index = 0, length = 0;
	int cp_length = 0;
	char name[sizeof("AprobeLifecycle$Payload") - 1], method_name[6];
	const char target[] = "AprobeLifecycle$Payload";
	if (read64(nm, NM_METHOD, &method) ||
	    read64(method, METHOD_CONST, &cm) || read64(cm, CONST_POOL, &cp) ||
	    read64(cp, CP_HOLDER, &klass) ||
	    read64(klass, KLASS_NAME, &symbol) ||
	    bpf_probe_read_user(&length, sizeof(length),
				(void *)(symbol + SYMBOL_LENGTH)))
		return -1;
	if (length != sizeof(name))
		return 0;
	if (bpf_probe_read_user(name, sizeof(name),
				(void *)(symbol + SYMBOL_BODY)))
		return -1;
#pragma unroll
	for (int i = 0; i < (int)sizeof(name); i++)
		if (name[i] != target[i])
			return 0;
	if (bpf_probe_read_user(&index, sizeof(index),
				(void *)(cm + CONST_NAME_INDEX)) ||
	    bpf_probe_read_user(&cp_length, sizeof(cp_length),
				(void *)(cp + CP_LENGTH)))
		return -1;
	if (!index || index >= cp_length ||
	    read64(cp, CP_SIZE + index * 8, &symbol) ||
	    bpf_probe_read_user(&length, sizeof(length),
				(void *)(symbol + SYMBOL_LENGTH)))
		return -1;
	if (length != sizeof(method_name))
		return 0;
	if (bpf_probe_read_user(method_name, sizeof(method_name),
				(void *)(symbol + SYMBOL_BODY)))
		return -1;
	return method_name[0] == 't' && method_name[1] == 'a' &&
	       method_name[2] == 'r' && method_name[3] == 'g' &&
	       method_name[4] == 'e' && method_name[5] == 't';
}

SEC("uprobe.multi.s")
int hotspot_lifecycle(struct pt_regs *ctx)
{
	__u32 zero = 0;
	struct hotspot_stats *s = bpf_map_lookup_elem(&stats, &zero);
	if (!s)
		return 0;
	__u64 event = bpf_get_attach_cookie(ctx);
	if (event & HIT_COOKIE) {
		struct generation *g = bpf_map_lookup_elem(&history, &event);
		if (!g || g->phase == FREE) {
			__sync_fetch_and_add(&s->stale_hits, 1);
			return 0;
		}
		__sync_fetch_and_add(&g->hits, 1);
		__sync_fetch_and_add(&s->hits, 1);
		return 0;
	}
	__u64 nm = (event == PUBLISH || event == OSR) ? PT_REGS_PARM2(ctx) :
							PT_REGS_PARM1(ctx);
	if (event == PUBLISH || event == OSR) {
		int match = selected(nm);
		if (match < 0) {
			__sync_fetch_and_add(&s->read_errors, 1);
			return 0;
		}
		if (!match)
			return 0;
		int code = 0, id = 0;
		__u16 verified = 0;
		__u8 level = 0;
		if (bpf_probe_read_user(&code, sizeof(code),
					(void *)(nm + CB_CODE)) ||
		    bpf_probe_read_user(&verified, sizeof(verified),
					(void *)(nm + NM_VERIFIED)) ||
		    bpf_probe_read_user(&id, sizeof(id),
					(void *)(nm + NM_COMPILE_ID)) ||
		    bpf_probe_read_user(&level, sizeof(level),
					(void *)(nm + NM_LEVEL))) {
			__sync_fetch_and_add(&s->read_errors, 1);
			return 0;
		}
		if (code <= 0 || id <= 0) {
			__sync_fetch_and_add(&s->errors, 1);
			return 0;
		}
		__u64 cookie = HIT_COOKIE | (__u32)id;
		__u64 entry = nm + code + verified;
		if (event == OSR && read64(nm, NM_OSR_ENTRY, &entry)) {
			__sync_fetch_and_add(&s->read_errors, 1);
			return 0;
		}
		struct generation g = { .nmethod = nm,
					.entry = entry,
					.cookie = cookie,
					.level = level };
		if (bpf_map_update_elem(&history, &cookie, &g, BPF_NOEXIST) ||
		    bpf_map_update_elem(&live, &nm, &cookie, BPF_NOEXIST)) {
			__sync_fetch_and_add(&s->errors, 1);
			return 0;
		}
		/* Exercise failure cleanup without a grace-period wait in a callback. */
		if (!s->publications && bpf_aprobe_attach(1, 0) != -22) {
			__sync_fetch_and_add(&s->errors, 1);
			return 0;
		}
		int ret = bpf_aprobe_attach(entry, cookie);
		if (ret) {
			__sync_fetch_and_add(&s->errors, 1);
			return 0;
		}
		__sync_fetch_and_add(&s->publications, 1);
		if (level == 4)
			__sync_fetch_and_add(&s->c2, 1);
		else
			__sync_fetch_and_add(&s->c1, 1);
		return 0;
	}
	__u64 *cookie = bpf_map_lookup_elem(&live, &nm);
	if (!cookie)
		return 0;
	__u64 key = *cookie;
	struct generation *g = bpf_map_lookup_elem(&history, &key);
	int size = 0;
	if (!g ||
	    bpf_probe_read_user(&size, sizeof(size), (void *)(nm + CB_SIZE)) ||
	    size <= 0) {
		__sync_fetch_and_add(&s->read_errors, 1);
		return 0;
	}
	int ret = bpf_aprobe_detach(nm, (__u32)size);
	if (ret < 0) {
		__sync_fetch_and_add(&s->errors, 1);
		return 0;
	}
	__sync_fetch_and_add(&s->removed, ret);
	g->phase = event;
	if (event == INVALIDATE)
		__sync_fetch_and_add(&s->invalidations, 1);
	if (event == UNLINK)
		__sync_fetch_and_add(&s->unloads, 1);
	if (event == FREE) {
		__sync_fetch_and_add(&s->frees, 1);
		bpf_map_delete_elem(&live, &nm);
	}
	return 0;
}
char LICENSE[] SEC("license") = "GPL";
