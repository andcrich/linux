/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright 2026 Isovalent, Inc. */
#ifndef APROBE_HOTSPOT_STATS_H
#define APROBE_HOTSPOT_STATS_H
#include <linux/types.h>
enum { PUBLISH = 1, OSR = 2, INVALIDATE = 3, UNLINK = 4, FREE = 5 };
#define HIT_COOKIE (1ULL << 63)
struct generation {
	__u64 nmethod, entry, cookie, hits;
	__u32 phase, level;
};
struct hotspot_stats {
	__u64 publications, hits, invalidations, unloads, frees, removed;
	__u64 errors, read_errors, stale_hits, c1, c2;
};
#endif
