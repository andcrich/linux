// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2026 Isovalent, Inc.
public class AprobeHotSpot {
    static { System.load("/libaprobe-hotspot.so"); }
    private static native void prepare();
    private static native void complete();
    static volatile long sink;
    public static int target(int x) { return x + 7; }
    public static void main(String[] args) {
        for (int i = 0; i < 100000; i++) sink += target(i);
        prepare();
        long sum = 0;
        for (int i = 0; i < 10000; i++) sum += target(i);
        if (sum != 50065000L) throw new AssertionError("wrong compiled result: " + sum);
        System.out.println("HOTSPOT_COMPILED_RESULT=" + sum);
        complete();
        System.out.println("HOTSPOT_TEST_DONE");
    }
}
