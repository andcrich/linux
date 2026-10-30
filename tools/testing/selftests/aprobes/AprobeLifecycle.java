// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2026 Isovalent, Inc.
import java.io.InputStream;
import java.lang.ref.WeakReference;
import java.lang.reflect.Method;
import java.util.ArrayList;
public class AprobeLifecycle {
    public static class Payload {
        public interface Op { int apply(int x); }
        public static class Add implements Op { public int apply(int x) { return x + 7; } }
        public static class Mul implements Op { public int apply(int x) { return x * 3; } }
        static Op op = new Add();
        public static int target(int x) { return op.apply(x); }
        public static void change() { op = new Mul(); }
    }
    static class Loader extends ClassLoader {
        Loader() { super(AprobeLifecycle.class.getClassLoader()); }
        protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
            if (!name.startsWith("AprobeLifecycle$Payload")) return super.loadClass(name, resolve);
            Class<?> c = findLoadedClass(name);
            if (c == null) {
                try (InputStream in = getParent().getResourceAsStream(name.replace('.', '/') + ".class")) {
                    byte[] bytes = in.readAllBytes();
                    c = defineClass(name, bytes, 0, bytes.length);
                } catch (Exception e) { throw new ClassNotFoundException(name, e); }
            }
            if (resolve) resolveClass(c);
            return c;
        }
    }
    static volatile long sink;
    static WeakReference<ClassLoader> batch() throws Exception {
        Loader loader = new Loader();
        Class<?> c = loader.loadClass("AprobeLifecycle$Payload");
        Method target = c.getMethod("target", int.class);
        for (int i = 0; i < 12000; i++) {
            int actual = (int) target.invoke(null, i);
            if (actual != i + 7) throw new AssertionError("bad Add result " + actual);
            sink += actual;
        }
        c.getMethod("change").invoke(null);
        for (int i = 0; i < 12000; i++) {
            int actual = (int) target.invoke(null, i);
            if (actual != i * 3) throw new AssertionError("bad Mul result " + actual);
            sink += actual;
        }
        return new WeakReference<>(loader);
    }
    public static void main(String[] args) throws Exception {
        ArrayList<WeakReference<ClassLoader>> refs = new ArrayList<>();
        for (int i = 0; i < 24; i++) {
            refs.add(batch());
            System.gc(); Thread.sleep(40);
        }
        for (int i = 0; i < 8; i++) { System.gc(); Thread.sleep(100); }
        long unloaded = refs.stream().filter(r -> r.get() == null).count();
        if (unloaded != 24) throw new AssertionError("loaders collected: " + unloaded);
        System.out.println("HOTSPOT_LIFECYCLE_DONE unloaded=" + unloaded + " checksum=" + sink);
    }
}
