import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InvalidClassException;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamException;
import java.io.Serializable;

/**
 * Proves log4j-unsafe-deserialization's sink is real: a Serializable class
 * whose readObject() performs an observable side effect stands in for a real
 * exploit gadget. This demonstrates the defining danger of CWE-502 -- code
 * runs *during* deserialization itself, before the caller can inspect or
 * reject the resulting type.
 */
class UnsafeDeserializationProof {

    /** Stand-in for a gadget: readObject() runs code, exactly like a real one. */
    static class Gadget implements Serializable {
        private static final long serialVersionUID = 1L;
        static volatile boolean sideEffectFired = false;

        private void readObject(java.io.ObjectInputStream in)
                throws IOException, ClassNotFoundException {
            in.defaultReadObject();
            sideEffectFired = true; // stands in for e.g. Runtime.exec(), file write, etc.
        }

        private Object writeReplace() throws ObjectStreamException {
            return this;
        }
    }

    private static int failed = 0;

    public static void main(String[] args) throws Exception {
        System.out.println("=== Unsafe deserialization: dynamic proof ===\n");

        byte[] payload = serialize(new Gadget());

        vulnerableStreamRunsTheGadget(payload);
        filteredStreamBlocksTheGadget(payload);

        System.out.println();
        if (failed > 0) {
            System.out.println(failed + " check(s) FAILED");
            System.exit(1);
        }
        System.out.println("All checks passed.");
    }

    private static byte[] serialize(Object o) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(o);
        }
        return bos.toByteArray();
    }

    /** CVE-2019-17571's shape: a bare ObjectInputStream over untrusted bytes. */
    private static void vulnerableStreamRunsTheGadget(byte[] payload) throws Exception {
        Gadget.sideEffectFired = false;

        // ruleid: log4j-unsafe-deserialization -- no filter, arbitrary readObject() runs
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(payload));
        ois.readObject();

        assertTrue("readObject() executed the gadget's side effect during deserialization "
                + "itself -- before any type check by the caller was possible",
                Gadget.sideEffectFired);
        System.out.println("  vulnerable: Gadget.sideEffectFired flipped to true purely from "
                + "calling readObject() -- this is what CVE-2019-17571-class bugs exploit.");
    }

    private static void filteredStreamBlocksTheGadget(byte[] payload) throws Exception {
        Gadget.sideEffectFired = false;

        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(payload));
        // ok: log4j-unsafe-deserialization -- filter denies the class by name
        ois.setObjectInputFilter(ObjectInputFilter.Config.createFilter(
                "!" + Gadget.class.getName() + ";maxdepth=10"));

        boolean threw = false;
        try {
            ois.readObject();
        } catch (InvalidClassException expected) {
            threw = true;
        }

        assertTrue("ObjectInputFilter rejected the Gadget class before it could be instantiated",
                threw);
        assertTrue("the gadget's side effect never fired", !Gadget.sideEffectFired);
        System.out.println("  guarded:    ObjectInputFilter threw InvalidClassException; "
                + "Gadget.sideEffectFired stayed false.");
    }

    private static void assertTrue(String what, boolean ok) {
        if (ok) {
            System.out.println("  [PASS] " + what);
        } else {
            failed++;
            System.out.println("  [FAIL] " + what);
        }
    }
}
