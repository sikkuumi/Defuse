// r3-a09-getandset-exec: a04 as a command injection.
public class Outer {
    static class Slot {
        private String f = "echo";
        String swap(String v) { String old = f; f = v; return old; }
    }
    void run(String[] args) throws Exception {
        Slot h = new Slot();
        h.swap(System.getenv("CMD"));
        String cmd = h.swap("ls");
        // EXPECT command-injection
        Runtime.getRuntime().exec("sh -c " + cmd);
    }
}
