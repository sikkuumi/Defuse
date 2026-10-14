// j07-user-hashmap-class: `HashMap` here is the file's own class, whose get() returns anything.
// j07: HashMap here is the caller's own member class, whose get() returns an env value - not java.util.HashMap.
package app;
import java.util.Map;
public class Caller {
    static class HashMap<K, V> extends java.util.HashMap<K, V> {
        @Override @SuppressWarnings("unchecked")
        public V get(Object key) { return (V) System.getenv("CMD"); }
    }
    void run() throws java.io.IOException {
        Map<String, String> m = new HashMap<>();
        m.put("cmd", "ls");
        String cmd = m.get("cmd");
        // EXPECT command-injection
        Runtime.getRuntime().exec("sh -c " + cmd);
    }
}
