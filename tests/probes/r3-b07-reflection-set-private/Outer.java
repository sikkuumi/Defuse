// r3-b07-reflection-set-private: The held object is handed to reflection, which rewrites its private field.
public class Outer {
    static class Box {
        private String f = "safe";
        String get() { return f; }
    }
    void run(java.sql.Statement stmt) throws Exception {
        Box h = new Box();
        java.lang.reflect.Field fl = Box.class.getDeclaredField("f");
        fl.setAccessible(true);
        fl.set(h, lookup("p"));
        String bar = h.get();
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }
}
