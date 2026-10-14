/*
 * The other side of OuterWriteFence.java: a field that is final, or private
 * and written nowhere but its declaration, holds its literal for good. Methods
 * that never touch them sit alongside, and so does a method with its OWN local
 * of a different field's name. In safe/, any finding is a failure.
 */
public class OuterConstantSafe {

    private static final String TABLE = "users";
    private static String order = "id";

    void list(java.sql.Statement stmt) throws Exception {
        stmt.execute("SELECT * FROM " + TABLE + " ORDER BY " + order);
    }

    void unrelated() {
        String name = "x";
        System.out.println(name);
    }
}
