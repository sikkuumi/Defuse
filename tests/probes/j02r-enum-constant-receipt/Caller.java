// j02r-enum-constant-receipt: As j02, with a compile-time condition so the withdrawal leaves a receipt.
// j02r: inside enum Kind, `table` is the enum constant Kind.table, whose toString() returns an env value; it shadows the outer constant field.
package app;
import java.sql.Statement;
public class Caller {
    private static final String table = 1 > 0 ? "users" : "accounts";

    enum Kind {
        table {
            @Override public String toString() { return System.getenv("TABLE"); }
        },
        other;

        void run(Statement st) throws Exception {
            // EXPECT sql-injection
            st.execute("SELECT * FROM " + table);
        }
    }
}
