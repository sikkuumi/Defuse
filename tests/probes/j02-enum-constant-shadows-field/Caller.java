// j02-enum-constant-shadows-field: Inside the enum, `table` is its constant, whose toString() returns anything.
// j02: inside enum Kind, `table` is the enum constant Kind.table, whose toString() returns an env value; it shadows the outer constant field.
package app;
import java.sql.Statement;
public class Caller {
    private static final String table = "users";

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
