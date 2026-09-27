/*
 * EVERY CASE HERE IS A REAL SQL INJECTION THAT THE CONSTANT FOLDER HID.
 *
 * The folder decides conditions like `num > 200` by asking what `num` holds.
 * Its rule was "if the function writes to `num` exactly once, that write is its
 * value". Each case below has exactly one `=` - and in each one the name holds
 * something else when the condition is read:
 *
 *   fromParameter     a parameter holds the caller's value BEFORE any `=`,
 *                     and the one `=` here might not run
 *   fromField         a field is not this function's to decide
 *   loopCounter       `i++` writes without an `=`
 *   incremented       so does `n++`
 *   readBeforeDeclaration
 *                     the one `=` declares a local `mode` - after the read,
 *                     which still sees the field
 *   blockLocalShadow  the one `=` declares a DIFFERENT `mode` inside a block;
 *                     the `mode` in the condition is the field
 *
 * The folder decided the branch, dropped the arm that reads `param`, and the SQL
 * rule then withdrew its own guess with a receipt calling the line "provably
 * constant". A miss, with a certificate.
 *
 * The rule now: one write that cannot be bypassed - a declaration, read inside
 * its own block after it runs - and no other kind of write at all.
 */
import javax.servlet.http.*;

public class FolderSoundness extends HttpServlet {

    int mode;

    void fromParameter(HttpServletRequest request, java.sql.Statement stmt, int num)
            throws Exception {
        String param = request.getParameter("p");
        if (param.isEmpty()) num = 500;
        String bar = num > 200 ? "safe" : param;
        // EXPECT-FLOW sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    void fromField(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        String param = request.getParameter("p");
        if (param.isEmpty()) mode = 500;
        String bar = mode > 200 ? "safe" : param;
        // EXPECT-FLOW sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    void loopCounter(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        String param = request.getParameter("p");
        for (int i = 0; i < 10; i++) {
            String bar = i > 5 ? param : "safe";
            // EXPECT-FLOW sql-injection
            stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
        }
    }

    void incremented(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        String param = request.getParameter("p");
        int n = 0;
        if (param.isEmpty()) n++;
        String bar = n > 0 ? param : "safe";
        // EXPECT-FLOW sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }

    // The declaration is real and unconditional - but it comes AFTER the read.
    // Until it runs, `mode` in this method is still the field.
    void readBeforeDeclaration(HttpServletRequest request, java.sql.Statement stmt)
            throws Exception {
        String param = request.getParameter("p");
        String bar = mode > 200 ? "safe" : param;
        // EXPECT-FLOW sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
        int mode = 500;
        System.out.println(mode);
    }

    void blockLocalShadow(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
        String param = request.getParameter("p");
        if (param.isEmpty()) {
            int mode = 500;
            System.out.println(mode);
        }
        String bar = mode > 200 ? "safe" : param;
        // EXPECT-FLOW sql-injection
        stmt.execute("SELECT * FROM t WHERE x = '" + bar + "'");
    }
}
