// Taint that never touches a variable assignment.
//
// `sb.append(x)` and `list.add(x)` return void or a boolean - the value is
// carried INSIDE the object. `append` and `format` were both already in the
// propagator list and caught nothing, because propagators move taint through a
// RETURN VALUE and there is no useful return here.
//
// The second half is rarer and stranger: `pb.start()` is the dangerous act and
// it takes no arguments at all. The payload went in on an earlier line.
import java.sql.*;
import java.util.*;
import javax.servlet.http.*;

public class ReceiverState {

    public void builtWithStringBuilder(HttpServletRequest request, Connection conn)
            throws Exception {
        String param = request.getParameter("id");
        StringBuilder sb = new StringBuilder();
        sb.append("SELECT * FROM users WHERE id = ");
        sb.append(param);
        Statement stmt = conn.createStatement();
        // EXPECT-FLOW sql-injection
        stmt.executeQuery(sb.toString());
    }

    public void loadedIntoAListThenRun(HttpServletRequest request) throws Exception {
        String param = request.getHeader("h");
        List<String> argList = new ArrayList<String>();
        argList.add("sh");
        argList.add("-c");
        argList.add("echo " + param);
        ProcessBuilder pb = new ProcessBuilder();
        pb.command(argList);
        // EXPECT-FLOW command-injection
        Process p = pb.start();
    }
}
