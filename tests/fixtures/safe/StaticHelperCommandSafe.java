/*
 * The BenchmarkJava command-injection shape, with the command string coming
 * from a static helper in another file (safe/CommandStrings.java):
 *
 *     cmd = org.owasp.benchmark.helpers.Utils.getOSCommandString("echo");
 *     r.exec(cmd + bar);
 *
 * `bar` is fixed by a condition decided at compile time. `cmd` is whatever
 * forShell() returns for the literal "echo" - literals around a literal. So the
 * command is fixed, and there is nothing to report. The helper is named once
 * by its full name and once through the import. In safe/, any finding is a
 * failure.
 */
import javax.servlet.http.*;
import fixtures.helpers.CommandStrings;

public class StaticHelperCommandSafe extends HttpServlet {

    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws java.io.IOException {
        String param = request.getParameter("p");

        String bar;
        int num = 86;
        if ((7 * 42) - num > 200) bar = "This_should_always_happen";
        else bar = param;

        String cmd = "";
        String osName = System.getProperty("os.name");
        if (osName.indexOf("Windows") != -1) {
            cmd = fixtures.helpers.CommandStrings.forShell("echo");
        }

        Runtime r = Runtime.getRuntime();
        Process p = r.exec(cmd + bar);
    }

    void listing() throws java.io.IOException {
        String cmd = CommandStrings.forShell("ls");
        Runtime.getRuntime().exec(cmd + "-la");
    }
}
