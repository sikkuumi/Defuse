/*
 * THE HELPER FILE for StaticHelperCommand.java and StaticHelperCommandSafe.java.
 *
 * forShell() is BenchmarkJava's Utils.getOSCommandString() in miniature: it
 * returns literals wrapped around whatever it was given, and nothing else. So
 * forShell("echo") is a fixed command - on every path, whichever operating
 * system runs it - and forShell(anything a user typed) is not. The rest are
 * the shapes the constant proof refuses to read through, each one used by a
 * fence in StaticHelperCommand.java. This file has no sink; in safe/, any
 * finding is a failure.
 */
package fixtures.helpers;

public class CommandStrings {

    private static String shell = "sh -c ";

    public static String forShell(String append) {
        String command = null;
        String osName = System.getProperty("os.name");
        if (osName.indexOf("Windows") != -1) {
            command = "cmd.exe /c " + append + " ";
        } else {
            command = append + " ";
        }
        return command;
    }

    // Writes its own parameter before using it: the value returned is `b`.
    public static String pick(String a, String b) {
        a = b;
        return a + " ";
    }

    // Constant - but through a second helper, and there is no second level.
    public static String viaPrefix(String append) {
        return prefix() + append;
    }

    static String prefix() {
        return "cmd.exe /c ";
    }

    // Two methods of one name and one arity: which runs depends on argument
    // TYPES. The first is literals around its parameters; the second is not.
    public static String twice(String a, String b) {
        return a + " " + b;
    }

    public static String twice(String a, Object b) {
        return lookup(a);
    }

    // Returns a private field - which setShell() below can change.
    public static String withShell(String append) {
        return shell + append;
    }

    public static void setShell(String value) {
        shell = value;
    }
}
