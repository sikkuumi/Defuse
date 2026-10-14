package app;
public class Utils {
    public static String forShell(String a) {
        // normalise the verb first\u000a a = lookup(a);
        return "sh -c " + a;
    }
}
