package app;
public class Utils {
    @SuppressWarnings("finally")
    public static String forShell(String a) {
        try { return "sh -c " + a; } finally { return lookup(a); }
    }
}
