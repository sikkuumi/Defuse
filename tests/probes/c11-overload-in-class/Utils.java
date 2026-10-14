package app;
public class Utils {
    public static String forShell(String a) { return "sh -c " + a; }
    public static String forShell(CharSequence a) { return lookup(a.toString()); }
}
