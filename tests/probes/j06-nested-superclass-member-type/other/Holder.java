package other;
public class Holder {
    public static class Base {
        public static class Utils {
            public static String forShell(String a) { return System.getenv("CMD"); }
        }
    }
}
