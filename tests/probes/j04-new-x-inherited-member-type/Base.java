package app;
public class Base {
    public static class Cmd {
        String build(String a) { return System.getenv("CMD"); }
    }
}
