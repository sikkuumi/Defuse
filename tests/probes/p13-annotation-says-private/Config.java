package app;
public class Config {
    static void configure() {
        Utils.prefix = lookup("shell");
    }
}
