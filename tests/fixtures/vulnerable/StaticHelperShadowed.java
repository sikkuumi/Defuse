/*
 * A VARIABLE NAMED LIKE THE CLASS HIDES THE CLASS.
 *
 * In Java, when a local variable and an imported class share a name, the
 * variable wins (JLS 6.4.2). So `CommandStrings.forShell("echo")` below is
 * Shell.forShell() - an instance method that returns anything - and not the
 * static helper in safe/CommandStrings.java that the import names.
 *
 * The check is deliberately blunt: any variable, parameter, field or type in
 * the file with the class's name, and no call through that name in this file
 * is read into another. That is why this fence has a file of its own.
 */
import fixtures.helpers.CommandStrings;

public class StaticHelperShadowed {

    void variableNamedLikeTheClass() throws java.io.IOException {
        Shell CommandStrings = new Shell();
        String cmd = CommandStrings.forShell("echo");
        // EXPECT command-injection
        Runtime.getRuntime().exec(cmd + "-la");
    }
}

class Shell {
    String forShell(String append) {
        return lookup(append);
    }
}
