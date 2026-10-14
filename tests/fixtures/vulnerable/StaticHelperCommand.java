/*
 * A STATIC HELPER IN ANOTHER FILE, READ THROUGH - AND WHERE IT IS NOT.
 *
 * 31 of BenchmarkJava's command-injection false positives build the command
 * with a helper that lives in another file:
 *
 *     cmd = org.owasp.benchmark.helpers.Utils.getOSCommandString("echo");
 *     r.exec(cmd + bar);
 *
 * The helper wraps literals around its argument and returns that. The
 * constant proof now follows the call into the other file when the method
 * that runs is not in doubt: a STATIC method, named through its class - by full
 * name, by an import, or in the same package - with exactly one method of that
 * name in exactly one class of that full name in the scan. Every return must be
 * built from literals and the method's own parameters, and a parameter counts
 * only when the argument passed for it is itself provably fixed and the method
 * never writes to it. One level: a helper that calls another helper is not
 * read.
 *
 * safe/CommandStrings.java is the helper; every fence below uses one of its
 * shapes. `lookup` is defined nowhere in the scan, so the tracer has no source
 * to follow and the pattern rule is the only thing that speaks.
 */
import javax.servlet.http.*;
import fixtures.helpers.CommandStrings;
import fixtures.other.Quoter;

public class StaticHelperCommand extends HttpServlet {

    // ---------------------------------------------------------------- RESOLVED

    // By full name: forShell("echo") is literals around a literal.
    void fullName() throws java.io.IOException {
        String cmd = fixtures.helpers.CommandStrings.forShell("echo");
        // EXPECT-CLEAN command-injection
        Runtime.getRuntime().exec(cmd + "hello");
    }

    // Through the import.
    void imported() throws java.io.IOException {
        String cmd = CommandStrings.forShell("ls");
        // EXPECT-CLEAN command-injection
        Runtime.getRuntime().exec(cmd + "-la");
    }

    // ---------------------------------------------------------------- THE FENCE

    // The argument is not fixed, so neither is what comes back.
    void unknownArgument() throws java.io.IOException {
        String cmd = CommandStrings.forShell(lookup("cmd"));
        // EXPECT command-injection
        Runtime.getRuntime().exec(cmd + "-la");
    }

    // pick() overwrites its first parameter with its second before returning
    // it: the literal "echo" is not what comes back.
    void parameterOverwritten() throws java.io.IOException {
        String cmd = CommandStrings.pick("echo", lookup("cmd"));
        // EXPECT command-injection
        Runtime.getRuntime().exec(cmd + "-la");
    }

    // Two methods named twice(), both taking two arguments: which one runs
    // depends on their TYPES, and this proof does not choose between
    // overloads. `other` is declared Object, so this is twice(String, Object),
    // which returns something unknown; twice(String, String) would have been
    // provable.
    void overloaded() throws java.io.IOException {
        Object other = "x";
        String cmd = CommandStrings.twice("echo", other);
        // EXPECT command-injection
        Runtime.getRuntime().exec(cmd + "-la");
    }

    // withShell() returns a private field, and setShell() can change it.
    void fieldInHelper() throws java.io.IOException {
        String cmd = CommandStrings.withShell("ls");
        // EXPECT command-injection
        Runtime.getRuntime().exec(cmd + "-la");
    }

    // viaPrefix("echo") IS fixed, but only through a second helper. One level
    // is all this proof reads, so it stays a guess - a limit, stated.
    void secondLevel() throws java.io.IOException {
        String cmd = CommandStrings.viaPrefix("echo");
        // EXPECT command-injection
        Runtime.getRuntime().exec(cmd + "-la");
    }

    // Two classes called Quoter: one in this package (vulnerable/Quoter.java),
    // one imported (safe/Quoter.java). The import wins, and its wrap() returns
    // something unknown. The one in this package would have been provable.
    void importBeatsPackage() throws java.io.IOException {
        String cmd = Quoter.wrap("echo");
        // EXPECT command-injection
        Runtime.getRuntime().exec(cmd + "-la");
    }

    // `Wrapper.Inner` could be class Inner in a package called Wrapper
    // (safe/Inner.java) - but Wrapper is also a class in this package
    // (safe/Wrapper.java), and a class outranks a package. Its nested Inner
    // returns something unknown.
    void classNotPackage() throws java.io.IOException {
        String cmd = Wrapper.Inner.m("echo");
        // EXPECT command-injection
        Runtime.getRuntime().exec(cmd + "-la");
    }

    // A variable named like the class: StaticHelperShadowed.java.

    // Two classes in the scan are called fixtures.dup.DupStrings, and one of
    // them returns something unknown. Neither is chosen.
    void twoClassesOneName() throws java.io.IOException {
        String cmd = fixtures.dup.DupStrings.forShell("echo");
        // EXPECT command-injection
        Runtime.getRuntime().exec(cmd + "-la");
    }
}
