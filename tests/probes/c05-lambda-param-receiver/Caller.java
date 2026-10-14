// c05-lambda-param-receiver: A shape the constant proof read correctly when it was probed; kept so it stays that way.
package app;
public class Caller {
    void run(java.util.List<Shell> shells) {
        shells.forEach(Utils -> {
            String cmd = Utils.forShell("echo");
            // EXPECT command-injection
            try { Runtime.getRuntime().exec(cmd + "-la"); } catch (Exception e) { }
        });
    }
}
