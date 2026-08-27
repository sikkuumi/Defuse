// FIXTURE: OS command injection, Java.
public class Pinger {
    public void ping(String host) throws Exception {
        // EXPECT command-injection
        Runtime.getRuntime().exec("ping -c 1 " + host);
    }
}
