// FIXTURE: hardcoded credentials, Java. All values are FAKE.
public class Config {
    // EXPECT hardcoded-secret
    private static final String DB_PASSWORD = "hunter2-not-a-real-password";

    // EXPECT hardcoded-secret
    // Shaped like a real key id, generated for this fixture. Not AWS's
    // published AKIAIOSFODNN7EXAMPLE - see safe/awsdocs-example.js.
    private static final String AWS_KEY = "AKIA4KTQVBN2WZRJH7PL";
}
