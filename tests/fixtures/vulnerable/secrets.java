// FIXTURE: hardcoded credentials, Java. All values are FAKE.
public class Config {
    // EXPECT hardcoded-secret
    // Value changed from "hunter2-not-a-real-password", which the placeholder
    // rule now correctly ignores - see the long note in secrets.js.
    private static final String DB_PASSWORD = "Tr0ub4dor3xK";

    // EXPECT hardcoded-secret
    // Shaped like a real key id, generated for this fixture. Not AWS's
    // published AKIAIOSFODNN7EXAMPLE - see safe/awsdocs-example.js.
    private static final String AWS_KEY = "AKIA4KTQVBN2WZRJH7PL";
}
