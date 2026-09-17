// FIXTURE: hardcoded credentials, Go. All values are FAKE.
package fixtures

// EXPECT hardcoded-secret
// Value changed from "hunter2-not-a-real-password", which the placeholder rule
// now correctly ignores - see the long note in secrets.js.
const dbPassword = "Tr0ub4dor3xK"

type Config struct {
	ApiKey string
	Region string
}

func load() Config {
	// EXPECT hardcoded-secret
	return Config{ApiKey: "ghp_FAKEfakeFAKEfake0123456789ABCD", Region: "eu-west-1"}
}
