// FIXTURE: hardcoded credentials, Go. All values are FAKE.
package fixtures

// EXPECT hardcoded-secret
const dbPassword = "hunter2-not-a-real-password"

type Config struct {
	ApiKey string
	Region string
}

func load() Config {
	// EXPECT hardcoded-secret
	return Config{ApiKey: "ghp_FAKEfakeFAKEfake0123456789ABCD", Region: "eu-west-1"}
}
