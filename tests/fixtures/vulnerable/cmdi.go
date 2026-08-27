// FIXTURE: OS command injection, Go.
package fixtures

import "os/exec"

func ping(host string) error {
	// EXPECT command-injection
	return exec.Command("sh", "-c", "ping -c 1 "+host).Run()
}
