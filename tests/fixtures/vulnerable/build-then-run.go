// THE TWO-LINE FORM, IN GO.
//
// See build-then-run.py. Go only reports exec.Command when the call itself
// names a shell - exec.Command("ls", name) is an argument vector and genuinely
// safe - and that rule is unchanged. What changes is that the command handed
// to `sh -c` is now followed back to where it was built.
package fixtures

import (
	"fmt"
	"os/exec"
)

func concatThenRun(name string) {
	c := "ls " + name
	// EXPECT-SIGNATURE command-injection
	exec.Command("sh", "-c", c).Run()
}

func sprintfThenRun(host string) {
	c := fmt.Sprintf("ping -c 1 %s", host)
	// EXPECT-SIGNATURE command-injection
	exec.Command("bash", "-c", c).Run()
}

// ---------------------------------------------------------------- FENCES

func fixed() {
	c := "uptime"
	exec.Command("sh", "-c", c).Run()
}

// No shell: an argument vector, so `name` is one argument however it is spelled.
func argumentVector(name string) {
	exec.Command("ls", "-l", name).Run()
}
