// FIXTURE: OS command injection, JavaScript.
const { exec, spawn } = require('child_process');

function pingHost(host) {
  // EXPECT command-injection
  exec("ping -c 1 " + host, (err, stdout) => console.log(stdout));
}

function listDir(dir) {
  // EXPECT command-injection
  spawn("ls -la " + dir, { shell: true });
}
