// s09b-js-concat-receiver-name: `dir.concat(flags)` - the receiver `dir` is the parameter, and it was never judged.
// s09b: in dir.concat(flags) only the argument is judged; the receiver `dir` is never looked at.
const { execSync } = require("child_process");

function list(dir) {
  const flags = 1 > 0 ? " -la" : " -l";
  // EXPECT command-injection
  return execSync(dir.concat(flags));
}
module.exports = { list };
