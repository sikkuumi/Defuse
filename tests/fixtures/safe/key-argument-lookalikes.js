// EXPECT-NONE
// FIXTURE: the same function names as a key-taking call, with something that
// is not a key in the key's position. `sign` is only jsonwebtoken's when the
// object is jwt; Node's Sign object takes an output encoding second.
const crypto = require('crypto');

function signIt(privateKeyPem, data) {
  const signer = crypto.createSign('SHA256');
  signer.update(data);
  return signer.sign(privateKeyPem, 'base64');
}

module.exports = { signIt };
