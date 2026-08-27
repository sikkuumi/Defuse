// FIXTURE: broken hash algorithms, JavaScript.
const crypto = require('crypto');

function hashPassword(password) {
  // EXPECT weak-hash
  return crypto.createHash('md5').update(password).digest('hex');
}

function fingerprint(data) {
  // EXPECT weak-hash
  return crypto.createHash('sha1').update(data).digest('hex');
}
