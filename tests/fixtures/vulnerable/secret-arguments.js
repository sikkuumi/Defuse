// FIXTURE: a key handed straight to the function that uses it.
//
// The secrets check looked at NAMED values - `const key = '...'`. Juice Shop's
// lib/insecurity.ts passes its HMAC key straight into createHmac(), with no
// name to match, and it was missed.
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

// EXPECT-SIGNATURE hardcoded-secret
const sign = (data) => crypto.createHmac('sha256', 'pa4qacea4VK9t9nGv7yZtwmj').update(data).digest('hex');

// EXPECT-SIGNATURE hardcoded-secret
const issue = (user) => jwt.sign({ id: user.id }, 'my-jwt-signing-secret');

// A wallet's PRIVATE key is 64 hex digits, not an address's 40: still a secret.
// EXPECT-SIGNATURE hardcoded-secret
const walletPrivateKey = '0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318';

// Address-shaped, but the name says secret: a 40-hex-digit signing secret is
// still a secret. Only a name that says address, or says nothing, lets it off.
// EXPECT-SIGNATURE hardcoded-secret
const signingSecret = '0x9f86d081884c7d659a2feaa0c55ad015a3bf4f1b';

// The correct pattern: the key comes from outside the code.
const fromEnv = (data) => crypto.createHmac('sha256', process.env.HMAC_KEY).update(data).digest('hex');

module.exports = { sign, issue, walletPrivateKey, signingSecret, fromEnv };
