// FIXTURE (cross-file): the SANITISER lives here.
// EXPECT-NONE
const escapeHtml = require('escape-html');

function cleanHtml(value) {
  return escapeHtml(value);
}

module.exports = { cleanHtml };
