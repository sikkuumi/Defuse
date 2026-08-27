// FIXTURE: the sanitiser is reached through a helper function.
// The tracer must follow the value in, see escapeHtml, and retract the guess.
// EXPECT-NONE
const escapeHtml = require('escape-html');

function clean(value) {
  return escapeHtml(value);
}

function render(req, el) {
  el.innerHTML = "<b>Hello " + clean(req.query.name) + "</b>";
}
