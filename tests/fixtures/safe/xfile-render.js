// FIXTURE (cross-file): the tracer must follow into xfile-clean.js, see the
// escaping there, and stay silent.
// EXPECT-NONE
const { cleanHtml } = require('./xfile-clean');

function render(req, el) {
  el.innerHTML = "<b>Hello " + cleanHtml(req.query.name) + "</b>";
}
