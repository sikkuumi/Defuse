// FIXTURE: the proof must not become an excuse to stay quiet.
//
// The companion to safe/escaped-composition.js. Every case here has SOME
// escaping in it - enough that a check looking for "is an escaper mentioned on
// this line?" would wave it through - and one value that reaches the HTML
// parser exactly as written. The finding must still fire, and its reasoning
// must name the part that is not covered rather than shrugging at the line.

function escapeHtml(text) {
  return String(text).replace(/</g, '&lt;');
}

// One of two values escaped. The other is the bug.
// EXPECT xss
export function row(name, note) {
  document.querySelector('#row').innerHTML = `<b>${escapeHtml(name)}</b><i>${note}</i>`;
}

// The helper escapes its first argument and forgets the second.
function cell(label, title) {
  return `<td title="${title}">${escapeHtml(label)}</td>`;
}

// EXPECT xss
export function table(rows) {
  document.querySelector('#table').innerHTML = rows.map((r) => cell(r.label, r.title)).join('');
}

// An escaper that is not one: String() converts, it does not clean.
// EXPECT xss
export function caption(text) {
  document.querySelector('#caption').innerHTML = `<figcaption>${String(text)}</figcaption>`;
}

// JSON.stringify output can contain a literal </script>, which closes the tag
// it is sitting inside and hands the rest of the string to the parser as code.
// EXPECT xss
export function debug(state) {
  document.querySelector('#debug').innerHTML = `<pre>${JSON.stringify(state)}</pre>`;
}

// The dangerous half of the comment case. If a comment in a `${ }` hole counts
// as "the expression" and comments are safe, the real value underneath is never
// looked at and this line goes quiet.
// EXPECT xss
export function annotated(label) {
  document.querySelector('#annotated').innerHTML = `<b>${
    // A comment sitting ahead of an unescaped value.
    label
  }</b>`;
}

// `sanitize` is a trusted escaper NAME, and here it is a local identity
// function. The binding must be resolved before the name is trusted, or any
// codebase with a variable called `sanitize` silences the rule.
const sanitize = (x) => x;

// EXPECT xss
export function shadowed(text) {
  document.querySelector('#shadowed').innerHTML = `<p>${sanitize(text)}</p>`;
}
