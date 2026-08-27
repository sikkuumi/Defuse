// EXPECT-NONE
//
// ESCAPING THE SCANNER CAN SEE MUST COUNT.
//
// Every shape below came from this project's own browser UI, where the XSS rule
// reported seven innerHTML assignments and printed "No escaping or sanitiser
// call is visible at this line" over code that escapes every single value. The
// label on those findings was honest - signature-based, flow not traced - but
// the sentence underneath was a false statement about code already parsed.
//
// So the rule now proves what it can before it complains, and this file is the
// proof's floor: if any line here reports, the proof has broken.

function escapeHtml(text) {
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// 1. The escaper sits inside the template, four characters from the value.
export function status(message) {
  document.querySelector('#status').innerHTML = `<span>${escapeHtml(message)}</span>`;
}

// 2. A local render helper. Judged with the CALLER's arguments bound, so
//    `className` is the literal below rather than "some parameter, who knows".
function tile(value, label, className = '') {
  return `<div class="tile ${className}"><b>${escapeHtml(value)}</b>${escapeHtml(label)}</div>`;
}

// 3. Composition through map/join - the commonest shape in real UI code, and
//    the one a check that stops at the first call proves nothing about.
export function summary(rows, count) {
  const tiles = rows.map((row) => tile(row.value, row.label, 'wide')).join('');
  const header = tile(count, 'total', 'lead');
  document.querySelector('#summary').innerHTML = `${header}<div class="grid">${tiles}</div>`;
}

// 4. Numbers cannot open a tag: a length, a subtraction, a fixed decimal.
export function meter(items, ratio) {
  document.querySelector('#meter').innerHTML =
    `<i style="width:${ratio.toFixed(1)}%"></i><em>${items.length - 1} more</em>`;
}

// 5. A local variable holding a value built earlier, and a ternary where both
//    branches are safe.
export function empty(rows) {
  const body = rows.length === 0 ? '<p>Nothing here</p>' : `<p>${rows.length} rows</p>`;
  document.querySelector('#body').innerHTML = body;
}

// 6. The escaper passed BY REFERENCE rather than called. Resolving the name to
//    its declaration and judging the body lands on `String(x).replace(...)`,
//    which proves nothing - so the checker used to report the innards of its
//    own escaper as the unsafe part.
export function hops(names) {
  document.querySelector('#hops').innerHTML = `<em>${names.map(escapeHtml).join(', ')}</em>`;
}

// 7. The index parameter of map. Not a heuristic: the language specifies an
//    integer there, and digits cannot open a tag. Line numbers beside rendered
//    source are this shape, and without it every one of them reads as unproven.
export function listing(lines) {
  document.querySelector('#listing').innerHTML = lines
    .map((text, i) => `<div><span class="ln">${i + 1}</span>${escapeHtml(text)}</div>`)
    .join('');
}

// 8. A comment inside the `${ }` hole, ahead of the expression. Taking the
//    hole's first named child hands the checker the COMMENT instead of the
//    code - which produced a false alarm here, and would have waved through
//    the matching case in partial-escape.js.
export function annotated(label) {
  document.querySelector('#annotated').innerHTML = `<b>${
    // The comment is the first child of this hole, not the call below it.
    escapeHtml(label)
  }</b>`;
}
