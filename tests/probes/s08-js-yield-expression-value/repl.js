// s08-js-yield-expression-value: The query splices in `(yield prompt)` - whatever the caller passes back - not `prompt`.
// s08: `(yield prompt)` evaluates to whatever the caller passes to next(), not to `prompt`.
function* tableRepl(db) {
  const prompt = 1 > 0 ? "table?" : "name?";
  while (true) {
    // EXPECT sql-injection
    db.query("SELECT * FROM " + (yield prompt));
  }
}
module.exports = { tableRepl };
