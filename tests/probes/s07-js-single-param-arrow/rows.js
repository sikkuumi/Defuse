// s07-js-single-param-arrow: `table` is the single parameter of the inner arrow function.
// s07: in `table => ...` the arrow's own parameter shadows the module constant.
const table = 1 > 0 ? "users" : "accounts";

// EXPECT sql-injection
export const makeLister = (db) => table => db.query("SELECT * FROM " + table);
