// s01-js-generator-param: `table` is the generator's parameter, not the module constant.
// s01: inside the generator, `table` is its own parameter, not the module constant.
const table = "users";

function* rows(db, table) {
  // EXPECT sql-injection
  yield db.query("SELECT * FROM " + table);
}

module.exports = { rows };
