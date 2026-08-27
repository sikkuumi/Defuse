function getUser(req) {
  const userId = req.query.id;
  return db.query("SELECT * FROM users WHERE id = " + userId);
}
