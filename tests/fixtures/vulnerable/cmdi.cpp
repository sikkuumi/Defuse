/*
 * FIXTURE: command injection and SQL injection in C++.
 *
 * WHY C++ IS A SEPARATE LANGUAGE HERE AND NOT A DIALECT OF C.
 *
 * The taint dictionaries are nearly identical - C++ inherits every dangerous
 * function C has, and people still call them. But three things differ enough
 * to need their own grammar and their own entry:
 *
 *   1. NAMESPACES.  `std::system(cmd)` parses as a qualified_identifier, not a
 *      plain identifier. A C query that only matched bare calls would miss
 *      every std:: call in the language - and `<cstdlib>` is how C++ code is
 *      SUPPOSED to reach system(), so the correct-by-style version is exactly
 *      the one that would slip through.
 *
 *   2. METHODS.  `db.query(sql)` and `conn->exec(sql)` are how C++ database
 *      libraries look, so the receiver-scoped sink machinery that the JS and
 *      Java dictionaries use is needed here too, unlike in C.
 *
 *   3. std::string.  A value can be built with `+` on objects rather than
 *      sprintf into a char array, which means the string-building analysis
 *      the other languages use applies, and the C-specific buffer functions
 *      often do not appear at all.
 *
 * What does NOT differ: the sources. `argv`, `getenv` and the socket calls are
 * the same operating system underneath.
 */

#include <cstdlib>
#include <cstdio>
#include <string>

/* The std:: form. The bare `system(cmd)` form is covered by cmdi.c. */
void qualifiedSystemCall(int argc, char **argv) {
    std::string target = argv[1];
    std::string cmd = "ping -c 1 " + target;
    // EXPECT-FLOW command-injection
    std::system(cmd.c_str());
}

/* Built with std::string concatenation rather than sprintf. */
void stringConcatenation(char **argv) {
    std::string cmd = std::string("tar xf ") + argv[1];
    // EXPECT-FLOW command-injection
    system(cmd.c_str());
}

/* popen through the environment, the C++ way of spelling the same mistake. */
void throughTheEnvironment() {
    const char *dir = std::getenv("UPLOAD_DIR");
    std::string cmd = "du -sh " + std::string(dir);
    // EXPECT-FLOW command-injection
    popen(cmd.c_str(), "r");
}

/*
 * A method call on a database object. This exercises the receiver-scoped sink
 * path rather than the bare-function path - `query` on a `db` is a database
 * call, `query` on anything else is somebody's search helper.
 */
void intoADatabaseMethod(char **argv, Connection &db) {
    std::string sql = "SELECT * FROM users WHERE name = '" + std::string(argv[1]) + "'";
    // EXPECT-FLOW sql-injection
    db.query(sql);
}

/* Across a function boundary. */
static std::string buildCommand(const std::string &host) {
    return "nmap " + host;
}

void acrossFunctions(char **argv) {
    // EXPECT-FLOW command-injection
    std::system(buildCommand(argv[1]).c_str());
}
