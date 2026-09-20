// EXPECT-NONE
//
// C++ HAD NO NEGATIVE FIXTURE AT ALL.
//
// Until this file, every C++ case in the suite was a vulnerability that had to
// be found, and not one asserted that the engine stays quiet on code that is
// fine. That is half a language's coverage missing: a rule that fires on
// everything passes every positive test ever written.
//
// It matters more for C++ than for most of the others here, because the C
// family dictionary is built out of short, extremely common function names -
// system, exec, query, read - and C++ adds namespaces and methods on top, so
// there are many more ways for a name to look like a sink without being one.
//
// Every case below is deliberately close to something that SHOULD fire.

#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// 1. A constant command. The source is absent, not sanitised.
//
// The nearest thing to vulnerable/cmdi.cpp that is not a bug.
// ---------------------------------------------------------------------------
void fixedCommand() {
    std::string cmd = "df -h /var";
    std::system(cmd.c_str());
}

// ---------------------------------------------------------------------------
// 2. exec on a program that is NOT a shell, with attacker data in the argv.
//
// This is the documented scoping, and it is the single most valuable case in
// this file. exec does not run a command line - it runs one named program with
// arguments handed over as separate strings, so a semicolon in argv[1] is a
// filename containing a semicolon and nothing more. The dictionary only treats
// exec as a command sink when the program being run is itself a shell.
//
// If this fires, the engine is reporting every argument-passing program in C++
// as command injection, which is most of them.
// ---------------------------------------------------------------------------
void execWithoutAShell(char **argv) {
    char *args[] = { (char *)"/usr/bin/convert", argv[1], (char *)"out.png", nullptr };
    execv("/usr/bin/convert", args);
}

// ---------------------------------------------------------------------------
// 3. A bound parameter. The value never becomes part of the statement.
// ---------------------------------------------------------------------------
void boundParameter(sqlite3_stmt *stmt, char **argv) {
    sqlite3_bind_text(stmt, 1, argv[1], -1, nullptr);
}

// ---------------------------------------------------------------------------
// 4. `query` on something that is not a database.
//
// The receiver-scoped machinery exists so that a short method name is judged
// by what it is called on. A search index has a query method; so does every
// second class in a large codebase. Only the database-shaped receivers should
// count.
// ---------------------------------------------------------------------------
void searchIndexIsNotADatabase(SearchIndex &index, char **argv) {
    std::string term = argv[1];
    index.query(term);
}

// ---------------------------------------------------------------------------
// 5. A bounded copy.
//
// snprintf writes at most the length it is given, which is why it is in the
// sanitiser list and sprintf is not. The unbounded-copy rule is explicitly
// about writes that run until a NUL byte.
// ---------------------------------------------------------------------------
void boundedCopy(char **argv) {
    char name[64];
    snprintf(name, sizeof(name), "%s", argv[1]);
    printf("%s\n", name);
}

// ---------------------------------------------------------------------------
// 6. std::string methods on clean data.
//
// substr, find, append and operator+ all carry taint when there is taint to
// carry. Here there is none, and none of them may invent any.
// ---------------------------------------------------------------------------
std::string buildBanner() {
    std::string base = "defuse";
    std::string version = base + " 0.5.0";
    std::string shortName = version.substr(0, 6);
    shortName.append(" ready");
    return shortName;
}

// ---------------------------------------------------------------------------
// 7. A vector of constants handed to a program.
// ---------------------------------------------------------------------------
void constantArguments() {
    std::vector<std::string> args = { "--version", "--quiet" };
    std::string cmd = "defuse";
    for (const auto &a : args) {
        cmd += " " + a;
    }
    std::system(cmd.c_str());
}
