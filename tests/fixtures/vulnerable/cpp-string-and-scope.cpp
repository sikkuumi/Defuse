/*
 * THE C++ CLAIMS, TESTED ONE AT A TIME.
 *
 * The coverage note printed on every scan says this about C++:
 *
 *   "everything listed for C, plus namespace-qualified calls (std::system),
 *    receiver-scoped database methods (db.query(sql)), and std::string - whose
 *    c_str(), substr() and operator+ carry taint, which is how a tainted string
 *    actually reaches system() in C++ code."
 *
 * cmdi.cpp proved two of those: the std:: form and operator+. The rest were
 * assertions. substr() was named in the note and never traced. The arrow form
 * `conn->exec(sql)` is named in cmdi.cpp's own header comment as a shape C++
 * database code takes, and no fixture used it. `+=` appears in real code far
 * more than `a = b + c` and had never been tried at all.
 *
 * C++ also had ZERO signature-labelled findings in the whole suite, which
 * means the downgrade path - report it, but do not claim a proof - had never
 * once fired in this language.
 *
 * Every annotation below is a PREDICTION written before running the engine.
 */

#include <cstdlib>
#include <cstdio>
#include <string>

// ---------------------------------------------------------------------------
// 1. substr(), named in the coverage note and never tested.
//
// Trimming a value does not clean it. A shell metacharacter survives a
// substring as happily as any other byte.
// ---------------------------------------------------------------------------
void throughSubstr(char **argv) {
    std::string raw = argv[1];
    std::string host = raw.substr(0, 64);
    std::string cmd = "ping -c 1 " + host;
    // EXPECT-FLOW command-injection
    std::system(cmd.c_str());
}

// ---------------------------------------------------------------------------
// 2. operator+=, which is how strings are actually built.
//
// `cmd = cmd + x` was covered. `cmd += x` is a different node and is the form
// almost everyone writes.
// ---------------------------------------------------------------------------
void throughPlusEquals(char **argv) {
    std::string cmd = "tar xf ";
    cmd += argv[1];
    // EXPECT-FLOW command-injection
    std::system(cmd.c_str());
}

// ---------------------------------------------------------------------------
// 3. append(), the method spelling of the same thing.
// ---------------------------------------------------------------------------
void throughAppend(char **argv) {
    std::string cmd = "gzip ";
    cmd.append(argv[1]);
    // EXPECT-FLOW command-injection
    popen(cmd.c_str(), "r");
}

// ---------------------------------------------------------------------------
// 4. The arrow form on a database handle.
//
// cmdi.cpp's header names `conn->exec(sql)` as a shape C++ database code
// takes, then only ever tests the dot. A pointer is the more common way to
// hold a connection in C++.
// ---------------------------------------------------------------------------
void throughArrowReceiver(char **argv, Connection *conn) {
    std::string sql = "DELETE FROM sessions WHERE token = '";
    sql += argv[1];
    sql += "'";
    // EXPECT-FLOW sql-injection
    conn->exec(sql);
}

// ---------------------------------------------------------------------------
// 5. exec WITH a shell, which is the case that must still fire.
//
// safe/cpp-clean.cpp asserts that execv on a real program stays quiet. That
// assertion is only worth something if the shell case is loud, otherwise the
// rule could be switched off entirely and both files would pass.
// ---------------------------------------------------------------------------
void execIntoAShell(char **argv) {
    std::string cmd = "cat /var/log/";
    cmd += argv[1];
    // EXPECT-FLOW command-injection
    execl("/bin/sh", "sh", "-c", cmd.c_str(), nullptr);
}

// ---------------------------------------------------------------------------
// 6. A sink with no traceable source. SILENT, AND THAT IS A DECISION NOBODY
//    HAS ACTUALLY TAKEN YET.
//
// Predicted EXPECT-SIGNATURE: the value reaches a shell, no path can be walked
// to it, so the honest output is a finding without a proof attached. It fires
// nothing at all.
//
// Controlled before blaming C++, and it is not a C++ gap. The same shape in
// plain C is equally silent - `void f(const char *name){ system(name); }`
// produces nothing - so the whole C family reports command injection ONLY when
// a full source-to-sink path is traced. There is no signature-level pass
// behind it, which is why C++ has never produced a signature-labelled finding
// in the entire suite.
//
// That may well be right. `system(x)` where x is any variable is extremely
// common in C, and a signature rule on it would be loud in a language whose
// whole standard library is short common names - the same reasoning that keeps
// `exec` bare-only in JavaScript.
//
// But it is currently an accident rather than a decision: no coverage note
// says the C family is flow-only for this rule, and a reader who knows the
// other six languages report unproven leads would reasonably expect this one
// to as well. Either the behaviour changes or the note does. Left annotated
// with nothing until that is chosen, so the fixture records the truth rather
// than a preference.
// ---------------------------------------------------------------------------
void fromAnUnknownConfig(Settings &settings) {
    std::string cmd = "systemctl restart " + settings.serviceName;
    std::system(cmd.c_str());
}

// ---------------------------------------------------------------------------
// 7. A source read from a stream rather than from argv.
//
// getline is in the source list. The operating system is the framework in this
// language, and stdin is as attacker-controlled as a query string when the
// program is on the end of a pipe.
// ---------------------------------------------------------------------------
void fromStandardInput() {
    char *line = nullptr;
    size_t cap = 0;
    getline(&line, &cap, stdin);
    std::string cmd = "grep -F " + std::string(line);
    // EXPECT-FLOW command-injection
    std::system(cmd.c_str());
}
