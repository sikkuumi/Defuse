/*
 * C++ HAS A `+` FOR STRINGS, AND STILL HID EVERY CASE BEHIND `.c_str()`.
 *
 * See build-then-run.c. std::string can be concatenated inline, so C++ looked
 * as if it should behave like Python - but std::system() takes a `const char*`,
 * so every call ends `.c_str()`, and to the signature pass a method call is an
 * opaque value. Even the one-line form
 *
 *     std::system(("ls " + name).c_str());
 *
 * was silent: the concatenation was sitting right there inside the brackets,
 * one method call deep. The rule now looks through `.c_str()` and `.data()`,
 * which do nothing to the text but hand it over in the shape the C API wants.
 */
#include <cstdio>
#include <cstdlib>
#include <string>

void inline_form(const std::string& name) {
    // EXPECT-SIGNATURE command-injection
    std::system(("ls " + name).c_str());
}

void two_step(const std::string& name) {
    std::string cmd = "ls -l " + name;
    // EXPECT-SIGNATURE command-injection
    std::system(cmd.c_str());
}

void compound(const std::string& term) {
    std::string cmd = "grep -r ";
    cmd += term;
    // EXPECT-SIGNATURE command-injection
    system(cmd.c_str());
}

void appended(const std::string& file) {
    std::string cmd = "cat ";
    cmd.append(file);
    // EXPECT-SIGNATURE command-injection
    std::system(cmd.data());
}

/* The C idiom is still everywhere in C++, so it gets its own case here too. */
void c_style(const char* host) {
    char buf[128];
    std::snprintf(buf, sizeof buf, "ping -c 1 %s", host);
    // EXPECT-SIGNATURE command-injection
    popen(buf, "r");
}

/* ------------------------------------------------------------------ FENCES */

void fixed() {
    std::string cmd = "uptime";
    std::system(cmd.c_str());
}

/* The overwrite: whatever `name` put in, the last reset before the call is a
 * literal. Reporting this would mean the rule reads every write instead of the
 * ones that reach the call. */
void overwritten(const std::string& name) {
    std::string cmd = "ls " + name;
    cmd = "ls -l";
    std::system(cmd.c_str());
}
