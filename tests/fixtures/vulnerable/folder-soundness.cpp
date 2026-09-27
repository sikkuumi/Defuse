/*
 * The C++ half of FolderSoundness.java. C++ can write to a local without an
 * `=` and without a `&` at the call site:
 *
 *   byReference   `void fill(int &x)` - the call `fill(n)` looks like it passes
 *                 a copy, and does not
 *   streamed      `std::cin >> n` is a call to operator>> taking n by reference
 *   aliased       `int &r = n` is a second name for the same storage
 *
 * So in C++ a local handed to any call, read into from a stream, or bound to a
 * reference is no longer a value the folder knows.
 */
#include <cstdlib>
#include <iostream>
#include <string>

void fill(int &x);

void byReference(int argc, char **argv) {
    int n = 0;
    std::string cmd = "ls";
    fill(n);
    if (n > 5) cmd = argv[1];
    // EXPECT-FLOW command-injection
    system(cmd.c_str());
}

void streamed(int argc, char **argv) {
    int n = 0;
    std::string cmd = "ls";
    std::cin >> n;
    if (n > 5) cmd = argv[1];
    // EXPECT-FLOW command-injection
    system(cmd.c_str());
}

void aliased(int argc, char **argv) {
    int n = 0;
    int &r = n;
    r = 7;
    std::string cmd = "ls";
    if (n > 5) cmd = argv[1];
    // EXPECT-FLOW command-injection
    system(cmd.c_str());
}
