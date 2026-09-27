/*
 * The C++ half of FolderSoundnessProbe.java. In C++ a mutable local can be
 * written through a reference with no sign of it at the write, so only a
 * `const` or `constexpr` local is folded at all.
 */
#include <atomic>
#include <cstdlib>
#include <iostream>
#include <string>
struct Slot { int &r; };

void refbrace(int argc, char **argv) {
    int n = 0;
    int &r{n};
    r = std::atoi(argv[2]);
    std::string cmd = "ls";
    if (n > 5) cmd = argv[1];
    // EXPECT command-injection
    system(cmd.c_str());
}

void refparen(int argc, char **argv) {
    int n = 0;
    auto &r = (n);
    r = std::atoi(argv[2]);
    std::string cmd = "ls";
    if (n > 5) cmd = argv[1];
    // EXPECT command-injection
    system(cmd.c_str());
}

void cinparen(int argc, char **argv) {
    int n = 0;
    std::cin >> (n);
    std::string cmd = "ls";
    if (n > 5) cmd = argv[1];
    // EXPECT command-injection
    system(cmd.c_str());
}

void atomic(int argc, char **argv) {
    std::atomic<int> n = 0;
    n.store(std::atoi(argv[2]));
    std::string cmd = "ls";
    if (n > 5) cmd = argv[1];
    // EXPECT command-injection
    system(cmd.c_str());
}

void initcapture(int argc, char **argv) {
    int n = 0;
    auto set = [&r = n](int v) { r = v; };
    set(std::atoi(argv[2]));
    std::string cmd = "ls";
    if (n > 5) cmd = argv[1];
    // EXPECT command-injection
    system(cmd.c_str());
}

void structref(int argc, char **argv) {
    int n = 0;
    Slot s{n};
    s.r = std::atoi(argv[2]);
    std::string cmd = "ls";
    if (n > 5) cmd = argv[1];
    // EXPECT command-injection
    system(cmd.c_str());
}

void lambdaref(int argc, char **argv) {
    int n = 0;
    auto bump = [&]() { n += 10; };
    bump();
    std::string cmd = "ls";
    if (n > 5) cmd = argv[1];
    // EXPECT command-injection
    system(cmd.c_str());
}

void octal(int argc, char **argv) {
    const int mode = 0644;
    std::string cmd = "ls";
    if (mode < 600) cmd = argv[1];
    // EXPECT command-injection
    system(cmd.c_str());
}

void lambdaparen(int argc, char **argv) {
    int n = 0;
    auto set = [&](int v) { (n) = v; };
    set(std::atoi(argv[2]));
    std::string cmd = "ls";
    if (n > 5) cmd = argv[1];
    // EXPECT command-injection
    system(cmd.c_str());
}
