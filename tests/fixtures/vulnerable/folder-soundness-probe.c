/*
 * The C half of FolderSoundnessProbe.java - an adversarial probe's programs,
 * each a real injection the constant folder hid before this was fixed.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define SET_INT(var, s) ((var) = atoi(s))

void paren(int argc, char **argv) {
    int n = 0;
    char *cmd = "ls";
    (n) = atoi(argv[2]);
    if (n > 5) cmd = argv[1];
    // EXPECT command-injection
    system(cmd);
}

void addrparen(int argc, char **argv) {
    int n = 0;
    char *cmd = "ls";
    scanf("%d", &(n));
    if (n > 5) cmd = argv[1];
    // EXPECT command-injection
    system(cmd);
}

void addrcomment(int argc, char **argv) {
    int n = 0;
    char *cmd = "ls";
    scanf("%d", &/*out*/n);
    if (n > 5) cmd = argv[1];
    // EXPECT command-injection
    system(cmd);
}

void macrowrite(int argc, char **argv) {
    int n = 0;
    char *cmd = "ls";
    SET_INT(n, argv[2]);
    if (n > 5) cmd = argv[1];
    // EXPECT command-injection
    system(cmd);
}

void octal(int argc, char **argv) {
    int n = 010;
    char *cmd = "ls";
    if (n < 9) cmd = argv[1];
    // EXPECT command-injection
    system(cmd);
}

void unsignedWrap(int argc, char **argv) {
    unsigned int n = 0 - 1;
    char *cmd = "ls";
    if (n > 5) cmd = argv[1];
    // EXPECT command-injection
    system(cmd);
}

void charswitch(int argc, char **argv) {
    char *cmd = "ls";
    signed char c = 200;
    switch (c) {
    case 200:
        cmd = "date";
        break;
    default:
        cmd = argv[1];
    }
    // EXPECT command-injection
    system(cmd);
}

void macrostatic(int argc, char **argv) {
    static int calls = 0;
    char *cmd = "ls";
    if (calls > 0) cmd = argv[1];
    // EXPECT command-injection
    system(cmd);
    calls += 1;
}

void elseif_chain(int argc, char **argv) {
    int n = 0;
    char *cmd = "ls";
    const char *op = argv[3];
    if (strcmp(op, "op0") == 0) {
        puts("op0");
    } else if (strcmp(op, "op1") == 0) {
        puts("op1");
    } else if (strcmp(op, "op2") == 0) {
        puts("op2");
    } else if (strcmp(op, "op3") == 0) {
        puts("op3");
    } else if (strcmp(op, "op4") == 0) {
        puts("op4");
    } else if (strcmp(op, "op5") == 0) {
        puts("op5");
    } else if (strcmp(op, "op6") == 0) {
        puts("op6");
    } else if (strcmp(op, "op7") == 0) {
        puts("op7");
    } else if (strcmp(op, "op8") == 0) {
        puts("op8");
    } else if (strcmp(op, "op9") == 0) {
        puts("op9");
    } else if (strcmp(op, "op10") == 0) {
        puts("op10");
    } else if (strcmp(op, "op11") == 0) {
        puts("op11");
    } else if (strcmp(op, "op12") == 0) {
        puts("op12");
    } else if (strcmp(op, "op13") == 0) {
        puts("op13");
    } else if (strcmp(op, "op14") == 0) {
        puts("op14");
    } else if (strcmp(op, "op15") == 0) {
        puts("op15");
    } else if (strcmp(op, "op16") == 0) {
        puts("op16");
    } else if (strcmp(op, "op17") == 0) {
        puts("op17");
    } else if (strcmp(op, "op18") == 0) {
        puts("op18");
    } else if (strcmp(op, "op19") == 0) {
        puts("op19");
    } else if (strcmp(op, "op20") == 0) {
        puts("op20");
    } else if (strcmp(op, "op21") == 0) {
        puts("op21");
    } else {
        n = atoi(argv[2]);
    }
    if (n > 5) cmd = argv[1];
    // EXPECT command-injection
    system(cmd);
}

void gotoPastInit(int argc, char **argv) {
    char *cmd = "ls";
    if (argc > 3) goto inside;
    {
        int n = 0;
    inside:
        if (n > 5) cmd = argv[1];
    }
    // EXPECT command-injection
    system(cmd);
}


void macroshadow(int argc, char **argv) {
    int n = 0;
    char *cmd = "ls";
#define n atoi(argv[2])
    if (n > 5) cmd = argv[1];
    // EXPECT command-injection
    system(cmd);
}
