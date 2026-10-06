// PE program whose import stubs IDA names with a numeric suffix (e.g.,
// `strcpy_0`), since symbols in the binary already use their plain names, used
// to test that rhabdomancer matches such stubs.
// Built with: x86_64-w64-mingw32-gcc -O0 -Wl,--strip-debug -o import_stubs import_stubs.c
// and renamed without the `.exe` that mingw appends, since IDA names the IDB of
// `foo.exe` `foo.exe.i64`, which the test harness wouldn't remove.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int (*sys_ptr)(const char *) = system;

int helper(char *dst, const char *src) {
    strcpy(dst, src);
    return sprintf(dst, "%s", getenv("HOME"));
}

int main(int argc, char **argv) {
    char buf[64];
    memcpy(buf, argv[0], 8);
    helper(buf, argc > 1 ? argv[1] : "x");
    system(buf);
    return sys_ptr(buf);
}
