// Mach-O program whose calls go through stubs that IDA names with the variant
// suffixes of Apple's SDK (`_realpath$DARWIN_EXTSN`, `_syslog$DARWIN_EXTSN`,
// and `_stat$INODE64`), used to test that rhabdomancer matches such stubs;
// `popen` has no suffix, as a control.
// Built with: cc -arch x86_64 -O0 -o darwin_variants darwin_variants.c
// (an x86_64 build, since only x86_64 binaries use `$INODE64`).
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <syslog.h>

int main(int argc, char **argv) {
    char buf[1024];
    struct stat st;

    realpath(argv[0], buf);
    syslog(LOG_ERR, "%s", buf);
    stat(buf, &st);
    FILE *f = popen(argv[0], "r");
    return f == NULL;
}
