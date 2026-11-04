// Program with a wrapper whose only instruction is a tail call to `free`, so
// that the call location is the wrapper's start address, where IDA's
// `append_cmt` appends to the function comment instead of the instruction's,
// used to test that rhabdomancer comments such call locations like any other.
// Built with: cc -arch arm64 -O2 -o tail_call tail_call.c
#include <stdlib.h>

__attribute__((noinline)) void xfree(void *ptr) { free(ptr); }

int main(void) {
    void *ptr = malloc(8);
    xfree(ptr);
    return 0;
}
