// Minimal program without calls to known bad API functions, used to test that
// rhabdomancer marks no call locations in such binaries.
// Built with: cc -O0 -o no_calls no_calls.c
int main(void) { return 0; }
