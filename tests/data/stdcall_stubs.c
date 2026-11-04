// 32-bit x86 PE program that calls stdcall functions of the Windows API
// through import stubs, which IDA names with the size of their arguments
// (e.g., `_WinExec@8`), used to test that rhabdomancer matches such stubs. The
// functions are declared here without `__declspec(dllimport)`, unlike in
// <windows.h>, since that would make the compiler call them through the import
// address table instead of through the stubs.
// Built with: i686-w64-mingw32-gcc -O0 -Wl,--strip-debug -o stdcall_stubs stdcall_stubs.c
// and renamed without the `.exe` that mingw appends, since IDA names the IDB of
// `foo.exe` `foo.exe.i64`, which the test harness wouldn't remove.
typedef unsigned int UINT;

__attribute__((stdcall)) UINT WinExec(const char *cmd_line, UINT cmd_show);
__attribute__((stdcall)) char *lstrcpyA(char *dst, const char *src);
__attribute__((stdcall)) void *LoadLibraryA(const char *lib_file_name);

int main(int argc, char **argv) {
    char buf[64];
    lstrcpyA(buf, argv[0]);
    WinExec(buf, 0);
    LoadLibraryA(buf);
    return 0;
}
