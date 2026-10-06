# rhabdomancer

[![](https://img.shields.io/github/stars/0xdea/rhabdomancer.svg?style=flat&color=yellow)](https://github.com/0xdea/rhabdomancer)
[![](https://img.shields.io/crates/v/rhabdomancer?style=flat&color=green)](https://crates.io/crates/rhabdomancer)
[![](https://img.shields.io/crates/d/rhabdomancer?style=flat&color=red)](https://crates.io/crates/rhabdomancer)
[![](https://img.shields.io/badge/ida-9.4-violet)](https://hex-rays.com/ida-pro)
[![](https://img.shields.io/badge/twitter-%400xdea-blue.svg)](https://twitter.com/0xdea)
[![](https://img.shields.io/badge/mastodon-%40raptor-purple.svg)](https://infosec.exchange/@raptor)
[![build](https://github.com/0xdea/rhabdomancer/actions/workflows/build.yml/badge.svg)](https://github.com/0xdea/rhabdomancer/actions/workflows/build.yml)
[![doc](https://github.com/0xdea/rhabdomancer/actions/workflows/doc.yml/badge.svg)](https://github.com/0xdea/rhabdomancer/actions/workflows/doc.yml)

> "The road to exploitable bugs is paved with unexploitable bugs."
>
> -- Mark Dowd

Rhabdomancer is a blazing-fast IDA headless plugin that locates calls to potentially insecure API functions in
a binary file. Auditors can backtrace from these candidate points to find pathways allowing access to untrusted input.

![](https://raw.githubusercontent.com/0xdea/rhabdomancer/master/.img/screen01.png)

## Features

- Blazing-fast, headless user experience courtesy of IDA 9.x and idalib-rs Rust bindings.
- Support for C/C++ binary targets compiled for any architecture implemented by IDA.
- Bad API function call locations are printed to stdout and marked in the IDB.
  - Call locations in library code recognized by IDA (e.g., a statically linked runtime matched by FLIRT signatures) are
    labeled `(lib)` after the address (`0x... (lib) in <caller>`), so that they can be filtered out, e.g., with
    `grep -v '^0x[0-9A-F]* (lib) in '`. Filtering may also hide calls from your own code that reach a bad function only
    through library code.
  - Calls through stubs (e.g., the `.plt` entries of ELF binaries or the import stubs of PE and Mach-O binaries,
    listed as thunks) are traced back to their callers.
  - In ELF binaries, a function is typically listed twice with the same call locations: once as its `.plt` stub
    (marked as thunk) and once as its import. This redundancy is deliberate: it ensures that no call location is
    missed. Each call location is marked only once in the IDB.
- Known bad API functions are grouped in tiers of badness to help prioritize the audit work.
  - [BAD 0] High priority - Functions that are generally considered insecure.
  - [BAD 1] Medium priority - Interesting functions that should be checked for insecure use cases.
  - [BAD 2] Low priority - Code paths involving these functions should be carefully checked.
- The list of known bad API functions is built in and can be easily customized with a configuration file based on
  `conf/rhabdomancer.toml`.
- Function names are matched without these decorations: leading dots and underscores (e.g., `_strcpy`), the prefixes
  of library aliases (e.g., `__o_malloc` in the Universal CRT, `__libc_system` and `__GI___snprintf` in glibc), and,
  for stubs and such aliases only, the numeric suffix that IDA appends to names already in use (e.g., `memset_0`).

> [!NOTE]
> Fortified functions (e.g., `__strcpy_chk`, used instead of `strcpy` when building with `_FORTIFY_SOURCE`) are
> deliberately not matched, since they are the checked variants of the listed functions. To also mark their calls,
> add them explicitly to a custom configuration (e.g., `"__strcpy_chk"` with the same priority as `strcpy`).

## Articles

- <https://hex-rays.com/blog/streamlining-vulnerability-research-idalib-rust-bindings>
- <https://hnsecurity.it/blog/streamlining-vulnerability-research-with-ida-pro-and-rust>

## See also

- <https://github.com/0xdea/ghidra-scripts/blob/main/Rhabdomancer.java>
- <https://docs.hex-rays.com/release-notes/9_0#headless-processing-with-idalib>
- <https://github.com/idalib-rs/idalib>
- <https://books.google.it/books/about/The_Art_of_Software_Security_Assessment.html>

## Installing

The easiest way to get the latest release is via [crates.io](https://crates.io/crates/rhabdomancer):

1. Download, install, and configure IDA (see <https://hex-rays.com/ida-pro>).
2. Install LLVM/Clang (see <https://rust-lang.github.io/rust-bindgen/requirements.html>).
3. On Linux/macOS, install as follows:
   ```sh
   export IDADIR=/path/to/ida # if not set, the build script will check common locations
   cargo install rhabdomancer --locked
   ```
   On Windows, instead, use the following commands:
   ```powershell
   $env:LIBCLANG_PATH="\path\to\clang+llvm\bin"
   $env:PATH="\path\to\ida;$env:PATH"
   $env:IDADIR="\path\to\ida" # if not set, the build script will check common locations
   cargo install rhabdomancer --locked
   ```

## Compiling

Alternatively, you can build from [source](https://github.com/0xdea/rhabdomancer):

1. Download, install, and configure IDA (see <https://hex-rays.com/ida-pro>).
2. Install LLVM/Clang (see <https://rust-lang.github.io/rust-bindgen/requirements.html>).
3. On Linux/macOS, compile as follows:
   ```sh
   git clone --depth 1 https://github.com/0xdea/rhabdomancer
   cd rhabdomancer
   export IDADIR=/path/to/ida # if not set, the build script will check common locations
   cargo build --release --locked
   ```
   On Windows, instead, use the following commands:
   ```powershell
   git clone --depth 1 https://github.com/0xdea/rhabdomancer
   cd rhabdomancer
   $env:LIBCLANG_PATH="\path\to\clang+llvm\bin"
   $env:PATH="\path\to\ida;$env:PATH"
   $env:IDADIR="\path\to\ida" # if not set, the build script will check common locations
   cargo build --release --locked
   ```

## Usage

1. Make sure IDA is properly configured with a valid license.
2. Optionally customize the list of known bad API functions: copy
   [`conf/rhabdomancer.toml`](https://github.com/0xdea/rhabdomancer/blob/master/conf/rhabdomancer.toml) (pick the tag
   that matches your installed version for its exact built-in list), edit the copy, and set the `RHABDOMANCER_CONFIG`
   environment variable to its path. The file must define the `high`, `medium`, and `low` arrays, and no other keys.
   Otherwise (or if the variable is empty), the built-in list is used, which is embedded in the binary at build time
   from `conf/rhabdomancer.toml` (editing that file requires a rebuild).
3. Make sure the `IDADIR` environment variable is set if your IDA installation is in a non-standard location.
4. Run as follows:
   ```sh
   rhabdomancer <binary_file>
   ```
   Any existing `.i64` IDB file will be updated; otherwise, a new IDB file will be created.
5. Open the resulting `.i64` IDB file with IDA.
6. Select `View` > `Open subviews` > `Bookmarks`
7. Enjoy your results conveniently collected into an IDA window.

> [!NOTE]
> Rhabdomancer also adds comments at marked call locations. Both bookmarks and comments are tagged as
> `[BAD n] <function_name>`, where `n` is the priority tier (0 = high, 1 = medium, 2 = low), so that scripts can
> search IDBs for them. This format is stable across releases.

## Compatibility

Only the latest IDA release is officially supported, but older versions may work as well. The following table
summarizes the latest compatible release for each IDA version:

| IDA version | Latest compatible release |
| ----------- | ------------------------- |
| v9.0.240925 | v0.2.4                    |
| v9.0.241217 | v0.3.5                    |
| v9.1.250226 | v0.6.2                    |
| v9.2.250908 | v0.7.6                    |
| v9.3.260213 | v0.8.1                    |
| v9.3.260327 | v0.9.0                    |
| v9.3.260421 | v0.9.3                    |
| v9.4.260714 | current release           |
| v9.4.260915 | current release           |

> [!NOTE]
> Check the [idalib-rs](https://github.com/idalib-rs/idalib) documentation for additional information.

## Credits

This project's development has been supported by the following organizations:

- [HN Security](https://hnsecurity.it)
- [Hex-Rays](https://hex-rays.com) via their [Contributor Program](https://hex-rays.com/contributor-program)

## Changelog

- [CHANGELOG.md](https://github.com/0xdea/rhabdomancer/blob/master/CHANGELOG.md)

## TODO

- Further enrich the known bad API function list (see <https://github.com/0xdea/semgrep-rules>).
- Consider broadening the scope of normalization in `normalize_name` to account for more cases.
- Follow calls through thunks outside `.plt` segments (e.g., MSVC incremental-linking `j_` thunks) to their callers.
- Consider an option to skip marking call locations in library code recognized by IDA (now only labeled `(lib)`).
- Implement serialized output to facilitate automated parsing and analysis.
- Implement a basic ruleset in the style of [VulFi](https://github.com/Accenture/VulFi)
  and [VulnFanatic](https://github.com/Martyx00/VulnFanatic).
