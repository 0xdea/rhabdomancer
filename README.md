# rhabdomancer

[![](https://img.shields.io/github/stars/0xdea/rhabdomancer.svg?style=flat&color=yellow)](https://github.com/0xdea/rhabdomancer)
[![](https://img.shields.io/crates/v/rhabdomancer?style=flat&color=green)](https://crates.io/crates/rhabdomancer)
[![](https://img.shields.io/crates/d/rhabdomancer?style=flat&color=red)](https://crates.io/crates/rhabdomancer)
[![](https://img.shields.io/badge/ida-9.2-lightcoral)](https://hex-rays.com/ida-pro)
[![](https://img.shields.io/badge/twitter-%400xdea-blue.svg)](https://twitter.com/0xdea)
[![](https://img.shields.io/badge/mastodon-%40raptor-purple.svg)](https://infosec.exchange/@raptor)
[![build](https://github.com/0xdea/rhabdomancer/actions/workflows/build.yml/badge.svg)](https://github.com/0xdea/rhabdomancer/actions/workflows/build.yml)
[![doc](https://github.com/0xdea/rhabdomancer/actions/workflows/doc.yml/badge.svg)](https://github.com/0xdea/rhabdomancer/actions/workflows/doc.yml)

> "The road to exploitable bugs is paved with unexploitable bugs."
>
> -- Mark Dowd

Rhabdomancer is a blazing fast IDA Pro headless plugin that locates calls to potentially insecure API functions in
a binary file. Auditors can backtrace from these candidate points to find pathways allowing access to untrusted input.

![](https://raw.githubusercontent.com/0xdea/rhabdomancer/master/.img/screen01.png)

## Features

* Blazing fast, headless user experience courtesy of IDA Pro 9.x and Binarly's idalib Rust bindings.
* Support for C/C++ binary targets compiled for any architecture implemented by IDA Pro.
* Bad API function call locations are printed to stdout and marked in the IDB.
* Known bad API functions are grouped in tiers of badness to help prioritize the audit work.
    * [BAD 0] High priority - Functions that are generally considered insecure.
    * [BAD 1] Medium priority - Interesting functions that should be checked for insecure use cases.
    * [BAD 2] Low priority - Code paths involving these functions should be carefully checked.
* The list of known bad API functions can be easily customized by editing `conf/rhabdomancer.toml`.

## Blog posts

* <https://hex-rays.com/blog/streamlining-vulnerability-research-idalib-rust-bindings>
* <https://hnsecurity.it/blog/streamlining-vulnerability-research-with-ida-pro-and-rust>

## See also

* <https://github.com/0xdea/ghidra-scripts/blob/main/Rhabdomancer.java>
* <https://docs.hex-rays.com/release-notes/9_0#headless-processing-with-idalib>
* <https://github.com/binarly-io/idalib>
* <https://books.google.it/books/about/The_Art_of_Software_Security_Assessment.html>

## Installing

The easiest way to get the latest release is via [crates.io](https://crates.io/crates/rhabdomancer):

1. Download, install, and configure IDA Pro (see <https://hex-rays.com/ida-pro>).
2. Install LLVM/Clang (see <https://rust-lang.github.io/rust-bindgen/requirements.html>).
3. On Linux/macOS, install as follows:
    ```sh
    export IDADIR=/path/to/ida # if not set, the build script will check common locations
    cargo install rhabdomancer
    ```
   On Windows, instead, use the following commands:
    ```powershell
    $env:LIBCLANG_PATH="\path\to\clang+llvm\bin"
    $env:PATH="\path\to\ida;$env:PATH"
    $env:IDADIR="\path\to\ida" # if not set, the build script will check common locations
    cargo install rhabdomancer
    ```

## Compiling

Alternatively, you can build from [source](https://github.com/0xdea/rhabdomancer):

1. Download, install, and configure IDA Pro (see <https://hex-rays.com/ida-pro>).
2. Install LLVM/Clang (see <https://rust-lang.github.io/rust-bindgen/requirements.html>).
3. On Linux/macOS, compile as follows:
    ```sh
    git clone --depth 1 https://github.com/0xdea/rhabdomancer
    cd rhabdomancer
    export IDADIR=/path/to/ida # if not set, the build script will check common locations
    cargo build --release
    ```
   On Windows, instead, use the following commands:
    ```powershell
    git clone --depth 1 https://github.com/0xdea/rhabdomancer
    cd rhabdomancer
    $env:LIBCLANG_PATH="\path\to\clang+llvm\bin"
    $env:PATH="\path\to\ida;$env:PATH"
    $env:IDADIR="\path\to\ida" # if not set, the build script will check common locations
    cargo build --release
    ```

## Usage

1. Make sure IDA Pro is properly configured with a valid license.
2. Customize the list of known bad API functions in `conf/rhabdomancer.toml` if needed.
3. Run as follows:
    ```sh
    rhabdomancer <binary_file>
    ```
   Any existing `.i64` IDB file will be updated; otherwise, a new IDB file will be created.
4. Open the resulting `.i64` IDB file with IDA Pro.
5. Select `View` > `Open subviews` > `Bookmarks`
6. Enjoy your results conveniently collected into an IDA Pro window.

*Note: rhabdomancer also adds comments at marked call locations.*

## Compatibility

* IDA Pro 9.0.240925 - Latest compatible: v0.2.4.
* IDA Pro 9.0.241217 - Latest compatible: v0.3.5.
* IDA Pro 9.1.250226 - Latest compatible: v0.6.2.
* IDA Pro 9.2.250908 - Latest compatible: current version.

*Note: check [idalib](https://github.com/binarly-io/idalib) documentation for additional information.*

## Changelog

* [CHANGELOG.md](CHANGELOG.md)

## TODO

* Enrich the known bad API function list (see <https://github.com/0xdea/semgrep-rules>).
* Consider converting `traverse_xrefs` to an iterative walk to avoid potential stack overflows and infinite loops.
* Consider broadening the scope of normalization in `normalize_name` to account for more cases.
* Implement a basic ruleset in the style of [VulFi](https://github.com/Accenture/VulFi)
  and [VulnFanatic](https://github.com/Martyx00/VulnFanatic).
