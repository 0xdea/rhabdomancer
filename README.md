# rhabdomancer

[![](https://img.shields.io/github/stars/0xdea/rhabdomancer.svg?style=flat&color=yellow)](https://github.com/0xdea/rhabdomancer)
[![](https://img.shields.io/github/forks/0xdea/rhabdomancer.svg?style=flat&color=green)](https://github.com/0xdea/rhabdomancer)
[![](https://img.shields.io/github/watchers/0xdea/rhabdomancer.svg?style=flat&color=red)](https://github.com/0xdea/rhabdomancer)
[![](https://img.shields.io/badge/twitter-%400xdea-blue.svg)](https://twitter.com/0xdea)
[![](https://img.shields.io/badge/mastodon-%40raptor-purple.svg)](https://infosec.exchange/@raptor)

> "The road to exploitable bugs is paved with unexploitable bugs."
>
> -- Mark Dowd

Rhabdomancer is a blazing fast IDA Pro headless plugin that locates all calls to potentially insecure API functions in
a binary file. Auditors can backtrace from these candidate points to find pathways allowing access from untrusted input.

## Features

* Blazing fast, headless user experience courtesy of IDA Pro and Binarly's idalib Rust bindings.
* Support for C/C++ binary targets compiled for any architecture implemented by IDA Pro.
* Bad API function call locations are printed to stdout and marked with comments in the IDB.
* Known bad API functions are grouped in tiers of badness to help prioritize the audit work.

## Blog post

* <https://security.humanativaspa.it/doing-vulnerability-research-with-ida-pro-and-rust>

## See also

* <https://github.com/0xdea/ghidra-scripts/blob/main/Rhabdomancer.java>
* <https://docs.hex-rays.com/release-notes/9_0#headless-processing-with-idalib>
* <https://github.com/binarly-io/idalib/>
* <https://books.google.it/books/about/The_Art_of_Software_Security_Assessment.html>

## Compiling

1. Download, install, and configure IDA Pro (see https://hex-rays.com/ida-pro).
2. Download and extract the IDA SDK (see https://docs.hex-rays.com/developer-guide).
3. Compile rhabdomancer as follows:
    ```sh
    $ git clone https://github.com/0xdea/rhabdomancer
    $ cd rhabdomancer
    $ export IDASDKDIR=/path/to/idasdk90 # or edit .cargo/config.toml
    $ cargo build --release
    ```

## Usage

1. Make sure IDA Pro is properly configured with a valid license.
2. Run rhabdomancer as follows:
    ```sh
    $ ./target/release/rhabdomancer [binary file]
    ```
3. Open the resulting `.i64` IDB file with IDA Pro.
4. Select `Search` > `Text...`, flag `Find all occurrences`, and search for `[BAD `.
5. Enjoy your results conveniently collected in an IDA Pro window.

## Tested with

* IDA Pro 9.0.240925 on macOS arm64.

## TODO

* Try the `bookmarks_t` API, despite it being cumbersome and having a `MAX_MARK_SLOT` of 1024.
* Enrich the known bad API function list (see <https://github.com/0xdea/semgrep-rules>).
* Implement regex pattern matching instead of .plt hack (`_func` in GUI is `.func` in idalib).
* Implement a basic ruleset in the style of <https://github.com/Accenture/VulFi>.
