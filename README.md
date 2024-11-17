# rhabdomancer

[![](https://img.shields.io/github/stars/0xdea/rhabdomancer.svg?style=flat&color=yellow)](https://github.com/0xdea/rhabdomancer)
[![](https://img.shields.io/crates/v/rhabdomancer?style=flat&color=green)](https://crates.io/crates/rhabdomancer)
[![](https://img.shields.io/crates/d/rhabdomancer?style=flat&color=red)](https://crates.io/crates/rhabdomancer)
[![](https://img.shields.io/badge/twitter-%400xdea-blue.svg)](https://twitter.com/0xdea)
[![](https://img.shields.io/badge/mastodon-%40raptor-purple.svg)](https://infosec.exchange/@raptor)
[![build](https://github.com/0xdea/rhabdomancer/actions/workflows/build.yml/badge.svg)](https://github.com/0xdea/rhabdomancer/actions/workflows/build.yml)
[![doc](https://github.com/0xdea/rhabdomancer/actions/workflows/doc.yml/badge.svg)](https://github.com/0xdea/rhabdomancer/actions/workflows/doc.yml)

> "The road to exploitable bugs is paved with unexploitable bugs."
>
> -- Mark Dowd

Rhabdomancer is a blazing fast IDA Pro headless plugin that locates all calls to potentially insecure API functions in
a binary file. Auditors can backtrace from these candidate points to find pathways allowing access from untrusted input.

![](https://raw.githubusercontent.com/0xdea/rhabdomancer/master/.img/screen01.png)

## Features

* Blazing fast, headless user experience courtesy of IDA Pro 9 and Binarly's idalib Rust bindings.
* Support for C/C++ binary targets compiled for any architecture implemented by IDA Pro.
* Bad API function call locations are printed to stdout and marked in the IDB.
* Known bad API functions are grouped in tiers of badness to help prioritize the audit work.
* The list of known bad API functions can be easily customized by editing `conf/rhabdomancer.toml`.

## Blog post

* <https://security.humanativaspa.it/doing-vulnerability-research-with-ida-pro-and-rust>

## See also

* <https://github.com/0xdea/ghidra-scripts/blob/main/Rhabdomancer.java>
* <https://docs.hex-rays.com/release-notes/9_0#headless-processing-with-idalib>
* <https://github.com/binarly-io/idalib/>
* <https://books.google.it/books/about/The_Art_of_Software_Security_Assessment.html>

## Installing

The easiest way to get the latest release is via [crates.io](https://crates.io/crates/rhabdomancer):

1. Download, install, and configure IDA Pro (see <https://hex-rays.com/ida-pro>).
2. Download and extract the IDA SDK (see <https://docs.hex-rays.com/developer-guide>).
3. Install rhabdomancer as follows:
   ```sh
   $ export IDASDKDIR=/path/to/idasdk90
   $ cargo install rhabdomancer
   ```

## Compiling

Alternatively, you can build from [source](https://github.com/0xdea/rhabdomancer):

1. Download, install, and configure IDA Pro (see <https://hex-rays.com/ida-pro>).
2. Download and extract the IDA SDK (see <https://docs.hex-rays.com/developer-guide>).
3. Compile rhabdomancer as follows:
    ```sh
    $ git clone https://github.com/0xdea/rhabdomancer
    $ cd rhabdomancer
    $ export IDASDKDIR=/path/to/idasdk90 # or edit .cargo/config.toml
    $ cargo build --release
    ```

## Usage

1. Make sure IDA Pro is properly configured with a valid license.
2. Customize the list of known bad API functions in `conf/rhabdomancer.toml` if needed.
3. Run rhabdomancer as follows:
    ```sh
    $ rhabdomancer [binary file]
    ```
4. Open the resulting `.i64` IDB file with IDA Pro.
5. Select `View` > `Open subviews` > `Bookmarks`
6. Enjoy your results conveniently collected in an IDA Pro window.

*Note: rhabdomancer also adds comments at marked call locations.*

## Tested with

* IDA Pro 9.0.240925 on macOS arm64.

## Changelog

* <https://github.com/0xdea/rhabdomancer/blob/master/CHANGELOG.md>

## TODO

* Enrich the known bad API function list (see <https://github.com/0xdea/semgrep-rules>).
* Implement a basic ruleset in the style of <https://github.com/Accenture/VulFi>.
