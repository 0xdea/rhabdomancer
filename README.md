# rhabdomancer

[![](https://img.shields.io/github/stars/0xdea/rhabdomancer.svg?style=flat&color=yellow)](https://github.com/0xdea/rhabdomancer)
[![](https://img.shields.io/github/forks/0xdea/rhabdomancer.svg?style=flat&color=green)](https://github.com/0xdea/rhabdomancer)
[![](https://img.shields.io/github/watchers/0xdea/rhabdomancer.svg?style=flat&color=red)](https://github.com/0xdea/rhabdomancer)
[![](https://img.shields.io/badge/twitter-%400xdea-blue.svg)](https://twitter.com/0xdea)
[![](https://img.shields.io/badge/mastodon-%40raptor-purple.svg)](https://infosec.exchange/@raptor)

> "The road to exploitable bugs is paved with unexploitable bugs."
>
> -- Mark Dowd

Rhabdomancer is a simple IDA Pro headless plugin that locates all calls to potentially insecure API functions in a
binary file. Auditors can backtrace from these candidate points to find pathways allowing access from untrusted input.

TODO description:

* C/C++ target
* Tiers of badness
* Briefly cover pros/cons of candidate point strategy
* Mention TAOSSA and other strategies
* Rust, idalib, headless

Blog post:  
TODO

See also:  
https://github.com/0xdea/ghidra-scripts/blob/main/Rhabdomancer.java  
https://github.com/Accenture/VulFi  
https://docs.hex-rays.com/release-notes/9_0#headless-processing-with-idalib  
https://github.com/binarly-io/idalib/

## Compiling

1. Download, install, and configure IDA Pro (see https://hex-rays.com/ida-pro)
2. Download and extract the IDA SDK (see https://docs.hex-rays.com/developer-guide)
3. Compile rhabdomancer (macOS example):

```
$ export IDASDKDIR=/path/to/idasdk90 # or edit .cargo/config.toml
$ cargo build --release
```

## Usage

```
TODO
```

## Examples

TODO:

```sh
TODO
```

TODO:

```sh
TODO
```

## Tested with

* IDA Pro 9.0.240925 on macOS arm64

## TODO

* TODO
