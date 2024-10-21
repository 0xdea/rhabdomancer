# rhabdomancer

[![](https://img.shields.io/github/stars/0xdea/rhabdomancer.svg?style=flat&color=yellow)](https://github.com/0xdea/rhabdomancer)
[![](https://img.shields.io/github/forks/0xdea/rhabdomancer.svg?style=flat&color=green)](https://github.com/0xdea/rhabdomancer)
[![](https://img.shields.io/github/watchers/0xdea/rhabdomancer.svg?style=flat&color=red)](https://github.com/0xdea/rhabdomancer)
[![](https://img.shields.io/badge/twitter-%400xdea-blue.svg)](https://twitter.com/0xdea)
[![](https://img.shields.io/badge/mastodon-%40raptor-purple.svg)](https://infosec.exchange/@raptor)

> "The road to exploitable bugs is paved with unexploitable bugs."
>
> -- Mark Dowd

Rhabdomancer is a simple IDA Pro plugin that locates all calls to potentially insecure API functions in a binary file.
Auditors can backtrace from these candidate points to find pathways allowing access from untrusted input.

TODO description:

* C/C++ target
* Tiers of badness
* Briefly cover pros/cons of candidate point strategy
* Mention TAOSSA and other strategies
* Rust, idalib

Blog post:  
TODO

See also:  
https://github.com/0xdea/ghidra-scripts/blob/main/Rhabdomancer.java  
https://github.com/binarly-io/idalib/

## Compiling (macOS arm64)

```
[Download and install IDA Pro]
See https://hex-rays.com/ida-pro

[Download, extract, and compile the IDA SDK]
$ cd idasdk90
$ export PATH=~/idasdk90/bin:$PATH
$ make NDEBUG=1 __MAC__=1 __ARM__=1 __EA64__=1

[Compile rhabdomancer]
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
