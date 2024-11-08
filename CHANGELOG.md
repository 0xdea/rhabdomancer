# Changelog for rhabdomancer

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

* **TODO** Add support for IDA Pro's `bookmarks_t` API that I've implemented in idalib.
* **TODO** Add integration tests without the default harness, because they must run in the main thread.

### Fixed

* **TODO** Improve user experience when opening IDB files thanks to the new license manager API in idalib.

## [0.1.1] - 2024-11-08

### Added

* Add instructions for installing via `cargo install` in README and crate comments.
* Add markdown links to version tags on release headings in CHANGELOG.

### Changed

* Instruct `cargo doc` to generate documentation also for private items.
* Update dependencies.

### Fixed

* Locally generate documentation that fails to build on docs.rs and host it on GitHub pages.

## [0.1.0] - 2024-11-05

* First release to be published on [crates.io](https://crates.io/).

[unreleased]: https://github.com/0xdea/rhabdomancer/compare/v0.1.1...HEAD

[0.1.1]: https://github.com/0xdea/rhabdomancer/compare/v0.1.0...v0.1.1

[0.1.0]: https://github.com/0xdea/rhabdomancer/releases/tag/v0.1.0
