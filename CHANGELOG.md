# Changelog for rhabdomancer

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

* Add markdown links to version tags on release headings in CHANGELOG.
* Add instructions for installing via `cargo install` in README and crate comments.
* Add integration tests without the default harness, because they must run in the main thread.
* Add support for the `bookmarks_t` API.

### Changed

* Update dependencies.

### Fixed

* Improved user experience when opening IDB files thanks to the new license manager API in idalib.

## [0.1.0] - 2024-11-05

* First release to be published on [crates.io](https://crates.io/).

### Added

* This CHANGELOG file to keep track of notable changes for each version of this project.

[unreleased]: https://github.com/0xdea/rhabdomancer/compare/v0.1.0...HEAD

[0.1.0]: https://github.com/0xdea/rhabdomancer/releases/tag/v0.1.0
