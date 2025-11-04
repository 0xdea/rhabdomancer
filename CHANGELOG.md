# Changelog for rhabdomancer

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

* Add `__isoc99_*scanf` and `_mbs*` family functions to the list of insecure functions.

### Changed

* Update dependencies.

## [0.7.2] - 2025-10-13

### Changed

* Improve documentation.
* Update dependencies.

## [0.7.1] - 2025-09-17

### Changed

* Update idalib to v0.7.2 and update other dependencies.

## [0.7.0] - 2025-09-15

### Changed

* Switch to idalib v0.7 and update other dependencies.
* Update documentation.
* Improve output messages.
* Update build and doc GitHub workflows.

## [0.6.2] - 2025-07-18

### Changed

* Update dependencies.

### Fixed

* Update LLVM version in Windows build action.

## [0.6.1] - 2025-06-13

### Added

* Add `ida-plugin.json` for <https://plugins.hex-rays.com/>.

### Changed

* Disable debug info to improve compile time.
* Update dependencies.

## [0.6.0] - 2025-05-23

### Added

* Add contents read permission to build CI.

### Changed

* Switch to idalib v0.6 and update other dependencies.
* Improve documentation.

### Fixed

* Address new clippy lints.

## [0.5.5] - 2025-05-09

### Changed

* Update dependencies.

### Fixed

* Update `sccache-action` version.

## [0.5.4] - 2025-03-29

### Added

* Add `security` category to Cargo.toml.

### Changed

* Refactor the integration test directory structure.
* Update dependencies.

## [0.5.3] - 2025-03-20

### Changed

* Improve documentation.

### Fixed

* Fix typo in documentation.

## [0.5.2] - 2025-03-19

### Changed

* Port to the `windows` family and update documentation.
* Update documentation to clarify LLVM/Clang requirement.
* Update dependencies.

## [0.5.1] - 2025-03-10

### Changed

* Update dependencies.
* Add `missing_docs` lint and improve documentation.
* Avoid generating documentation for private items.
* Improve CI effectiveness and performance.

## [0.5.0] - 2025-03-03

### Changed

* Follow idalib major version from now on.
* Switch to idalib v0.5.1 and update other dependencies.
* Update documentation and add a compatibility matrix.
* Make CI more robust for future IDA SDK updates.

### Removed

* Remove the target file check that is no longer necessary.

## [0.3.5] - 2025-02-28

### Changed

* Bump Rust edition to 2024 and update dependencies and CI.
* Switch to idalib v0.4.1 and update other dependencies.
* Improve error handling.
* Improve CI speed by removing redundant tasks.

## [0.3.4] - 2025-02-24

### Changed

* Update dependencies.
* Improve documentation.

## [0.3.3] - 2025-02-18

### Changed

* Make regex parsing logic more robust.
* Update dependencies.

## [0.3.2] - 2025-02-13

### Changed

* Refactor code to avoid unwrapping Options.
* Update dependencies.
* Improve documentation.

## [0.3.1] - 2025-02-03

### Changed

* Use `UpperHex` in output messages.
* Update dependencies.

## [0.3.0] - 2025-01-17

### Changed

* Disable compilation on non-unix target families.
* Update dependencies.

## [0.2.6] - 2025-01-10

### Changed

* Update dependencies.
* Improve documentation.

## [0.2.5] - 2024-12-20

### Added

* Document Linux as a supported platform and specify that Windows was not tested.

### Changed

* Bump to IDA Pro 9.0.241217 (9.0sp1).
* Switch to idalib v0.4 and update other dependencies.

## [0.2.4] - 2024-12-16

### Changed

* Update dependencies.

### Fixed

* Emit a warning in case the build script cannot find an IDA Pro installation.
* Document the `IDADIR` optional environment variable.

## [0.2.3] - 2024-12-04

### Changed

* Switch to idalib v0.3 and update other dependencies.
* Update doc workflow to include dependencies.

## [0.2.2] - 2024-11-25

### Added

* Mention the `conf/rhabdomancer.toml` configuration file in the documentation.
* Add a project logo.

### Changed

* Improve output and force IDA Pro to stay quiet via `idalib::force_batch_mode`.

## [0.2.1] - 2024-11-16

### Fixed

* Fix "configuration file not found" error in the [crates.io](https://crates.io/) package.

## [0.2.0] - 2024-11-16

### Added

* Add support for IDA Pro's `bookmarks_t` API that I've contributed to idalib.
* Add support for IDA Pro's search API that I've contributed to idalib (only used in tests).
* Add build and doc GitHub workflows as [documented](https://github.com/binarly-io/idalib/blob/master/GITHUB-ACTIONS.md)
  in idalib.

### Changed

* Switch to idalib v0.2 and update other dependencies.

### Fixed

* Improve the user experience when opening IDB files thanks to the new license manager API in idalib v0.2.
* Improve custom integration tests using the `bookmarks_t` API and search API.
* Exclude tests that include binary files from the [crates.io](https://crates.io/) package.

## [0.1.1] - 2024-11-08

### Added

* Add integration tests with a custom harness because they must run in the main thread.
* Add instructions for installing via `cargo install` in README and crate comments.
* Add Markdown links to version tags on release headings in CHANGELOG.

### Changed

* Instruct `cargo doc` to generate documentation also for private items.
* Update dependencies.

### Fixed

* Locally generate documentation that fails to build on docs.rs and host it on GitHub pages.

## [0.1.0] - 2024-11-05

* First release to be published to [crates.io](https://crates.io/).

[unreleased]: https://github.com/0xdea/rhabdomancer/compare/v0.7.2...HEAD

[0.7.2]: https://github.com/0xdea/rhabdomancer/compare/v0.7.1...v0.7.2

[0.7.1]: https://github.com/0xdea/rhabdomancer/compare/v0.7.0...v0.7.1

[0.7.0]: https://github.com/0xdea/rhabdomancer/compare/v0.6.2...v0.7.0

[0.6.2]: https://github.com/0xdea/rhabdomancer/compare/v0.6.1...v0.6.2

[0.6.1]: https://github.com/0xdea/rhabdomancer/compare/v0.6.0...v0.6.1

[0.6.0]: https://github.com/0xdea/rhabdomancer/compare/v0.5.5...v0.6.0

[0.5.5]: https://github.com/0xdea/rhabdomancer/compare/v0.5.4...v0.5.5

[0.5.4]: https://github.com/0xdea/rhabdomancer/compare/v0.5.3...v0.5.4

[0.5.3]: https://github.com/0xdea/rhabdomancer/compare/v0.5.2...v0.5.3

[0.5.2]: https://github.com/0xdea/rhabdomancer/compare/v0.5.1...v0.5.2

[0.5.1]: https://github.com/0xdea/rhabdomancer/compare/v0.5.0...v0.5.1

[0.5.0]: https://github.com/0xdea/rhabdomancer/compare/v0.3.5...v0.5.0

[0.3.5]: https://github.com/0xdea/rhabdomancer/compare/v0.3.4...v0.3.5

[0.3.4]: https://github.com/0xdea/rhabdomancer/compare/v0.3.3...v0.3.4

[0.3.3]: https://github.com/0xdea/rhabdomancer/compare/v0.3.2...v0.3.3

[0.3.2]: https://github.com/0xdea/rhabdomancer/compare/v0.3.1...v0.3.2

[0.3.1]: https://github.com/0xdea/rhabdomancer/compare/v0.3.0...v0.3.1

[0.3.0]: https://github.com/0xdea/rhabdomancer/compare/v0.2.6...v0.3.0

[0.2.6]: https://github.com/0xdea/rhabdomancer/compare/v0.2.5...v0.2.6

[0.2.5]: https://github.com/0xdea/rhabdomancer/compare/v0.2.4...v0.2.5

[0.2.4]: https://github.com/0xdea/rhabdomancer/compare/v0.2.3...v0.2.4

[0.2.3]: https://github.com/0xdea/rhabdomancer/compare/v0.2.2...v0.2.3

[0.2.2]: https://github.com/0xdea/rhabdomancer/compare/v0.2.1...v0.2.2

[0.2.1]: https://github.com/0xdea/rhabdomancer/compare/v0.2.0...v0.2.1

[0.2.0]: https://github.com/0xdea/rhabdomancer/compare/v0.1.1...v0.2.0

[0.1.1]: https://github.com/0xdea/rhabdomancer/compare/v0.1.0...v0.1.1

[0.1.0]: https://github.com/0xdea/rhabdomancer/releases/tag/v0.1.0
