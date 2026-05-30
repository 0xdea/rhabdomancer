# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

**Rhabdomancer** is a headless IDA Pro 9.x plugin (written in Rust) that locates calls to potentially insecure API functions in binary files. It uses `idalib` — Rust bindings to the IDA Pro SDK — and requires a valid IDA Pro installation to build and run.

## Build Requirements

- IDA Pro 9.x installation with `IDADIR` environment variable set
- LLVM/Clang (required by `idalib` for bindgen)
- Rust (edition 2024)

The `build.rs` script uses `idalib-build` to auto-configure IDA SDK linkage. It emits a warning (but does not fail) if `IDADIR` is unset.

## Commands

```bash
# Build
cargo build --release     # optimized (LTO, stripped, O3)
cargo build               # debug build

# Test (uses a custom harness, not the standard Rust test framework)
cargo test --test tests

# Lint & format (CI enforces these as errors)
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings

# Documentation
cargo doc
```

## Architecture

Three source files:

- **`src/main.rs`** — CLI entry point. Parses a single binary path argument, calls `force_batch_mode()` to suppress IDA UI, then delegates to `lib::run()`.
- **`src/lib.rs`** — Core analysis logic. Key types:
  - `KnownBadFunctions`: Loads `conf/rhabdomancer.toml`, normalizes function names for matching.
  - `BadFunctions<'a>`: Scans the opened IDB for calls to bad functions and annotates them with IDA bookmarks and inline comments (`[BAD 0]`/`[BAD 1]`/`[BAD 2]`).
  - `Priority` enum: `High`/`Medium`/`Low` — maps to BAD 0/1/2.
  - `traverse_xrefs()`: Iteratively walks cross-references using an explicit `Vec` stack. Handles `.plt` thunk indirection for ELF binaries.
  - `normalize_name()`: Strips leading dots/underscores from function names for cross-platform matching.
- **`tests/main.rs`** — Integration test with three scenarios against `tests/data/ls`:
  1. Default config: asserts exactly 86 marked locations, then verifies bookmark and comment content.
  2. Idempotency: second run on the same IDB must return 0 new marks.
  3. Custom config via `RHABDOMANCER_CONFIG`: writes a minimal TOML to `tests/data/custom.toml`, asserts exactly 13 marks, and checks all bookmarks carry the expected priority tag. Also exercises `normalize_name` since the custom config includes decorated names (`_fwrite`, `.memset`).

## Configuration

All "bad" functions are defined in `conf/rhabdomancer.toml`, grouped into `high`, `medium`, and `low` arrays. The config path can be overridden with the `RHABDOMANCER_CONFIG` environment variable. The loader uses the `config` crate with serde deserialization.

## Lint Policy

The workspace `Cargo.toml` enables aggressive lints. Notably forbidden everywhere except tests:
- `unwrap`, `expect`, `panic`, `todo`, `unimplemented`, `unreachable`, `dbg_macro`
- Unsafe blocks require a `reason` attribute

Tests use `#[expect(clippy::expect_used, reason = "...")]` to locally permit panics. Follow this pattern when adding test code. `env::set_var`/`remove_var` are `unsafe` in Rust edition 2024; wrap them in `unsafe {}` with a `// Safety:` comment explaining the single-threaded context, as the existing test does.

## IDA Pro Integration Notes

- `idalib::open_database()` opens or creates an `.i64` IDB file with auto-analysis enabled.
- `idalib::force_batch_mode()` must be called before opening any database (suppresses IDA UI).
- Annotation is idempotent — existing bookmarks/comments are not duplicated.
- `.plt` sections in ELF binaries require following one level of thunk indirection to reach the real import; `traverse_xrefs` handles this.
