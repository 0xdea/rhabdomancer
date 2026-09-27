# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

**Rhabdomancer** is a headless IDA 9.x plugin (written in Rust) that locates calls to potentially insecure API functions in binary files. It uses `idalib` — Rust bindings to the IDA SDK — and requires a valid IDA installation to build and run.

## Build Requirements

- IDA 9.x installation with `IDADIR` environment variable set
- LLVM/Clang (required by `idalib` for bindgen)
- Rust (edition 2024)

The `build.rs` script uses `idalib-build` to auto-configure IDA SDK linkage. It emits a warning (but does not fail) if `IDADIR` is unset.

## Commands

```bash
# Build
cargo build --release --locked     # optimized (LTO, stripped, O3)
cargo build --locked               # debug build

# Unit tests (standard test framework, no IDA database needed)
cargo test --lib --locked

# Integration tests (use a custom harness, not the standard Rust test framework)
cargo test --test tests --locked

# Lint & format (CI enforces these as errors)
cargo fmt --all --check
cargo clippy --all-targets --locked -- -D warnings

# Documentation (CI enforces this as an error via RUSTDOCFLAGS=-D warnings)
cargo doc --locked

# Dependency vulnerability audit (CI enforces this; requires cargo-audit)
cargo audit
```

CI's own `test` step only runs `cargo test --no-run` — a compile-only smoke check. Both test suites link against the IDA libraries, and the integration suite in `tests/main.rs` also needs a working IDA installation to analyze binaries, which CI runners don't have, so both only run locally.

## Architecture

Three source files:

- **`src/main.rs`** — CLI entry point. Parses a single binary path argument, calls `force_batch_mode()` to suppress IDA UI, then delegates to `lib::run()`.
- **`src/lib.rs`** — Core analysis logic. Public entry point: `run(filepath: impl AsRef<Path>) -> anyhow::Result<BookmarkIndex>`. Key types:
  - `KnownBadFunctionsConfig`: Mirrors the configuration file (`high`/`medium`/`low` name lists); only used as the deserialization source of `KnownBadFunctions`.
  - `KnownBadFunctions`: Loads `conf/rhabdomancer.toml` into a single `HashMap<String, Priority>` keyed by normalized name. Deserialized via `#[serde(try_from = "KnownBadFunctionsConfig")]`: the `TryFrom` impl normalizes every name and rejects the configuration at the first name that is empty or is listed under multiple priorities (after normalization), so `load()` deserializes straight into `Self`. Duplicates are detected with `*functions.entry(name).or_insert(priority) != priority`, which keeps the first occurrence and compares against it in one expression. `check_function()` gets a function's name and delegates to `priority_of()`, a single lookup on a `&str` that is unit-testable without an IDB.
  - `BadFunctions<'a>`: Scans the opened IDB for calls to bad functions and annotates them with IDA bookmarks and inline comments (`[BAD 0]`/`[BAD 1]`/`[BAD 2]`).
  - `Priority` enum: `High`/`Medium`/`Low` — maps to BAD 0/1/2; has `tag_prefix()` (hardcoded `[BAD n]` tags, which must stay in sync with the `PREFIX` constant) and `description()` helpers.
  - `traverse_xrefs()`: Iteratively walks cross-references using an explicit `Vec` stack. Handles `.plt` thunk indirection for ELF binaries.
  - `BadFunctions::is_in_plt()`: Checks whether an address falls within a `.plt` segment, using the address ranges of all `.plt*` segments collected once in `find_all()` (no per-call FFI lookups). The ranges are half-open `Range<Address>` values, matching IDA's `range_t` (`end_ea` excluded).
  - `normalize_name()`: Strips leading dots/underscores from function names for cross-platform matching.
  - Output convention: scan results (bad-function headers and call-site locations) print to stdout via `println!`; everything else (banners, progress, summary/timing, errors) prints to stderr via `eprintln!`. Preserve this split when adding new output.
- **Unit tests** — `#[cfg(test)] mod tests` at the end of `src/lib.rs` covers `KnownBadFunctions` without an IDB: priority mapping, normalization of both configuration and function names, merging of duplicates within the same priority, rejection of names that normalize to empty (and no match for function names that do), rejection of names listed under multiple priorities (via `TryFrom` and via TOML deserialization, checking the error message), and validity of the shipped `conf/rhabdomancer.toml` (embedded with `include_str!`, so a duplicate there fails the unit tests).
- **`tests/main.rs`** — Integration test with three scenarios against `tests/data/ls`:
  1. Default config: asserts exactly 86 marked locations, then verifies bookmark count, that every bookmark description starts with `[BAD `, comment count, and that every comment starts with `[BAD `.
  2. Idempotency: second run on the same IDB must return 0 new marks.
  3. Custom config via `RHABDOMANCER_CONFIG`: writes a minimal TOML to `tests/data/custom.toml`, asserts exactly 13 marks, and checks all bookmarks start with `[BAD 1]` (medium priority). Also exercises `normalize_name` since the custom config includes decorated names (`_fwrite`, `.memset`).
  - Uses a `show_everything()` helper that enables hidden comments/functions/instructions/segments before checking bookmark and comment content.

## Configuration

All "bad" functions are defined in `conf/rhabdomancer.toml`, grouped into `high`, `medium`, and `low` arrays. The config path can be overridden with the `RHABDOMANCER_CONFIG` environment variable. The loader uses the `config` crate with serde deserialization. Each name may appear under only one priority (leading dots/underscores are ignored when comparing names); otherwise loading fails with an error naming the (normalized) duplicate. Repeats within the same priority are harmless and merged. Entries that are empty once normalized (e.g. `""`, `"_"`, `"."`) are also rejected, with an error showing the original spelling.

## Lint Policy

The workspace `Cargo.toml` enables aggressive lints. Notably forbidden everywhere except tests:

- `unwrap`, `expect`, `panic`, `todo`, `unimplemented`, `unreachable`, `dbg_macro`
- Unsafe blocks require a `reason` attribute

`clippy::min_ident_chars` is enabled, so single-character identifiers (e.g. `|s|`, `for f in`, `for i in`) are flagged — use descriptive names like `name`, `func`, `idx`.

Use `#[expect(clippy::some_lint, reason = "...")]` to locally suppress a specific lint anywhere it genuinely cannot be avoided — in both library code and tests. Examples already in the codebase: `arithmetic_side_effects` (`BookmarkIndex` counter), `else_if_without_else` (empty else branch), `expect_used`/`panic_in_result_fn` (test assertions), `as_conversions` (casting `BookmarkIndex` to `usize` in tests). `env::set_var`/`remove_var` are `unsafe` in Rust edition 2024; wrap them in `unsafe {}` with a `// Safety:` comment explaining the single-threaded context, as the existing test does.

## IDA Integration Notes

- `IDB::open_with(path, true, true)` opens or creates an `.i64` IDB file with auto-analysis enabled and the database kept after closing.
- `idalib::force_batch_mode()` must be called before opening any database (suppresses IDA UI).
- Annotation is idempotent — existing bookmarks/comments are not duplicated.
- `.plt` sections in ELF binaries require following one level of thunk indirection to reach the real import; `traverse_xrefs` handles this.

## CI Workflows

- **`build.yml`** — lint/build/test matrix across Linux, macOS, and Windows, plus a `zizmor` job that audits `.github/workflows/*.yml` for security issues (credential handling, injection, etc.).
- **`doc.yml`** — builds rustdoc and pushes it to the `gh-pages` branch on `v*` tags; its `checkout` step needs persisted git credentials to `git push` later, so it carries a `# zizmor: ignore[artipacked]` suppression comment.
- To suppress a specific zizmor finding, add an inline `# zizmor: ignore[<rule-id>]` comment on the flagged step with a short justification, rather than disabling the rule globally.
