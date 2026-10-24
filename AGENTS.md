# AGENTS.md

Guidance for AI coding agents in this repo. Human contributors: see [CONTRIBUTING.md](./CONTRIBUTING.md).

## Workflow

- Clarify the design before implementing. For anything non-trivial, agree on the approach first;
  prefer a short note in the [README](./README.md) over jumping to code. The README is the
  working spec: the pipeline and scope live there.
- One unit of change per commit. Never mix unrelated changes. Present the change for review
  before committing.
- Every change ships with tests. Run local CI before calling it done, and do not claim it passes
  without running it.
- Verify against the code and the tools: read before you answer, run before you assert.

Local CI:

```shell
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features
```

## Writing: code, comments, docs, commits

- Keep it minimal: the least that is correct and complete, no essays. This holds for docs as much
  as for code and commits. Explain the non-obvious; do not narrate the obvious.
- ASCII only. No em-dash and no `--`; write `-`. Use `->` not the arrow glyph, `!=` not the
  not-equal glyph, straight quotes for curly ones, and the same for every other non-ASCII glyph.
- Comments justify *why*, not *what*. Delete any comment that restates the code.
- Do not use the word "seam"; say boundary, interface, or extension point. Do not use "bespoke";
  say "custom". Use "etc.", not "...", when a list trails off.

## Commits

- Conventional Commits (see CONTRIBUTING.md). Write the subject in the present tense, imperative
  voice: `feat: add the dwarf unwinder`, not `added` or `adds`.
- Keep the body minimal, or omit it. A good subject plus the diff is usually enough; add a body
  only for what the code cannot show (why, a trade-off, a non-obvious consequence).
- Subject <= 50 characters; wrap body lines at ~72 columns. The `committed` hook and CI enforce it.
- Disclose AI with an `Assisted-by: Claude:claude-opus-4-8` trailer. Never `Co-Authored-By`, and
  never add a human's `Signed-off-by`.

## Tests

- Unit tests inline (`#[cfg(test)] mod tests`); public-surface and cross-crate tests in `tests/`.
- Put helpers *after* the tests that use them.
- Golden cores live in `crates/coretriage-core/tests/fixtures`, generated in a Linux x86_64
  container and committed, so tests run hermetically without producing cores on the host.
- Coverage must not drop. Keep line coverage at or above its current level. Measure with
  `cargo llvm-cov --workspace --all-features --summary-only`, matching CI.

## Terminology

- **core**: a raw ELF core dump - the saved memory image plus notes (`NT_PRSTATUS`, `NT_FILE`).
- **module**: the executable or a shared object mapped into the crashed process.
- **frame**: one entry in a thread's unwound backtrace (module, function, file, line).
- **fault**: what took the process down - a fatal `Signal(n)`, or a `Hang` (a core taken from a
  live, stuck process).
- **signature**: a stable hash of the normalized crashing backtrace.
- **bucket**: a group of cores that share a signature.

## Code conventions

- Document every public item with rustdoc; `#![warn(missing_docs)]` is on in the library.
- Import a type by one path and use it consistently (a single `use std::path::PathBuf`, not mixed
  inline paths).
- Keep dependencies minimal and pure-Rust where practical; do not add a dependency without a
  stated reason. All deps are centralized in the root `[workspace.dependencies]`; members use
  `foo.workspace = true`.
- The pipeline stages are private modules (`core`, `maps`, `unwind`, `symbolize`, `signature`,
  `aggregate`, `report`); the public surface is `model`, `error`, and the two entry points.

## CI workflows

- GitHub Actions live in `.github/workflows`. Write the workflow `name:`, every job name, and
  every named step in Sentence case, matching `ci.yml`.
- Keep workflows minimal and scoped to one purpose; prefer the built-in `GITHUB_TOKEN`.

## Architecture

- The system design lives in the [README](./README.md); keep it in sync. There is no separate
  design doc or ADR directory - record design decisions in the README.
