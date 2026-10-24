# Contributing

Thanks for contributing to coretriage. These guidelines keep history clean and review fast.

## Ground rules

1. Commits follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).
2. Keep commits small and self-contained so each can be reviewed on its own. Split large
   changes into incremental commits/PRs; never mix unrelated changes in one commit.
3. Every change ships with tests. Coverage should not drop.
4. CI must be green before review: formatting, clippy, and tests.
5. Address review feedback by amending the relevant commit and rebasing, not with follow-up
   `fix: typo` commits. Keep history linear.

## Commit messages

A Conventional Commits subject in the present tense, imperative voice (`feat: add the dwarf
unwinder`, not `added` or `adds`), then an optional body that explains *why* when it is not
obvious, wrapped at ~72 columns, ASCII only (no em-dash, no `--`).

AI-assisted commits disclose the assistant with an `Assisted-by:` trailer, following the kernel
[coding-assistants guidance](https://docs.kernel.org/process/coding-assistants.html). Do not use
`Co-Authored-By`.

```
feat(unwind): add the dwarf cfi unwinder

Register state comes from NT_PRSTATUS; framehop walks the frames using the
module's .eh_frame, reading stack memory from the core image.

Assisted-by: Claude:claude-opus-4-8
```

Agents have extra rules in [AGENTS.md](./AGENTS.md).

## Development

```shell
cargo build
cargo test --workspace --all-features
cargo fmt --all
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo llvm-cov --workspace --all-features --locked --summary-only   # coverage, matches CI
```

Triage a core locally:

```shell
cargo run -p coretriage -- --exe ./target/release/app core.1234
```

Install [prek](https://github.com/j178/prek) and enable the git hooks once. They run typos
and rustfmt on commit, a Conventional Commits check on the message, and clippy on push:

```shell
brew install prek   # or: cargo install --locked prek
prek install
```

## Rust style

Follow the [Rust Style Guide](https://doc.rust-lang.org/nightly/style-guide/); `rustfmt` and
`clippy` are enforced in CI. Prefer idiomatic Rust. Keep comments concise and reserved for the
non-obvious; do not narrate the code. Document every public item with rustdoc.

## Design

The system design and scope live in the [README](./README.md). Propose a change to it before a
change that alters the pipeline or the public model.
