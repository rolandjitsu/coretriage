**What kind of change does this PR introduce?**
- [ ] fix
- [ ] feat
- [ ] refactor
- [ ] perf
- [ ] docs
- [ ] test
- [ ] build / ci
- [ ] chore

**Summary**
Explain the motivation. What problem does this solve? Link any related issue.

**Tests**
- [ ] Added / updated tests (unit, plus a golden-core fixture where it fits)
- [ ] Not relevant, because: ...

**Checklist**
- [ ] CI is green locally: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`, `cargo test --workspace --all-features`
- [ ] Commits follow Conventional Commits; AI-assisted commits carry an `Assisted-by:` trailer (see CONTRIBUTING.md / AGENTS.md)
- [ ] Preserves the invariants: no new dependency without reason, and parsing an untrusted core stays panic-free and in-bounds
- [ ] rustdoc / README updated if the public API, CLI, or behavior changed

**Breaking change?**
If yes, describe the impact and the migration path (public API or CLI semantics).
