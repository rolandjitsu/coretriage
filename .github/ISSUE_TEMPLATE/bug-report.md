---
name: Bug Report
about: Report something that does not work as documented
title: "[BUG] "
labels: bug
assignees: ''

---

**Describe the bug**
A clear and concise description of what goes wrong.

**How to reproduce**
The command you ran and, if possible, a small core that shows the problem:

```sh
coretriage --exe ./app core.1234
```

If the core cannot be shared, describe how it was produced (the signal, or `gcore` on a
hung process) and the target it came from.

**Expected behavior**
What you expected to happen instead.

**Environment**
- coretriage version (`coretriage --version`):
- origin of the core: Linux distro / arch, and how it was captured (crash vs `gcore`):
- host you ran coretriage on (OS / arch):
- rustc version if built from source (`rustc --version`):

**Additional context**
Anything else that helps: a backtrace (`RUST_BACKTRACE=1`), the `--sysroot` / `--exe`
paths in use, and whether it reproduces under `--release`.
