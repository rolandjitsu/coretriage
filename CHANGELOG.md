# Changelog

All notable changes are recorded here. This project follows
[Conventional Commits](https://www.conventionalcommits.org/) and
[Semantic Versioning](https://semver.org/); releases are cut automatically by
[knope](https://knope.tech/) from the commit history, which fills in the sections below.
## 0.0.8 (2026-11-08)

### Features

- add a folded-stack emitter for flame graphs

## 0.0.7 (2026-11-08)

### Features

- name more signals (SIGQUIT, SIGTRAP, etc.)

## 0.0.6 (2026-11-08)

### Features

- resolve debug files via .gnu_debuglink

## 0.0.5 (2026-11-01)

### Features

- report build-id for modules without symbols

## 0.0.4 (2026-11-01)

### Features

- accept debuginfod layout in --debug-dir

## 0.0.3 (2026-11-01)

### Features

- resolve modules by build-id
- add optional debuginfod lookup

## 0.0.2 (2026-10-25)

### Features

- scaffold project
- add emitter trait with text, json
- parse ELF core notes
- add fault kind, number, and address
- build module map from NT_FILE
- unwind stacks via framehop
- resolve frames via addr2line
- add crash and hang signatures
- bucket cores in triage_batch
- surface the per-core signature

### Fixes

- send logs to stderr, not stdout
- pluralize the batch core count

## 0.0.1 (2026-10-25)

### Features

- scaffold project
- add emitter trait with text, json
- parse ELF core notes
- add fault kind, number, and address
- build module map from NT_FILE
- unwind stacks via framehop
- resolve frames via addr2line
- add crash and hang signatures
- bucket cores in triage_batch
- surface the per-core signature

### Fixes

- send logs to stderr, not stdout
- pluralize the batch core count
