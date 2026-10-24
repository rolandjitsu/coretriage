# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities **privately** through GitHub's
[private vulnerability reporting](https://github.com/rolandjitsu/coretriage/security/advisories/new)
(the repository's **Security -> Report a vulnerability** tab). We aim to acknowledge a report
within a few days and will keep you updated as we work on a fix. Please do not open a public
issue for a security problem.

## Supported versions

coretriage is pre-1.0 and under active development. Security fixes land on the latest release;
pin a version and upgrade to pick them up.

## Scope: parsing untrusted cores

coretriage parses raw ELF core dumps and the modules they reference. A core dump is attacker
influenceable input (a crash can be triggered by hostile data), so a malformed or crafted core
must never read out of bounds, panic in a way that leaks memory, or execute code from the input.
Parsing bugs that violate this are in scope; report them privately as above.
