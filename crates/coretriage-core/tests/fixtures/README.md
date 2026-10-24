# Test fixtures

Golden cores generated in a Linux x86_64 container, committed here.

Each fixture is a small ELF core dump (crash or hang) paired with the executable and any
shared objects needed to unwind and symbolicate it, so the triage tests run hermetically on
any host without producing cores locally. Regenerate them with the container recipe described
in the repository README.
