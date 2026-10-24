//! Parse a raw ELF core dump. Reads the `PT_LOAD` segments (the saved memory image) and the
//! `PT_NOTE` segment, pulling `NT_PRSTATUS` (per-thread register sets) and `NT_FILE` (the
//! file-backed mapping table) to recover threads and the module map. Memory is read lazily
//! over an mmap of the core, so large cores do not have to be loaded in full.
