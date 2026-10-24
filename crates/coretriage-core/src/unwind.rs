//! Unwind each thread's stack. Starting from the `NT_PRSTATUS` register set, it walks frames
//! using DWARF call-frame information via `framehop`, reading stack and register memory from
//! the core image, and yields the return-address chain for symbolication.
