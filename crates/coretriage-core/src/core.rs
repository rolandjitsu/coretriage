//! Parse a raw ELF core dump's notes into the internal [`ParsedCore`]. v0.1 reads the
//! per-thread status notes (`NT_PRSTATUS`) to recover each thread id and the fatal signal,
//! which is enough to tell a crash (a fatal signal) from a hang (a core taken from a live
//! process, where there is no signal). Module mappings (`NT_FILE`) and registers are read by
//! the later pipeline stages that consume them.

use object::Endianness;
use object::elf::{FileHeader64, PT_NOTE};
use object::read::elf::{FileHeader, ProgramHeader};

use crate::model::FaultKind;
use crate::{Error, Result};

/// Note type for a thread's status record (`struct elf_prstatus`).
const NT_PRSTATUS: u32 = 1;

/// A core dump parsed into the data the pipeline needs.
#[derive(Debug, Clone)]
pub(crate) struct ParsedCore {
    /// Threads in the order the core records them; the crashing thread is first.
    pub threads: Vec<ParsedThread>,
    /// What took the process down.
    pub fault: FaultKind,
    /// The crashing thread's id, or `None` for a hang.
    pub crashing_tid: Option<i32>,
}

/// One thread recovered from an `NT_PRSTATUS` note.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ParsedThread {
    /// Kernel thread id (`pr_pid`).
    pub tid: i32,
    /// Signal that stopped the thread (`pr_cursig`); 0 when there was none.
    pub cursig: i32,
}

/// Parse the notes of an ELF core dump.
pub(crate) fn parse(data: &[u8]) -> Result<ParsedCore> {
    let elf = FileHeader64::<Endianness>::parse(data)
        .map_err(|e| Error::Parse(format!("elf header: {e}")))?;
    let endian = elf
        .endian()
        .map_err(|e| Error::Parse(format!("endianness: {e}")))?;
    let headers = elf
        .program_headers(endian, data)
        .map_err(|e| Error::Parse(format!("program headers: {e}")))?;

    let mut threads = Vec::new();
    for ph in headers {
        if ph.p_type(endian) != PT_NOTE {
            continue;
        }
        let Some(mut notes) = ph
            .notes(endian, data)
            .map_err(|e| Error::Parse(format!("notes: {e}")))?
        else {
            continue;
        };
        while let Some(note) = notes
            .next()
            .map_err(|e| Error::Parse(format!("note: {e}")))?
        {
            if note.n_type(endian) == NT_PRSTATUS {
                threads.push(parse_prstatus(note.desc())?);
            }
        }
    }

    let crashing = *threads
        .first()
        .ok_or_else(|| Error::Parse("no NT_PRSTATUS note; not a core dump?".to_string()))?;
    let (fault, crashing_tid) = if crashing.cursig == 0 {
        (FaultKind::Hang, None)
    } else {
        (FaultKind::Signal(crashing.cursig), Some(crashing.tid))
    };

    Ok(ParsedCore {
        threads,
        fault,
        crashing_tid,
    })
}

/// Read the fields we need from a `struct elf_prstatus` descriptor (x86_64 layout):
/// `pr_cursig` is a `short` at offset 12 and `pr_pid` an `int` at offset 32.
fn parse_prstatus(desc: &[u8]) -> Result<ParsedThread> {
    let cursig = i16::from_le_bytes(read_arr(desc, 12)?) as i32;
    let tid = i32::from_le_bytes(read_arr(desc, 32)?);
    Ok(ParsedThread { tid, cursig })
}

/// Read a fixed-size little-endian field from `bytes` at `offset`, or fail if it is short.
fn read_arr<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N]> {
    bytes
        .get(offset..offset + N)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| Error::Parse(format!("note truncated at offset {offset}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::load_core;

    #[test]
    fn segv_core_is_single_thread_sigsegv() {
        let core = parse(&load_core("segv")).expect("parse segv core");
        assert_eq!(core.threads.len(), 1);
        assert_eq!(core.fault, FaultKind::Signal(11));
        assert_eq!(core.crashing_tid, Some(core.threads[0].tid));
    }

    #[test]
    fn abort_core_is_sigabrt() {
        let core = parse(&load_core("abort")).expect("parse abort core");
        assert_eq!(core.threads.len(), 1);
        assert_eq!(core.fault, FaultKind::Signal(6));
    }

    #[test]
    fn hang_core_has_four_threads_and_no_signal() {
        let core = parse(&load_core("hang")).expect("parse hang core");
        assert_eq!(core.threads.len(), 4);
        assert_eq!(core.fault, FaultKind::Hang);
        assert_eq!(core.crashing_tid, None);
    }

    #[test]
    fn rejects_non_core_input() {
        assert!(parse(b"this is not an ELF file").is_err());
    }
}
