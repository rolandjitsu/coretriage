//! Parse a raw ELF core dump's notes into the internal [`ParsedCore`]. It reads the
//! per-thread status notes (`NT_PRSTATUS`) for each thread's id, registers, and the fatal
//! signal, and the signal-info note (`NT_SIGINFO`) for the faulting address. Together they
//! tell a crash (a fatal signal) from a hang (a core taken from a live process, where there
//! is no signal). It also exposes the raw `NT_FILE` mapping note for [`crate::maps`] and the
//! `PT_LOAD` segment table for the core memory accessor in [`crate::unwind`].

use object::Endianness;
use object::elf::{FileHeader64, PT_LOAD, PT_NOTE};
use object::read::elf::{FileHeader, ProgramHeader};

use crate::model::FaultKind;
use crate::{Error, Result};

/// Note type for a thread's status record (`struct elf_prstatus`).
const NT_PRSTATUS: u32 = 1;
/// Note type for a thread's signal info (`siginfo_t`).
const NT_SIGINFO: u32 = 0x5349_4749;
/// Note type for the file-backed mapping table (`"FILE"` little-endian).
const NT_FILE: u32 = 0x4649_4c45;

/// A core dump parsed into the data the pipeline needs.
#[derive(Debug, Clone)]
pub(crate) struct ParsedCore {
    /// Threads in the order the core records them; the crashing thread is first.
    pub threads: Vec<ParsedThread>,
    /// What took the process down.
    pub fault: FaultKind,
    /// The crashing thread's id, or `None` for a hang.
    pub crashing_tid: Option<i32>,
    /// File-backed memory image: the `PT_LOAD` segments, for reading process memory by
    /// virtual address (stack, in-memory ELF headers) during unwinding.
    pub segments: Vec<LoadSegment>,
    /// Raw `NT_FILE` note descriptor, parsed into the module map by [`crate::maps`]; `None`
    /// when the core carries no mapping table.
    pub nt_file: Option<Vec<u8>>,
}

/// One `PT_LOAD` segment: a run of process memory backed by bytes in the core file.
#[derive(Debug, Clone, Copy)]
pub(crate) struct LoadSegment {
    /// First virtual address the segment covers.
    pub vaddr: u64,
    /// Bytes of the segment actually present in the core (its memory may be larger).
    pub filesz: u64,
    /// Offset of those bytes within the core file.
    pub offset: u64,
}

/// Read process memory out of a core by virtual address, over its `PT_LOAD` segments. Only
/// memory actually saved in the core (a segment's `filesz`) is readable; anything else
/// (unmapped, or pages the kernel elided) reads as absent.
pub(crate) struct CoreMemory<'a> {
    data: &'a [u8],
    segments: &'a [LoadSegment],
}

impl<'a> CoreMemory<'a> {
    /// Build an accessor over `data` (the whole core) and its parsed `segments`.
    pub fn new(data: &'a [u8], segments: &'a [LoadSegment]) -> Self {
        Self { data, segments }
    }

    /// Bytes at virtual address `vaddr`, up to `len`, when a single segment holds them all.
    /// Returns `None` if no segment covers the range or the core file is too short for it.
    pub fn read_bytes(&self, vaddr: u64, len: u64) -> Option<&'a [u8]> {
        let end = vaddr.checked_add(len)?;
        for seg in self.segments {
            let seg_end = seg.vaddr.checked_add(seg.filesz)?;
            if vaddr >= seg.vaddr && end <= seg_end {
                let rel = vaddr - seg.vaddr;
                let start = usize::try_from(seg.offset.checked_add(rel)?).ok()?;
                let stop = start.checked_add(usize::try_from(len).ok()?)?;
                return self.data.get(start..stop);
            }
        }
        None
    }

    /// Read a little-endian `u64` at `vaddr`, or `None` if that memory is not in the core.
    pub fn read_u64(&self, vaddr: u64) -> Option<u64> {
        let b = self.read_bytes(vaddr, 8)?;
        Some(u64::from_le_bytes(b.try_into().ok()?))
    }
}

/// One thread recovered from an `NT_PRSTATUS` note.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ParsedThread {
    /// Kernel thread id (`pr_pid`).
    pub tid: i32,
    /// Signal that stopped the thread (`pr_cursig`); 0 when there was none.
    pub cursig: i32,
    /// The thread's register state at the time of the dump, for unwinding.
    pub regs: Registers,
}

/// The x86_64 registers unwinding needs, read from the `pr_reg` array of `NT_PRSTATUS`.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Registers {
    /// Instruction pointer (the thread's current PC).
    pub rip: u64,
    /// Stack pointer.
    pub rsp: u64,
    /// Frame (base) pointer.
    pub rbp: u64,
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
    let mut segments = Vec::new();
    let mut nt_file: Option<Vec<u8>> = None;
    // The crashing thread's notes come first, so the first NT_SIGINFO is its faulting address.
    let mut fault_addr: Option<u64> = None;
    for ph in headers {
        if ph.p_type(endian) == PT_LOAD {
            segments.push(LoadSegment {
                vaddr: ph.p_vaddr(endian),
                filesz: ph.p_filesz(endian),
                offset: ph.p_offset(endian),
            });
            continue;
        }
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
            match note.n_type(endian) {
                NT_PRSTATUS => threads.push(parse_prstatus(note.desc())?),
                NT_SIGINFO if fault_addr.is_none() => fault_addr = Some(read_si_addr(note.desc())?),
                // Keep the first NT_FILE; a core carries exactly one mapping table.
                NT_FILE if nt_file.is_none() => nt_file = Some(note.desc().to_vec()),
                _ => {}
            }
        }
    }

    let crashing = *threads
        .first()
        .ok_or_else(|| Error::Parse("no NT_PRSTATUS note; not a core dump?".to_string()))?;
    // pr_cursig is the reliable signal indicator (0 for a gcore snapshot of a live process).
    // NT_SIGINFO only supplies the address, and only memory faults carry a meaningful one.
    let (fault, crashing_tid) = if crashing.cursig == 0 {
        (FaultKind::Hang, None)
    } else {
        let address = match crashing.cursig {
            4 | 7 | 8 | 11 => fault_addr, // SIGILL, SIGBUS, SIGFPE, SIGSEGV
            _ => None,
        };
        (
            FaultKind::Signal {
                number: crashing.cursig,
                address,
            },
            Some(crashing.tid),
        )
    };

    Ok(ParsedCore {
        threads,
        fault,
        crashing_tid,
        segments,
        nt_file,
    })
}

/// Read the fields we need from a `struct elf_prstatus` descriptor (x86_64 layout):
/// `pr_cursig` is a `short` at offset 12, `pr_pid` an `int` at offset 32, and the
/// `user_regs_struct` (`pr_reg`) begins at offset 112, with `rbp` at index 4 (offset 144),
/// `rip` at index 16 (offset 240), and `rsp` at index 19 (offset 264).
fn parse_prstatus(desc: &[u8]) -> Result<ParsedThread> {
    let cursig = i16::from_le_bytes(read_arr(desc, 12)?) as i32;
    let tid = i32::from_le_bytes(read_arr(desc, 32)?);
    let regs = Registers {
        rbp: u64::from_le_bytes(read_arr(desc, 144)?),
        rip: u64::from_le_bytes(read_arr(desc, 240)?),
        rsp: u64::from_le_bytes(read_arr(desc, 264)?),
    };
    Ok(ParsedThread { tid, cursig, regs })
}

/// Read `si_addr` (offset 16) from a `siginfo_t` descriptor (x86_64 layout).
fn read_si_addr(desc: &[u8]) -> Result<u64> {
    Ok(u64::from_le_bytes(read_arr(desc, 16)?))
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
    fn segv_core_is_single_thread_sigsegv_at_null() {
        let core = parse(&load_core("segv")).expect("parse segv core");
        assert_eq!(core.threads.len(), 1);
        assert_eq!(
            core.fault,
            FaultKind::Signal {
                number: 11,
                address: Some(0),
            }
        );
        assert_eq!(core.crashing_tid, Some(core.threads[0].tid));
    }

    #[test]
    fn abort_core_is_sigabrt_without_address() {
        let core = parse(&load_core("abort")).expect("parse abort core");
        assert_eq!(core.threads.len(), 1);
        assert_eq!(
            core.fault,
            FaultKind::Signal {
                number: 6,
                address: None,
            }
        );
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
