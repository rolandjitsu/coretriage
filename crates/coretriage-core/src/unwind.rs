//! Unwind each thread's stack. Starting from the `NT_PRSTATUS` register set, it walks frames
//! using DWARF call-frame information via `framehop`, reading stack and register memory from
//! the core image, and yields the return-address chain for symbolication.

use std::ops::Range;

use framehop::x86_64::{CacheX86_64, UnwindRegsX86_64, UnwinderX86_64};
use framehop::{ExplicitModuleSectionInfo, FrameAddress, Module, Unwinder};
use object::read::elf::ElfFile64;
use object::{Endianness, Object, ObjectSection};

use crate::core::{CoreMemory, ParsedCore};
use crate::maps::{ModuleMap, ResolvedModule, map_file};

/// Upper bound on frames per thread, so a corrupt stack cannot spin or allocate without end.
const MAX_FRAMES: usize = 4096;

/// Unwind every thread in the core, returning each thread's frames innermost-first (the PC
/// first, then return addresses). Threads are returned in the same order as `parsed.threads`.
pub(crate) fn unwind(parsed: &ParsedCore, core: &[u8], map: &ModuleMap) -> Vec<Vec<FrameAddress>> {
    let mut unwinder = UnwinderX86_64::<Vec<u8>>::new();
    for module in &map.modules {
        if let Some(fh) = framehop_module(module) {
            unwinder.add_module(fh);
        }
    }

    let mem = CoreMemory::new(core, &parsed.segments);
    let mut cache = CacheX86_64::new();
    parsed
        .threads
        .iter()
        .map(|t| {
            unwind_thread(
                &unwinder, &mut cache, &mem, t.regs.rip, t.regs.rsp, t.regs.rbp,
            )
        })
        .collect()
}

/// Unwind one thread from its seed registers, reading stack memory from the core.
fn unwind_thread(
    unwinder: &UnwinderX86_64<Vec<u8>>,
    cache: &mut CacheX86_64,
    mem: &CoreMemory,
    rip: u64,
    rsp: u64,
    rbp: u64,
) -> Vec<FrameAddress> {
    let mut read_stack = |addr: u64| mem.read_u64(addr).ok_or(());
    let mut iter = unwinder.iter_frames(
        rip,
        UnwindRegsX86_64::new(rip, rsp, rbp),
        cache,
        &mut read_stack,
    );

    let mut frames = Vec::new();
    // A trailing `Err` is normal when the stack root cannot be proven; keep what we have.
    while let Ok(Some(frame)) = iter.next() {
        frames.push(frame);
        if frames.len() >= MAX_FRAMES {
            break;
        }
    }
    frames
}

/// Build a `framehop` module from a resolved module's on-disk unwind sections, or `None` when
/// the module did not resolve to a file or carries no usable text.
fn framehop_module(module: &ResolvedModule) -> Option<Module<Vec<u8>>> {
    let path = module.on_disk.as_deref()?;
    let mmap = map_file(path).ok()?;
    let elf = ElfFile64::<Endianness>::parse(&*mmap).ok()?;

    let (text_svma, text) = section(&elf, ".text")?;
    let eh_frame = section(&elf, ".eh_frame");
    let eh_frame_hdr = section(&elf, ".eh_frame_hdr");
    let got = section(&elf, ".got");

    // base_svma is the module's stated base (its lowest svma); base_avma is where it actually
    // loaded. framehop maps a PC to a stated address via these, so the section svmas below -
    // the on-disk sh_addr values - line up with the DWARF CFI.
    let base_svma = module.base_avma.saturating_sub(module.load_bias);
    let section_info = ExplicitModuleSectionInfo {
        base_svma,
        text_svma: Some(text_svma),
        text: Some(text),
        eh_frame_svma: eh_frame.as_ref().map(|(r, _)| r.clone()),
        eh_frame: eh_frame.map(|(_, d)| d),
        eh_frame_hdr_svma: eh_frame_hdr.as_ref().map(|(r, _)| r.clone()),
        eh_frame_hdr: eh_frame_hdr.map(|(_, d)| d),
        got_svma: got.map(|(r, _)| r),
        ..Default::default()
    };

    Some(Module::new(
        module.name.clone(),
        module.avma_range.clone(),
        module.base_avma,
        section_info,
    ))
}

/// A named section's stated address range and bytes, if the ELF has it with data.
fn section(elf: &ElfFile64<Endianness>, name: &str) -> Option<(Range<u64>, Vec<u8>)> {
    let section = elf.section_by_name(name)?;
    let addr = section.address();
    let data = section.data().ok()?.to_vec();
    Some((addr..addr + data.len() as u64, data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TriageOptions;
    use crate::testutil::{fixture_path, load_core};

    #[test]
    fn segv_crashing_thread_unwinds_into_crasher() {
        let core = load_core("segv");
        let parsed = crate::core::parse(&core).expect("parse segv core");
        let opts = TriageOptions {
            exe: Some(fixture_path("crasher")),
            ..Default::default()
        };
        let map = crate::maps::build(&parsed, &core, &opts);
        let crasher = map
            .modules
            .iter()
            .find(|m| m.name == "crasher")
            .expect("crasher module");

        let frames = &unwind(&parsed, &core, &map)[0];
        // main -> alpha -> beta -> gamma_segv: at least four frames, innermost in crasher.
        assert!(frames.len() >= 4, "only {} frames", frames.len());
        for frame in frames.iter().take(4) {
            let pc = frame.address_for_lookup();
            assert!(
                crasher.avma_range.contains(&pc),
                "frame pc {pc:#x} not in crasher range {:#x?}",
                crasher.avma_range
            );
        }
    }
}
