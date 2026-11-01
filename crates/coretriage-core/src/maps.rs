//! Build the process module map. Turns the core's `NT_FILE` entries, plus any `--exe` and
//! `--sysroot` overrides, into resolved [`crate::model::Module`]s with load biases and,
//! where available, GNU build-ids - the inputs the unwinder and the symbolizer both need.

use std::collections::HashMap;
use std::ops::Range;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use memmap2::Mmap;
use object::read::elf::ElfFile64;
use object::{Endianness, Object, ObjectSegment};

use crate::TriageOptions;
use crate::core::{CoreMemory, ParsedCore};
use crate::{Error, Result};

/// GNU note type for a build-id (`NT_GNU_BUILD_ID`).
const NT_GNU_BUILD_ID: u32 = 3;
/// `PT_LOAD` / `PT_NOTE` program-header types, for parsing an in-core ELF image by hand.
const PT_LOAD: u32 = 1;
const PT_NOTE: u32 = 4;

/// The resolved module map for a core: one entry per distinct mapped file.
pub(crate) struct ModuleMap {
    /// Modules in first-seen order, each covering a disjoint virtual-address range.
    pub modules: Vec<ResolvedModule>,
}

impl ModuleMap {
    /// The module whose mapped range contains `avma`, for attributing a frame address.
    pub fn module_for_address(&self, avma: u64) -> Option<&ResolvedModule> {
        self.modules.iter().find(|m| m.avma_range.contains(&avma))
    }
}

/// One mapped file, resolved to an on-disk path where possible.
pub(crate) struct ResolvedModule {
    /// Short name for reports, the recorded path's final component (e.g. `libc.so.6`).
    pub name: String,
    /// Path recorded in the core, as it was on the origin system.
    pub recorded_path: PathBuf,
    /// The file located on this machine for symbols and unwind info, if any was found.
    pub on_disk: Option<PathBuf>,
    /// The separate debuginfo file carrying this module's DWARF, when the on-disk binary was
    /// stripped of it and a matching `.debug` was found. `None` when `on_disk` holds the DWARF.
    pub debug: Option<PathBuf>,
    /// GNU build-id of the on-disk file, lowercase hex, when it carries one.
    pub build_id: Option<String>,
    /// Virtual-address range the module occupies in the process (union of its mappings).
    pub avma_range: Range<u64>,
    /// Actual load address of the module (the mapping of file offset 0).
    pub base_avma: u64,
    /// `avma - svma` for this module: subtract it from a PC to get a module-relative
    /// (stated) address for symbolication. Equals `base_avma` for a PIE or shared object.
    pub load_bias: u64,
}

/// Memory-map a file read-only, the crate's one mmap boundary.
pub(crate) fn map_file(path: &Path) -> Result<Mmap> {
    let file = std::fs::File::open(path)?;
    // SAFETY: the file is opened read-only and neither it nor the mapping is ever mutated by
    // this crate; the returned `Mmap` owns the descriptor for its lifetime, so the bytes stay
    // valid for as long as callers hold it. Concurrent external truncation is out of scope.
    let mmap = unsafe { Mmap::map(&file)? };
    Ok(mmap)
}

/// Build the module map from a parsed core and the resolution options.
///
/// Never fails: a core with no `NT_FILE` note, or paths that resolve to nothing, yields a map
/// with unresolved (or no) modules rather than an error.
pub(crate) fn build(parsed: &ParsedCore, core: &[u8], opts: &TriageOptions) -> ModuleMap {
    let mappings = parsed
        .nt_file
        .as_deref()
        .and_then(|desc| parse_nt_file(desc).ok())
        .unwrap_or_default();

    // Group mappings by recorded path, preserving first-seen order for stable reports.
    let mut order: Vec<PathBuf> = Vec::new();
    let mut groups: HashMap<PathBuf, Vec<RawMapping>> = HashMap::new();
    for m in mappings {
        groups
            .entry(m.path.clone())
            .or_insert_with(|| {
                order.push(m.path.clone());
                Vec::new()
            })
            .push(m);
    }

    let mem = CoreMemory::new(core, &parsed.segments);
    let debug_dirs = effective_debug_dirs(opts);
    let mut modules = Vec::new();
    for path in order {
        let group = &groups[&path];
        // Module base is the mapping of file offset 0; fall back to the lowest mapping.
        let base_avma = group
            .iter()
            .find(|m| m.file_offset == 0)
            .or_else(|| group.iter().min_by_key(|m| m.start))
            .map(|m| m.start)
            .unwrap_or(0);
        let start = group.iter().map(|m| m.start).min().unwrap_or(base_avma);
        let end = group.iter().map(|m| m.end).max().unwrap_or(base_avma);

        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string());

        // The build-id drives the debug-store lookups. Prefer the one the crashing process
        // actually ran (recorded in the core image), falling back to the on-disk file's.
        let in_core = in_core_build_id(&mem, base_avma);

        // Direct path lookups first: recorded path, then --exe, then --sysroot.
        let mut on_disk = resolve_on_disk(&path, opts);
        let driving_id = in_core.clone().or_else(|| {
            on_disk
                .as_deref()
                .and_then(read_elf_info)
                .and_then(|(id, _)| id)
        });

        // Not found by path: look the executable up by build-id, in the debug stores and then
        // (with the debuginfod feature) a debuginfod server.
        if on_disk.is_none()
            && let Some(id) = &driving_id
        {
            on_disk = resolve_executable(&debug_dirs, id, opts);
        }

        let (build_id, min_svma) = match on_disk.as_deref().and_then(read_elf_info) {
            Some((id, min)) => (id, min),
            // Unresolved, or shared objects start at svma 0, so the bias is the load address.
            None => (None, 0),
        };
        let load_bias = base_avma.saturating_sub(min_svma);

        // The DWARF: the binary itself when it still carries `.debug_info`, else the separate
        // `.debug` file keyed by the same build-id (debug stores, then debuginfod).
        let debug = if on_disk.as_deref().is_some_and(has_debug_info) {
            None
        } else if let Some(id) = &driving_id {
            resolve_debug(&debug_dirs, id, opts)
        } else {
            None
        };

        // A wrong --exe/--sysroot silently yields bad symbols; warn when the on-disk build-id
        // disagrees with the one the crashing process actually had, but proceed regardless.
        if let (Some(disk), Some(in_core)) = (&build_id, &in_core)
            && disk != in_core
        {
            tracing::warn!(
                module = %name,
                on_disk = %disk,
                in_core = %in_core,
                "build-id mismatch; symbolication may be wrong"
            );
        }

        modules.push(ResolvedModule {
            name,
            recorded_path: path,
            on_disk,
            debug,
            build_id,
            avma_range: start..end,
            base_avma,
            load_bias,
        });
    }

    ModuleMap { modules }
}

/// One `NT_FILE` mapping entry.
struct RawMapping {
    start: u64,
    end: u64,
    /// Byte offset of this mapping within its backing file.
    file_offset: u64,
    path: PathBuf,
}

/// Parse an `NT_FILE` note descriptor into its mappings.
///
/// Layout: `[u64 count][u64 page_size][count x (u64 start, u64 end, u64 file_off_pages)]`
/// then `count` NUL-terminated paths. The count is validated against the descriptor length
/// before any iteration, and nothing is pre-allocated on it.
fn parse_nt_file(desc: &[u8]) -> Result<Vec<RawMapping>> {
    let count = u64::from_le_bytes(
        desc.get(0..8)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| Error::Parse("NT_FILE: truncated header".into()))?,
    );
    let page_size = u64::from_le_bytes(
        desc.get(8..16)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| Error::Parse("NT_FILE: truncated header".into()))?,
    );
    let count =
        usize::try_from(count).map_err(|_| Error::Parse("NT_FILE: count too large".into()))?;
    // Reject a count the descriptor cannot possibly back before allocating or looping.
    let table_len = count
        .checked_mul(24)
        .and_then(|n| n.checked_add(16))
        .ok_or_else(|| Error::Parse("NT_FILE: count overflow".into()))?;
    let paths_blob = desc
        .get(table_len..)
        .ok_or_else(|| Error::Parse("NT_FILE: count exceeds descriptor".into()))?;

    let mut paths = paths_blob.split(|&b| b == 0);
    let mut out = Vec::new();
    for i in 0..count {
        let base = 16 + i * 24;
        let start = u64::from_le_bytes(desc[base..base + 8].try_into().unwrap());
        let end = u64::from_le_bytes(desc[base + 8..base + 16].try_into().unwrap());
        let off_pages = u64::from_le_bytes(desc[base + 16..base + 24].try_into().unwrap());
        let raw = paths
            .next()
            .ok_or_else(|| Error::Parse("NT_FILE: fewer paths than entries".into()))?;
        out.push(RawMapping {
            start,
            end,
            file_offset: off_pages.wrapping_mul(page_size),
            path: PathBuf::from(std::ffi::OsStr::from_bytes(raw)),
        });
    }
    Ok(out)
}

/// Locate the on-disk file for a recorded module path: the recorded path if it exists, else an
/// `--exe` whose file name matches, else a match under a `--sysroot` (by suffix then basename).
fn resolve_on_disk(recorded: &Path, opts: &TriageOptions) -> Option<PathBuf> {
    if recorded.is_file() {
        return Some(recorded.to_path_buf());
    }
    let want = recorded.file_name();
    if let Some(exe) = &opts.exe
        && want.is_some()
        && exe.file_name() == want
        && exe.is_file()
    {
        return Some(exe.clone());
    }
    let suffix = recorded.strip_prefix("/").unwrap_or(recorded);
    for root in &opts.sysroot {
        let by_suffix = root.join(suffix);
        if by_suffix.is_file() {
            return Some(by_suffix);
        }
        if let Some(name) = want {
            let by_name = root.join(name);
            if by_name.is_file() {
                return Some(by_name);
            }
        }
    }
    None
}

/// The debug stores to search: the user's `--debug-dir` list, or the elfutils default
/// `/usr/lib/debug` when none were given.
fn effective_debug_dirs(opts: &TriageOptions) -> Vec<PathBuf> {
    if opts.debug_dirs.is_empty() {
        vec![PathBuf::from("/usr/lib/debug")]
    } else {
        opts.debug_dirs.clone()
    }
}

/// Locate a build-id artifact in the debug stores, trying two on-disk layouts per directory.
/// `suffix` is empty for the executable or `.debug` for its debuginfo.
///
/// - elfutils: `<dir>/.build-id/<ab>/<rest><suffix>`, where `<ab>` is the first two hex chars of
///   the build-id and `<rest>` the remainder.
/// - debuginfod: `<dir>/buildid/<id>/<name>`, where `<name>` is `executable` or `debuginfo`. This
///   is the layout of a debuginfod file cache and of split-debug trees that ship it (e.g. an
///   exported `/usr/lib/debug` with a `buildid/` index), so a `--debug-dir` at either resolves.
fn resolve_build_id_file(debug_dirs: &[PathBuf], build_id: &str, suffix: &str) -> Option<PathBuf> {
    // A build-id needs at least the two-char directory plus one more char to split.
    if build_id.len() < 3 {
        return None;
    }
    let (ab, rest) = build_id.split_at(2);
    let elfutils = Path::new(".build-id")
        .join(ab)
        .join(format!("{rest}{suffix}"));
    let name = if suffix == ".debug" {
        "debuginfo"
    } else {
        "executable"
    };
    let debuginfod = Path::new("buildid").join(build_id).join(name);
    for dir in debug_dirs {
        for rel in [&elfutils, &debuginfod] {
            let candidate = dir.join(rel);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

/// Locate the executable for a build-id: the debug stores first, then (with the `debuginfod`
/// feature and when `opts.debuginfod` is set) a debuginfod server.
fn resolve_executable(
    debug_dirs: &[PathBuf],
    build_id: &str,
    opts: &TriageOptions,
) -> Option<PathBuf> {
    if let Some(local) = resolve_build_id_file(debug_dirs, build_id, "") {
        return Some(local);
    }
    #[cfg(feature = "debuginfod")]
    if opts.debuginfod {
        return crate::debuginfod::fetch(build_id, crate::debuginfod::Artifact::Executable);
    }
    // `opts` is consulted only with the debuginfod feature built in.
    #[cfg(not(feature = "debuginfod"))]
    let _ = opts;
    None
}

/// Locate the separate debuginfo for a build-id: the debug stores first, then (with the
/// `debuginfod` feature and when `opts.debuginfod` is set) a debuginfod server.
fn resolve_debug(debug_dirs: &[PathBuf], build_id: &str, opts: &TriageOptions) -> Option<PathBuf> {
    if let Some(local) = resolve_build_id_file(debug_dirs, build_id, ".debug") {
        return Some(local);
    }
    #[cfg(feature = "debuginfod")]
    if opts.debuginfod {
        return crate::debuginfod::fetch(build_id, crate::debuginfod::Artifact::Debuginfo);
    }
    // `opts` is consulted only with the debuginfod feature built in.
    #[cfg(not(feature = "debuginfod"))]
    let _ = opts;
    None
}

/// Whether an on-disk ELF still carries its own DWARF (a `.debug_info` section), so no separate
/// debuginfo file is needed. A stripped binary lacks it; an unstripped one has it.
fn has_debug_info(path: &Path) -> bool {
    map_file(path)
        .ok()
        .and_then(|mmap| {
            let elf = ElfFile64::<Endianness>::parse(&*mmap).ok()?;
            Some(elf.section_by_name(".debug_info").is_some())
        })
        .unwrap_or(false)
}

/// Read an on-disk ELF's build-id and lowest `PT_LOAD` virtual address (its stated base).
fn read_elf_info(path: &Path) -> Option<(Option<String>, u64)> {
    let mmap = map_file(path).ok()?;
    let elf = ElfFile64::<Endianness>::parse(&*mmap).ok()?;
    let build_id = elf.build_id().ok().flatten().map(hex);
    let min_svma = elf.segments().map(|s| s.address()).min().unwrap_or(0);
    Some((build_id, min_svma))
}

/// Read the build-id from the module's own ELF image as mapped in the core, for the mismatch
/// check. Best effort: returns `None` if the header pages were not saved in the core.
fn in_core_build_id(mem: &CoreMemory, base_avma: u64) -> Option<String> {
    let hdr = mem.read_bytes(base_avma, 64)?;
    if hdr.get(0..4)? != b"\x7fELF" {
        return None;
    }
    let phoff = u64::from_le_bytes(hdr.get(32..40)?.try_into().ok()?);
    let phentsize = u64::from(u16::from_le_bytes(hdr.get(54..56)?.try_into().ok()?));
    let phnum = u64::from(u16::from_le_bytes(hdr.get(56..58)?.try_into().ok()?));
    if phentsize < 56 {
        return None;
    }
    let mut min_vaddr = u64::MAX;
    let mut notes = Vec::new();
    for i in 0..phnum {
        let off = base_avma
            .checked_add(phoff)?
            .checked_add(i.checked_mul(phentsize)?)?;
        let ph = mem.read_bytes(off, 56)?;
        let p_type = u32::from_le_bytes(ph.get(0..4)?.try_into().ok()?);
        let p_vaddr = u64::from_le_bytes(ph.get(16..24)?.try_into().ok()?);
        let p_filesz = u64::from_le_bytes(ph.get(32..40)?.try_into().ok()?);
        match p_type {
            PT_LOAD => min_vaddr = min_vaddr.min(p_vaddr),
            PT_NOTE => notes.push((p_vaddr, p_filesz)),
            _ => {}
        }
    }
    if min_vaddr == u64::MAX {
        return None;
    }
    let load_delta = base_avma.checked_sub(min_vaddr)?;
    for (p_vaddr, filesz) in notes {
        let data = mem.read_bytes(p_vaddr.checked_add(load_delta)?, filesz)?;
        if let Some(id) = find_build_id_note(data) {
            return Some(id);
        }
    }
    None
}

/// Scan a run of ELF notes for an `NT_GNU_BUILD_ID`, returning it as lowercase hex.
fn find_build_id_note(mut data: &[u8]) -> Option<String> {
    while data.len() >= 12 {
        let namesz = u32::from_le_bytes(data.get(0..4)?.try_into().ok()?) as usize;
        let descsz = u32::from_le_bytes(data.get(4..8)?.try_into().ok()?) as usize;
        let ntype = u32::from_le_bytes(data.get(8..12)?.try_into().ok()?);
        let desc_start = 12usize.checked_add((namesz + 3) & !3)?;
        let name = data.get(12..12 + namesz)?;
        if ntype == NT_GNU_BUILD_ID && name.starts_with(b"GNU") {
            return Some(hex(data.get(desc_start..desc_start.checked_add(descsz)?)?));
        }
        let next = desc_start.checked_add((descsz + 3) & !3)?;
        data = data.get(next..)?;
    }
    None
}

/// Lowercase hex encoding, for build-ids.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{TempDir, fixture_path, load_core};

    #[test]
    fn segv_map_resolves_crasher_with_exe_and_reads_build_id() {
        let core = load_core("segv");
        let parsed = crate::core::parse(&core).expect("parse segv core");
        let opts = TriageOptions {
            exe: Some(fixture_path("crasher")),
            ..Default::default()
        };
        let map = build(&parsed, &core, &opts);

        let names: Vec<&str> = map.modules.iter().map(|m| m.name.as_str()).collect();
        assert!(names.contains(&"crasher"), "modules: {names:?}");
        assert!(names.contains(&"libc.so.6"), "modules: {names:?}");

        let crasher = map
            .modules
            .iter()
            .find(|m| m.name == "crasher")
            .expect("crasher module");
        assert!(
            crasher.on_disk.is_some(),
            "crasher should resolve via --exe"
        );
        assert_eq!(
            crasher.build_id.as_deref(),
            Some("2d4984456a0c95229abe1c1c9007381b98872995")
        );
        // A PIE loads at its base address, so the bias equals that address.
        assert_eq!(crasher.load_bias, crasher.base_avma);
        assert!(crasher.avma_range.contains(&crasher.base_avma));
    }

    #[test]
    fn empty_debug_dir_leaves_module_unresolved() {
        let core = load_core("segv");
        let parsed = crate::core::parse(&core).expect("parse segv core");
        // An empty debug store holds no build-id artifact, so with no --exe the crasher cannot
        // be located; resolution must yield no files and must not panic.
        let store = TempDir::new("empty-store");
        let opts = TriageOptions {
            debug_dirs: vec![store.path.clone()],
            ..Default::default()
        };
        let map = build(&parsed, &core, &opts);
        let crasher = map
            .modules
            .iter()
            .find(|m| m.name == "crasher")
            .expect("crasher module");
        assert!(crasher.on_disk.is_none());
        assert!(crasher.debug.is_none());
    }

    #[test]
    fn resolves_crasher_by_build_id_and_leaves_debug_none() {
        // The unstripped crasher carries its own DWARF, so once found by build-id its `debug`
        // stays None (no separate debuginfo needed).
        let core = load_core("segv");
        let parsed = crate::core::parse(&core).expect("parse segv core");
        let store = TempDir::new("buildid-maps");
        store.put_build_id("crasher", "2d4984456a0c95229abe1c1c9007381b98872995", "");
        let opts = TriageOptions {
            debug_dirs: vec![store.path.clone()],
            ..Default::default()
        };
        let map = build(&parsed, &core, &opts);
        let crasher = map
            .modules
            .iter()
            .find(|m| m.name == "crasher")
            .expect("crasher module");
        assert!(
            crasher.on_disk.is_some(),
            "crasher found via build-id store"
        );
        assert!(crasher.debug.is_none(), "unstripped binary needs no .debug");
        assert_eq!(
            crasher.build_id.as_deref(),
            Some("2d4984456a0c95229abe1c1c9007381b98872995")
        );
    }

    #[test]
    fn resolves_crasher_by_build_id_in_debuginfod_layout() {
        // Same as the elfutils-layout case, but the store uses the debuginfod cache layout
        // `buildid/<id>/executable`, as a debuginfod cache or an exported debug tree uses.
        let core = load_core("segv");
        let parsed = crate::core::parse(&core).expect("parse segv core");
        let store = TempDir::new("debuginfod-maps");
        store.put_debuginfod(
            "crasher",
            "2d4984456a0c95229abe1c1c9007381b98872995",
            "executable",
        );
        let opts = TriageOptions {
            debug_dirs: vec![store.path.clone()],
            ..Default::default()
        };
        let map = build(&parsed, &core, &opts);
        let crasher = map
            .modules
            .iter()
            .find(|m| m.name == "crasher")
            .expect("crasher module");
        assert!(
            crasher.on_disk.is_some(),
            "crasher found via debuginfod-layout store"
        );
        assert_eq!(
            crasher.build_id.as_deref(),
            Some("2d4984456a0c95229abe1c1c9007381b98872995")
        );
    }

    #[test]
    fn resolve_build_id_file_accepts_elfutils_and_debuginfod_layouts() {
        let dir = TempDir::new("buildid-layouts");
        let id = "abcdef0123456789";
        // The debuginfo lives in the elfutils layout; the executable in the debuginfod layout.
        std::fs::create_dir_all(dir.path.join(".build-id/ab")).unwrap();
        std::fs::write(dir.path.join(".build-id/ab/cdef0123456789.debug"), b"d").unwrap();
        std::fs::create_dir_all(dir.path.join(format!("buildid/{id}"))).unwrap();
        std::fs::write(dir.path.join(format!("buildid/{id}/executable")), b"x").unwrap();

        let dirs = [dir.path.clone()];
        assert!(
            resolve_build_id_file(&dirs, id, ".debug").is_some(),
            "elfutils .debug"
        );
        assert!(
            resolve_build_id_file(&dirs, id, "").is_some(),
            "debuginfod executable"
        );
        assert!(
            resolve_build_id_file(&dirs, "zz", "").is_none(),
            "build-id too short to split"
        );
    }

    #[test]
    fn crasher_is_unresolved_without_exe() {
        let core = load_core("segv");
        let parsed = crate::core::parse(&core).expect("parse segv core");
        let map = build(&parsed, &core, &TriageOptions::default());
        let crasher = map
            .modules
            .iter()
            .find(|m| m.name == "crasher")
            .expect("crasher module");
        // The recorded /tmp path does not exist here, so without --exe there is no file.
        assert!(crasher.on_disk.is_none());
        assert!(crasher.build_id.is_none());
    }

    #[test]
    fn rejects_nt_file_with_bogus_count() {
        // count = u64::MAX cannot be backed by a 16-byte descriptor.
        let mut desc = Vec::new();
        desc.extend_from_slice(&u64::MAX.to_le_bytes());
        desc.extend_from_slice(&4096u64.to_le_bytes());
        assert!(parse_nt_file(&desc).is_err());
    }
}
