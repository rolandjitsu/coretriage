//! Symbolicate frame addresses. Maps each return address back to its module, then uses an
//! `addr2line::Context` (cached per build-id) to resolve function names and source
//! file/line from the module's DWARF, demangling Rust and C++ symbols for readable frames.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use addr2line::Context;
use framehop::FrameAddress;
use gimli::{EndianArcSlice, RunTimeEndian};
use object::read::elf::ElfFile64;
use object::{Endianness, Object, ObjectSection, ObjectSymbol, SymbolKind};

use crate::maps::{ModuleMap, ResolvedModule, map_file};
use crate::model::Frame;

/// DWARF and symbol-table data for one module, built once and reused across frames, threads,
/// and cores. `addr2line::Context` is `!Sync` (it lazily fills internal caches), so access is
/// guarded by a mutex; the heavy work of parsing the DWARF is what the cache avoids repeating.
struct ModuleSymbols {
    ctx: Context<EndianArcSlice<RunTimeEndian>>,
    /// Function symbols sorted by stated address, for the no-DWARF nearest-symbol fallback.
    symbols: Vec<FnSymbol>,
}

/// One function symbol from the ELF symbol table.
struct FnSymbol {
    /// Stated (module-relative) address.
    svma: u64,
    /// Size in bytes, or 0 when the table does not record one.
    size: u64,
    name: String,
}

/// Caches per-module symbol data keyed by build-id (or on-disk path when there is none), so a
/// module's DWARF is parsed once even across a whole batch of cores.
pub(crate) struct Symbolizer {
    cache: Mutex<HashMap<String, Option<Arc<Mutex<ModuleSymbols>>>>>,
}

impl Symbolizer {
    /// A symbolizer with an empty cache.
    pub fn new() -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Symbolicate one thread's unwound addresses into display frames, innermost first. A PC
    /// may expand into several frames when the compiler inlined calls at that address.
    pub fn symbolize_thread(&self, map: &ModuleMap, addrs: &[FrameAddress]) -> Vec<Frame> {
        let mut out = Vec::new();
        for fa in addrs {
            // Attribute by the actual PC, but look up by `address_for_lookup` so a return
            // address resolves to the call site (its PC minus one) like a debugger shows.
            let Some(module) = map.module_for_address(fa.address()) else {
                out.push(unknown_frame(None));
                continue;
            };
            match self.module_symbols(module) {
                Some(syms) => {
                    let rel = fa.address_for_lookup().wrapping_sub(module.load_bias);
                    let mut frames = syms.lock().unwrap().resolve(&module.name, rel);
                    out.append(&mut frames);
                }
                None => out.push(unknown_frame(Some(module.name.clone()))),
            }
        }
        out
    }

    /// Fetch (building and caching on first use) the symbol data for a module, or `None` when
    /// it did not resolve to a readable on-disk file.
    fn module_symbols(&self, module: &ResolvedModule) -> Option<Arc<Mutex<ModuleSymbols>>> {
        let path = module.on_disk.as_deref()?;
        let key = module
            .build_id
            .clone()
            .unwrap_or_else(|| path.to_string_lossy().into_owned());
        if let Some(entry) = self.cache.lock().unwrap().get(&key) {
            return entry.clone();
        }
        // Build outside the cache lock: parsing DWARF is slow and must not block other modules.
        let built = ModuleSymbols::load(path).map(|s| Arc::new(Mutex::new(s)));
        self.cache.lock().unwrap().insert(key, built.clone());
        built
    }
}

impl ModuleSymbols {
    /// Build symbol data from an on-disk ELF: an `addr2line::Context` over its DWARF plus its
    /// function symbol table. Returns `None` if the file cannot be read or parsed.
    fn load(path: &Path) -> Option<Self> {
        let mmap = map_file(path).ok()?;
        let elf = ElfFile64::<Endianness>::parse(&*mmap).ok()?;
        let endian = if elf.is_little_endian() {
            RunTimeEndian::Little
        } else {
            RunTimeEndian::Big
        };
        // Copy each DWARF section into an `Arc<[u8]>` so the context owns its data and can be
        // cached independently of the mmap, which drops when this function returns.
        let dwarf = gimli::Dwarf::load(|id| -> Result<_, gimli::Error> {
            let data = elf
                .section_by_name(id.name())
                .and_then(|s| s.data().ok())
                .unwrap_or(&[]);
            Ok(EndianArcSlice::new(Arc::from(data), endian))
        })
        .ok()?;
        let ctx = Context::from_dwarf(dwarf).ok()?;
        Some(Self {
            ctx,
            symbols: load_symbols(&elf),
        })
    }

    /// Resolve a module-relative address into one or more frames (inlines included).
    fn resolve(&self, module: &str, rel: u64) -> Vec<Frame> {
        let mut out = Vec::new();
        if let Ok(mut iter) = self.ctx.find_frames(rel).skip_all_loads() {
            while let Ok(Some(frame)) = iter.next() {
                let function = frame
                    .function
                    .as_ref()
                    .and_then(|f| f.raw_name().ok())
                    .map(|n| demangle(&n))
                    .or_else(|| self.nearest(rel).map(demangle));
                let (file, line) = match &frame.location {
                    Some(loc) => (loc.file.map(str::to_string), loc.line),
                    None => (None, None),
                };
                out.push(Frame {
                    module: Some(module.to_string()),
                    function,
                    file,
                    line,
                });
            }
        }
        // No DWARF line/function info: fall back to the nearest symbol-table entry.
        if out.is_empty() {
            out.push(Frame {
                module: Some(module.to_string()),
                function: self.nearest(rel).map(demangle),
                file: None,
                line: None,
            });
        }
        out
    }

    /// Name of the function symbol whose range contains `rel`, for the no-DWARF fallback.
    fn nearest(&self, rel: u64) -> Option<&str> {
        nearest_symbol(&self.symbols, rel)
    }
}

/// Name of the function symbol whose range contains `rel`: the greatest start `<= rel`, kept
/// only when `rel` falls within its recorded size (a zero size is treated as unbounded).
fn nearest_symbol(symbols: &[FnSymbol], rel: u64) -> Option<&str> {
    let idx = symbols.partition_point(|s| s.svma <= rel);
    let s = symbols.get(idx.checked_sub(1)?)?;
    if s.size == 0 || rel < s.svma.saturating_add(s.size) {
        Some(&s.name)
    } else {
        None
    }
}

/// A frame with no function or source location, carrying only a module name when known.
fn unknown_frame(module: Option<String>) -> Frame {
    Frame {
        module,
        function: None,
        file: None,
        line: None,
    }
}

/// Collect function symbols, sorted by address, for the nearest-symbol fallback.
fn load_symbols(elf: &ElfFile64<Endianness>) -> Vec<FnSymbol> {
    let mut symbols: Vec<FnSymbol> = elf
        .symbols()
        .filter(|s| s.kind() == SymbolKind::Text && s.address() != 0)
        .filter_map(|s| {
            let name = s.name().ok()?;
            (!name.is_empty()).then(|| FnSymbol {
                svma: s.address(),
                size: s.size(),
                name: name.to_string(),
            })
        })
        .collect();
    symbols.sort_by_key(|s| s.svma);
    symbols
}

/// Demangle a raw symbol name: Rust first, then C++, else return it unchanged.
fn demangle(name: &str) -> String {
    if let Ok(sym) = rustc_demangle::try_demangle(name) {
        // The alternate form drops the trailing hash, e.g. `foo::bar` not `foo::bar::h1234`.
        return format!("{sym:#}");
    }
    if let Ok(sym) = cpp_demangle::Symbol::new(name)
        && let Ok(demangled) = sym.demangle()
    {
        return demangled;
    }
    name.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demangle_rust_strips_hash() {
        let mangled = "_ZN4core3fmt5Debug3fmt17h0123456789abcdefE";
        assert_eq!(demangle(mangled), "core::fmt::Debug::fmt");
    }

    #[test]
    fn demangle_cpp() {
        assert_eq!(demangle("_ZN5space3fooEibc"), "space::foo(int, bool, char)");
    }

    #[test]
    fn demangle_passes_through_plain_c_names() {
        assert_eq!(demangle("gamma_segv"), "gamma_segv");
    }

    #[test]
    fn nearest_symbol_respects_bounds() {
        let syms = symbols_fixture();
        assert_eq!(nearest_symbol(&syms, 0x1000), Some("alpha"));
        assert_eq!(nearest_symbol(&syms, 0x1010), Some("alpha")); // inside alpha's size
        assert_eq!(nearest_symbol(&syms, 0x1100), Some("beta"));
        assert_eq!(nearest_symbol(&syms, 0x900), None); // before the first symbol
        assert_eq!(nearest_symbol(&syms, 0x1080), None); // in the gap past alpha's end
    }

    // Helpers after the tests that use them, per the house rules.
    fn symbols_fixture() -> Vec<FnSymbol> {
        vec![
            FnSymbol {
                svma: 0x1000,
                size: 0x40,
                name: "alpha".into(),
            },
            FnSymbol {
                svma: 0x1100,
                size: 0x40,
                name: "beta".into(),
            },
        ]
    }
}
