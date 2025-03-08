use anyhow::Result;
use plt_rs::{collect_modules, DynamicLibrary, RelocationTable};

fn main() -> Result<()> {
    let entries = collect_modules();
    println!("collected {} modules", entries.len());

    for entry in entries.into_iter() {
        let entry_name = entry.name().to_owned();
        println!("[{}] Addr: {:#X?}", entry_name, entry.addr());

        let Ok(dynamic_lib) = DynamicLibrary::initialize(entry) else {
            println!(
                "failed to parse {} as dynamic library, skipping...",
                entry_name
            );
            continue;
        };

        let Some(dynamic_symbols) = dynamic_lib.symbols() else {
            println!("failed to retrieve dynamic symbols, skipping...");
            continue;
        };
        let string_table = dynamic_lib.string_table();

        println!("dynamic addend relocations:");
        if let Some(dyn_relas) = dynamic_lib.addend_relocs() {
            dyn_relas
                .entries()
                .iter()
                .flat_map(|e| dynamic_symbols.resolve_name(e.symbol_index() as usize, string_table))
                .filter(|s| !s.is_empty())
                .for_each(|s| println!("\t{}", s));
        }

        println!("dynamic relocations:");
        if let Some(dyn_relocs) = dynamic_lib.relocs() {
            dyn_relocs
                .entries()
                .iter()
                .flat_map(|e| dynamic_symbols.resolve_name(e.symbol_index() as usize, string_table))
                .filter(|s| !s.is_empty())
                .for_each(|s| println!("\t{}", s));
        }

        println!("plt:");
        if let Some(plt) = dynamic_lib.plt() {
            match plt {
                RelocationTable::WithAddend(rel) => {
                    rel.entries()
                        .iter()
                        .flat_map(|e| {
                            dynamic_symbols.resolve_name(e.symbol_index() as usize, string_table)
                        })
                        .filter(|s| !s.is_empty())
                        .for_each(|s| println!("\t{}", s));
                }
                RelocationTable::WithoutAddend(rel) => {
                    rel.entries()
                        .iter()
                        .flat_map(|e| {
                            dynamic_symbols.resolve_name(e.symbol_index() as usize, string_table)
                        })
                        .filter(|s| !s.is_empty())
                        .for_each(|s| println!("\t{}", s));
                }
            }
        }
        println!();
    }

    Ok(())
}
