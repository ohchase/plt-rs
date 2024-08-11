use anyhow::Result;
use plt_rs::{collect_modules, DynamicLibrary, RelocationTable};

fn main() -> Result<()> {
    let entries = collect_modules();
    println!("collected modules");

    for entry in entries.into_iter() {
        println!("[{:?}] Addr: {:#X?}", entry.name(), entry.addr());
        if let Ok(dynamic_lib) = DynamicLibrary::initialize(entry) {
            println!(
                "Dynamic String Table Length: {}",
                dynamic_lib.string_table().total_size()
            );

            let dynamic_symbols = dynamic_lib.symbols().expect("symbols...");
            let string_table = dynamic_lib.string_table();

            println!("dynamic addend relocations:");
            if let Some(dyn_relas) = dynamic_lib.addend_relocs() {
                dyn_relas
                    .entries()
                    .iter()
                    .flat_map(|e| {
                        dynamic_symbols.resolve_name(e.symbol_index() as usize, string_table)
                    })
                    .filter(|s| !s.is_empty())
                    .for_each(|s| println!("\t{}", s));
            }

            println!("dynamic relocations:");
            if let Some(dyn_relocs) = dynamic_lib.relocs() {
                dyn_relocs
                    .entries()
                    .iter()
                    .flat_map(|e| {
                        dynamic_symbols.resolve_name(e.symbol_index() as usize, string_table)
                    })
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
                                dynamic_symbols
                                    .resolve_name(e.symbol_index() as usize, string_table)
                            })
                            .filter(|s| !s.is_empty())
                            .for_each(|s| println!("\t{}", s));
                    }
                    RelocationTable::WithoutAddend(rel) => {
                        rel.entries()
                            .iter()
                            .flat_map(|e| {
                                dynamic_symbols
                                    .resolve_name(e.symbol_index() as usize, string_table)
                            })
                            .filter(|s| !s.is_empty())
                            .for_each(|s| println!("\t{}", s));
                    }
                }
            }
        }
        println!();
    }

    Ok(())
}
