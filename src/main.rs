//! E-OS Guard — Crimson-themed filesystem integrity monitor.
//!
//! Baselines a set of directories (blake3 hash + metadata of every file, stored
//! in SQLite/WAL), then diffs a later scan against the baseline to surface
//! NEW / MODIFIED / REMOVED files, plus a world-writable security lint.
//!
//! GUI: Slint over the shared eos-ui Orbital backend (behind the default `gui`
//! feature — a Redox-target concern).
//! `eos-guard --selftest` runs the headless scan/diff proof and prints
//! GUARD-SELFTEST-OK.

mod db;
#[cfg(feature = "gui")]
mod gui;
mod scan;
mod selftest;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--selftest") {
        let path = std::path::PathBuf::from("/tmp/eos-guard-selftest.db");
        match selftest::run(&path) {
            Ok(()) => {
                println!("GUARD-SELFTEST-OK");
                eprintln!("GUARD-SELFTEST-OK");
            }
            Err(err) => {
                println!("GUARD-SELFTEST-FAIL: {err}");
                eprintln!("GUARD-SELFTEST-FAIL: {err}");
                std::process::exit(1);
            }
        }
        return;
    }

    #[cfg(feature = "gui")]
    gui::run();

    #[cfg(not(feature = "gui"))]
    {
        eprintln!("eos-guard: built without the `gui` feature (selftest-only binary)");
        std::process::exit(2);
    }
}
