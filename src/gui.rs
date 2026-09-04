//! The Slint GUI half of E-OS Guard (Redox-target concern; hosts may build with
//! `--no-default-features` for the CLI/selftest half only).

use crate::db::{self, Status};
use crate::scan;
use slint::{ModelRc, SharedString, VecModel};
use std::cell::RefCell;
use std::rc::Rc;

slint::include_modules!();

/// Cap the number of files a single GUI scan hashes, so pointing Guard at a huge
/// tree can't wedge the single-threaded event loop.
const SCAN_BUDGET: usize = 20_000;

fn kind_of(status: Status) -> i32 {
    match status {
        Status::Ok => 0,
        Status::New => 1,
        Status::Modified => 2,
        Status::Removed => 3,
        Status::Warn => 4,
    }
}

fn parse_roots(s: &str) -> Vec<String> {
    s.split(',')
        .map(|r| r.trim())
        .filter(|r| !r.is_empty())
        .map(str::to_string)
        .collect()
}

struct App {
    db: db::Db,
}

fn show(win: &MainWindow, findings: &[db::Finding], sum: db::Summary) {
    let items: Vec<Finding> = findings
        .iter()
        .map(|f| Finding {
            path: SharedString::from(f.path.as_str()),
            status: SharedString::from(f.status.label()),
            detail: SharedString::from(f.detail.as_str()),
            kind: kind_of(f.status),
        })
        .collect();
    win.set_findings(ModelRc::new(VecModel::from(items)));
    win.set_n_ok(sum.ok as i32);
    win.set_n_new(sum.new as i32);
    win.set_n_modified(sum.modified as i32);
    win.set_n_removed(sum.removed as i32);
    win.set_n_warn(sum.warn as i32);
}

pub fn run() {
    // Install the shared E-OS Slint-on-Orbital backend + fonts (no-op on host).
    eos_ui::init("E-OS Guard");

    let database =
        db::Db::open(&db::default_path()).expect("eos-guard: cannot open the baseline database");
    let app = Rc::new(RefCell::new(App { db: database }));

    let win = MainWindow::new().expect("eos-guard: cannot create the window");
    win.set_roots(SharedString::from("/usr/bin, /etc"));
    {
        let app = app.borrow();
        let base_n = app.db.baseline_count().unwrap_or(0);
        // `.unwrap_or(true)` used to stand here: a database error was displayed as "intact".
        // `verify_baseline` no longer returns anything that can be unwrapped into reassurance.
        let state = app.db.verify_baseline();
        win.set_status(SharedString::from(if base_n == 0 {
            "Brak wzorca — kliknij „Ustaw wzorzec”.".to_string()
        } else if !state.is_intact() {
            format!(
                "⚠ Wzorzec ({base_n} plików) {} — ustaw go ponownie.",
                state.describe()
            )
        } else {
            format!("Wzorzec: {base_n} plików. Kliknij Skanuj.")
        }));
    }

    {
        let app = app.clone();
        let weak = win.as_weak();
        win.on_baseline(move || {
            let win = weak.unwrap();
            let roots = parse_roots(win.get_roots().as_str());
            if roots.is_empty() {
                win.set_status(SharedString::from("Podaj przynajmniej jeden katalog."));
                return;
            }
            win.set_busy(true);
            win.set_status(SharedString::from("Skanowanie do wzorca…"));
            let (entries, truncated) = scan::scan_roots(&roots, SCAN_BUDGET);
            let n = entries.len();
            let mut app = app.borrow_mut();
            match app.db.set_baseline(&entries) {
                Ok(()) => win.set_status(SharedString::from(format!(
                    "Wzorzec ustawiony: {n} plików{}.",
                    if truncated {
                        " (obcięto do limitu)"
                    } else {
                        ""
                    }
                ))),
                Err(err) => win.set_status(SharedString::from(format!("Błąd zapisu: {err}"))),
            }
            show(&win, &[], db::Summary::default());
            win.set_busy(false);
        });
    }

    {
        let app = app.clone();
        let weak = win.as_weak();
        win.on_scan(move || {
            let win = weak.unwrap();
            if app.borrow().db.baseline_count().unwrap_or(0) == 0 {
                win.set_status(SharedString::from(
                    "Brak wzorca — najpierw „Ustaw wzorzec”.",
                ));
                return;
            }
            let roots = parse_roots(win.get_roots().as_str());
            win.set_busy(true);
            win.set_status(SharedString::from("Skanowanie…"));
            let (entries, truncated) = scan::scan_roots(&roots, SCAN_BUDGET);
            let app = app.borrow();
            let state = app.db.verify_baseline();
            match app.db.diff(&entries) {
                Ok((findings, sum)) => {
                    let changed = sum.new + sum.modified + sum.removed + sum.warn;
                    show(&win, &findings, sum);
                    win.set_status(SharedString::from(format!(
                        "Przeskanowano {} plików: {} zmian/ostrzeżeń{}.{}",
                        entries.len(),
                        changed,
                        if truncated {
                            " (obcięto do limitu)"
                        } else {
                            ""
                        },
                        // Same rule as the startup line: only `Intact` prints nothing. A
                        // baseline with no digest, or one that could not be read, is news.
                        if state.is_intact() {
                            String::new()
                        } else {
                            format!("  ⚠ WZORZEC {}", state.describe())
                        }
                    )));
                }
                Err(err) => win.set_status(SharedString::from(format!("Błąd skanu: {err}"))),
            }
            win.set_busy(false);
        });
    }

    win.run().expect("eos-guard: event loop failed");
}
