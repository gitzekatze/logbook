//! Spec of version 0.1a, step 2: protecting the store (claims L10.1 and
//! L10.2, both 🛡).
//!
//! Frozen by the owner's approval. The code PR includes it unchanged as an
//! integration test of its own, crates/logbook-store-write/tests/permissions.rs:
//!
//!     #[rustfmt::skip]
//!     #[path = "../../../verify/spec/step2/permissions_spec.rs"]
//!     mod spec_step2_permissions;
//!
//! A test binary of its own, because these tests set the process's umask to
//! 000 (nothing taken away from new files' permissions), so only an explicit
//! mode can make a file private. Dev-dependency: rustix (features fs,
//! process), for umask, inotify and file modes without unsafe code.
//!
//! The store folder is 0700 and every store file 0600 (F-L10), created that
//! way from the first moment: a file created open and closed off afterwards
//! would be readable for a moment. Inotify (the kernel's notice of file
//! changes) reports such a change of permissions as IN_ATTRIB, so the test
//! watches for it while the store is created.
//!
//! At every start, Writer::open checks the folder and every file in it
//! without following links (the folder opened with O_NOFOLLOW and
//! O_DIRECTORY, its owner the current user; modes changed through the opened
//! file), restores 0700/0600, and refuses with `StoreError::Unsafe` whatever
//! isn't a plain folder or a regular file with one link: a symlink, a FIFO,
//! a second hard link. A folder owned by another user is refused too; that
//! needs a second user and is tested on the test computers (step 8).

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use logbook_model::{Event, Lane, Severity};
use logbook_store::{Reader, DB_FILE};
use logbook_store_write::Writer;
use rustix::fs::inotify;

const NOW: i64 = 1_795_521_600_000_000;

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

fn open_everything() {
    // umask 000: the process takes nothing away; only explicit modes protect.
    rustix::process::umask(rustix::fs::Mode::empty());
}

/// Every file of the store that exists: the database, its WAL and its index.
fn store_files(dir: &Path) -> Vec<PathBuf> {
    ["", "-wal", "-shm"].iter().map(|s| dir.join(format!("{DB_FILE}{s}"))).filter(|p| p.exists()).collect()
}

/// Names that got a permission (or owner) change while `f` ran in `watched`.
fn attribute_changes(watched: &Path, f: impl FnOnce()) -> Vec<String> {
    let fd = inotify::init(inotify::CreateFlags::NONBLOCK | inotify::CreateFlags::CLOEXEC).unwrap();
    inotify::add_watch(&fd, watched, inotify::WatchFlags::ATTRIB).unwrap();
    f();
    let mut buf = [std::mem::MaybeUninit::uninit(); 8192];
    let mut reader = inotify::Reader::new(&fd, &mut buf);
    let mut out = Vec::new();
    while let Ok(event) = reader.next() {
        let name = event.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        out.push(name);
    }
    out
}

/// L10.2: a new store folder is 0700 and every new store file 0600 from its
/// creation: no permission is ever changed after the fact.
#[test]
fn l10_2_new_store_files_are_private_from_their_creation() {
    open_everything();
    let dir = TempDir::new();
    // The folder: created inside the watched parent, never changed afterwards.
    let changed = attribute_changes(dir.root(), || {
        let (mut w, report) = Writer::open(dir.path(), NOW).unwrap();
        assert!(report.fixed_permissions.is_empty(), "a new store had nothing to fix: {:?}", report.fixed_permissions);
        w.insert(&sample()).unwrap();
    });
    assert!(!changed.contains(&"logbook".to_owned()), "the store folder's permissions were changed after its creation");
    assert_eq!(mode(dir.path()), 0o700, "store folder");
    // The files: remove them, then watch the folder while the store is made again.
    for f in store_files(dir.path()) {
        std::fs::remove_file(f).unwrap();
    }
    // While writer and reader are open, the database, its WAL and its index
    // exist (SQLite removes the WAL when the last connection closes).
    let mut open_files = Vec::new();
    let changed = attribute_changes(dir.path(), || {
        let (mut w, _) = Writer::open(dir.path(), NOW).unwrap();
        w.insert(&sample()).unwrap();
        let r = Reader::open(dir.path()).unwrap();
        r.count().unwrap();
        open_files = store_files(dir.path()).into_iter().map(|f| (mode(&f), f)).collect();
    });
    assert_eq!(open_files.len(), 3, "expected the database, its WAL and its index, found {open_files:?}");
    for (m, f) in &open_files {
        assert_eq!(*m, 0o600, "{}", f.display());
    }
    assert!(changed.is_empty(), "store files got their permissions changed after creation: {changed:?}");
}

/// L10.1: after a deliberately wrong permission, the next start restores
/// 0700/0600 and records it as an event.
#[test]
fn l10_1_wrong_permissions_are_restored_and_recorded() {
    open_everything();
    for (dir_mode, file_mode) in [(0o755, 0o644), (0o777, 0o666), (0o700, 0o640), (0o750, 0o600)] {
        let dir = TempDir::new();
        {
            let (mut w, _) = Writer::open(dir.path(), NOW).unwrap();
            w.insert(&sample()).unwrap();
        }
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(dir_mode)).unwrap();
        let db = dir.path().join(DB_FILE);
        std::fs::set_permissions(&db, std::fs::Permissions::from_mode(file_mode)).unwrap();
        let (w, report) = Writer::open(dir.path(), NOW + 1).unwrap();
        drop(w);
        let mut want = Vec::new();
        if dir_mode != 0o700 {
            want.push(dir.path().to_owned());
        }
        if file_mode != 0o600 {
            want.push(db.clone());
        }
        let mut got = report.fixed_permissions.clone();
        got.sort();
        want.sort();
        assert_eq!(got, want, "{dir_mode:o}/{file_mode:o}: what was fixed");
        assert_eq!(mode(dir.path()), 0o700, "{dir_mode:o}: folder");
        for f in store_files(dir.path()) {
            assert_eq!(mode(&f), 0o600, "{file_mode:o}: {}", f.display());
        }
        let notes: Vec<Event> = Reader::open(dir.path()).unwrap().events().unwrap()
            .into_iter().filter(|e| e.kind == "logbook.permissions_fixed").collect();
        assert_eq!(notes.len(), 1, "{dir_mode:o}/{file_mode:o}: the fix is recorded once");
        assert_eq!((notes[0].lane, notes[0].severity), (Lane::Logbook, Severity::Problem));
    }
}

/// L10.1: every file in the store folder ends up 0600, not only the
/// database: a WAL left by a crash (fixed before SQLite opens it), a
/// damaged copy, any other file.
#[test]
fn l10_1_every_file_in_the_store_folder_is_restored() {
    open_everything();
    let dir = TempDir::new();
    let (mut w, _) = Writer::open(dir.path(), NOW).unwrap();
    w.insert(&sample()).unwrap();
    // A crash image: copy the files while the writer runs.
    let crashed = TempDir::new();
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(crashed.path()).unwrap();
    }
    for f in store_files(dir.path()) {
        std::fs::copy(&f, crashed.path().join(f.file_name().unwrap())).unwrap();
    }
    drop(w);
    let wal = crashed.path().join(format!("{DB_FILE}-wal"));
    assert!(wal.exists());
    let copy = crashed.path().join("logbook.db.damaged-20261101T000000Z");
    let other = crashed.path().join("notes.txt");
    std::fs::write(&copy, b"old damaged copy").unwrap();
    std::fs::write(&other, b"something else").unwrap();
    for f in [&wal, &copy, &other] {
        std::fs::set_permissions(f, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    let (w, report) = Writer::open(crashed.path(), NOW + 1).unwrap();
    drop(w);
    for f in [&wal, &copy, &other] {
        assert!(report.fixed_permissions.contains(f), "{} wasn't fixed: {:?}", f.display(), report.fixed_permissions);
    }
    for entry in std::fs::read_dir(crashed.path()).unwrap() {
        let f = entry.unwrap().path();
        assert_eq!(mode(&f), 0o600, "{}", f.display());
    }
    assert_eq!(Reader::open(crashed.path()).unwrap().events().unwrap().iter()
        .filter(|e| e.kind == "logbook.permissions_fixed").count(), 1);
}

/// L10.1/L10.2: a store folder or store file that isn't what it must be is
/// refused, and nothing outside the store is touched: a symlinked folder or
/// database (restoring 0600 through a link would change some other file), a
/// symlinked WAL, a database that is a FIFO or has a second hard link.
#[test]
fn l10_1_links_and_odd_files_in_the_store_are_refused() {
    open_everything();
    use std::os::unix::fs::symlink;
    let cases: [(&str, fn(&Path, &Path)); 5] = [
        ("the store folder is a symlink", |store, outside| {
            std::fs::create_dir(outside).unwrap();
            symlink(outside, store).unwrap();
        }),
        ("the database is a symlink", |store, outside| {
            make_store(store);
            std::fs::remove_file(store.join(DB_FILE)).unwrap();
            std::fs::write(outside, b"someone else's file").unwrap();
            symlink(outside, store.join(DB_FILE)).unwrap();
        }),
        ("the WAL is a symlink", |store, outside| {
            make_store(store);
            std::fs::write(outside, b"someone else's file").unwrap();
            symlink(outside, store.join(format!("{DB_FILE}-wal"))).unwrap();
        }),
        ("the database is a FIFO", |store, _| {
            make_store(store);
            std::fs::remove_file(store.join(DB_FILE)).unwrap();
            rustix::fs::mknodat(rustix::fs::CWD, store.join(DB_FILE), rustix::fs::FileType::Fifo,
                rustix::fs::Mode::from_raw_mode(0o600), 0).unwrap();
        }),
        ("the database has a second hard link", |store, outside| {
            make_store(store);
            std::fs::hard_link(store.join(DB_FILE), outside).unwrap();
        }),
    ];
    for (what, setup) in cases {
        let dir = TempDir::new();
        let outside = dir.root().join("outside");
        setup(dir.path(), &outside);
        let outside_mode = std::fs::symlink_metadata(&outside).ok().map(|_| mode(&outside));
        if outside_mode.is_some() {
            std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        match Writer::open(dir.path(), NOW) {
            Err(logbook_store::StoreError::Unsafe(_)) => {}
            Err(other) => panic!("{what}: refused, but not as unsafe: {other:?}"),
            Ok(_) => panic!("{what}: the store was opened"),
        }
        if outside_mode.is_some() {
            assert_eq!(mode(&outside), 0o644, "{what}: a file outside the store was changed");
        }
    }
}

/// A healthy store with its writer closed, for the cases above to damage.
fn make_store(dir: &Path) {
    let (mut w, _) = Writer::open(dir, NOW).unwrap();
    w.insert(&sample()).unwrap();
}

fn sample() -> Event {
    let id = logbook_model::EventId::derive("spec", b"permissions", 0).unwrap();
    serde_json::from_value(serde_json::json!({
        "id": id.as_str(), "time": "2026-11-24T12:00:00.000000Z", "last_time": null, "end": null,
        "utc_offset": 0, "lane": "system", "kind": "spec.example", "template": "spec.example",
        "severity": "info",
        "subject": {"type": "system", "name": "example", "version": null, "source_kind": "none",
                    "package": null, "path": null},
        "summary": "Example.", "details": {}, "count": 1, "first_time": false, "links": [],
        "raw": [], "raw_omitted": 0, "raw_lossy": false,
        "source": {"reader": "spec", "mode": "live"}, "rules_version": 1, "time_uncertain": false
    }))
    .unwrap()
}

struct TempDir {
    root: PathBuf,
    store: PathBuf,
}

impl TempDir {
    fn new() -> TempDir {
        static N: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "logbook-spec2p-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let store = root.join("logbook");
        TempDir { root, store }
    }

    fn root(&self) -> &Path {
        &self.root
    }

    fn path(&self) -> &Path {
        &self.store
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
