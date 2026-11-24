//! The store folder and its files (F-L10): 0700 and 0600 from the first
//! moment, checked at every start without following links.

use std::path::{Path, PathBuf};

use logbook_store::StoreError;
use rustix::fs::{FileType, Mode, OFlags};
use rustix::io::Errno;

/// Permissions of the store folder and of every file in it.
pub const FOLDER_MODE: u32 = 0o700;
pub const FILE_MODE: u32 = 0o600;

fn unsafe_store(why: String) -> StoreError {
    StoreError::Unsafe(why)
}

fn io(e: Errno) -> StoreError {
    StoreError::Io(e.into())
}

/// Makes sure `dir` is a private store folder: creates it as 0700 if it is
/// missing; otherwise checks it is a real folder of this user, and that
/// everything in it is a regular file of this user with one link, restoring
/// 0700/0600 through the opened files. Returns what it had to fix.
pub fn secure(dir: &Path) -> Result<Vec<PathBuf>, StoreError> {
    let mut fixed = Vec::new();
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let folder = match rustix::fs::open(dir, flags, Mode::empty()) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => {
            if let Some(parent) = dir.parent() {
                std::fs::create_dir_all(parent)?;
            }
            // Created private: the mode is given here, never fixed afterwards.
            rustix::fs::mkdir(dir, Mode::from_raw_mode(FOLDER_MODE)).map_err(io)?;
            return Ok(fixed);
        }
        Err(Errno::LOOP | Errno::NOTDIR) => {
            return Err(unsafe_store(format!(
                "{} isn't a plain folder (a link or a file)",
                dir.display()
            )))
        }
        Err(e) => return Err(io(e)),
    };
    let me = rustix::process::geteuid().as_raw();
    let stat = rustix::fs::fstat(&folder).map_err(io)?;
    if stat.st_uid != me {
        return Err(unsafe_store(format!(
            "{} belongs to another user",
            dir.display()
        )));
    }
    if stat.st_mode & 0o7777 != FOLDER_MODE {
        rustix::fs::fchmod(&folder, Mode::from_raw_mode(FOLDER_MODE)).map_err(io)?;
        fixed.push(dir.to_owned());
    }
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)?
        .map(|e| e.map(|e| e.path()))
        .collect::<Result<_, _>>()?;
    entries.sort();
    for path in entries {
        if secure_file(&path)? {
            fixed.push(path);
        }
    }
    Ok(fixed)
}

/// Checks one file in the store folder without following a link; returns
/// whether its mode had to be restored to 0600.
fn secure_file(path: &Path) -> Result<bool, StoreError> {
    // NONBLOCK: opening a FIFO must not wait for a writer.
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let file = match rustix::fs::open(path, flags, Mode::empty()) {
        Ok(fd) => fd,
        Err(Errno::LOOP) => return Err(unsafe_store(format!("{} is a link", path.display()))),
        Err(e) => return Err(io(e)),
    };
    let stat = rustix::fs::fstat(&file).map_err(io)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Err(unsafe_store(format!(
            "{} isn't a regular file",
            path.display()
        )));
    }
    if stat.st_nlink != 1 {
        return Err(unsafe_store(format!(
            "{} has a second name (a hard link)",
            path.display()
        )));
    }
    if stat.st_uid != rustix::process::geteuid().as_raw() {
        return Err(unsafe_store(format!(
            "{} belongs to another user",
            path.display()
        )));
    }
    if stat.st_mode & 0o7777 == FILE_MODE {
        return Ok(false);
    }
    rustix::fs::fchmod(&file, Mode::from_raw_mode(FILE_MODE)).map_err(io)?;
    Ok(true)
}

/// Creates a new, empty store file with 0600 from the first moment; fails if
/// anything is already there.
pub fn create_file(path: &Path) -> Result<(), StoreError> {
    let flags = OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    rustix::fs::open(path, flags, Mode::from_raw_mode(FILE_MODE)).map_err(io)?;
    Ok(())
}
