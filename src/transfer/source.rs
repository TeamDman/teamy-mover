//! Platform-specific source opening and change detection.

use eyre::Result;
#[cfg(target_os = "linux")]
use eyre::ensure;
use std::fs::File;
use std::time::SystemTime;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Fingerprint {
    pub device: u64,
    pub object: u64,
    length: u64,
    modified: SystemTime,
    #[cfg(target_os = "linux")]
    changed_secs: i64,
    #[cfg(target_os = "linux")]
    changed_nanos: i64,
}

#[cfg(windows)]
pub(super) fn fingerprint(file: &File) -> Result<Fingerprint> {
    let id = super::windows_lock::regular_file_identity(file)?;
    let metadata = file.metadata()?;
    Ok(Fingerprint {
        device: u64::from(id.volume_serial),
        object: id.file_index,
        length: metadata.len(),
        modified: metadata.modified()?,
    })
}

#[cfg(target_os = "linux")]
pub(super) fn fingerprint(file: &File) -> Result<Fingerprint> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.nlink() == 1 && metadata.ino() != 0,
        "source is not a uniquely linked regular file"
    );
    Ok(Fingerprint {
        device: metadata.dev(),
        object: metadata.ino(),
        length: metadata.len(),
        modified: metadata.modified()?,
        changed_secs: metadata.ctime(),
        changed_nanos: metadata.ctime_nsec(),
    })
}

/// Open an absolute Linux path one component at a time without following any
/// symlink, including the final component. O_NONBLOCK prevents FIFO opens from
/// hanging; fingerprint validation rejects non-regular files and hard links.
#[cfg(target_os = "linux")]
pub(super) fn open_linux(path: &std::path::Path) -> Result<File> {
    use rustix::fs::Mode;
    use rustix::fs::OFlags;
    use rustix::fs::openat;
    use std::path::Component;
    let mut components = path.components().peekable();
    ensure!(
        components.next() == Some(Component::RootDir),
        "source path must be absolute"
    );
    let mut parent = File::open("/")?;
    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            eyre::bail!("unsafe source path component");
        };
        let mut flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK;
        if components.peek().is_some() {
            flags |= OFlags::DIRECTORY;
        }
        let opened: File = openat(&parent, name, flags, Mode::empty())?.into();
        if components.peek().is_none() {
            fingerprint(&opened)?;
            return Ok(opened);
        }
        parent = opened;
    }
    eyre::bail!("source path must name a file")
}
