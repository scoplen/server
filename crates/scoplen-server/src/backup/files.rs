// SPDX-License-Identifier: AGPL-3.0-only
//! Private local staging and non-replacing publication.

use std::{
    fs::{self, File, OpenOptions},
    io,
    path::{Component, Path, PathBuf},
};

use super::{BackupError, Result, fail};

pub(super) fn existing(path: &Path, directory: bool) -> Result<PathBuf> {
    let absolute = std::path::absolute(path).map_err(|_| fail("resolve local path"))?;
    #[cfg(windows)]
    {
        if !matches!(absolute.components().next(), Some(Component::Prefix(prefix)) if matches!(prefix.kind(), std::path::Prefix::Disk(_)))
        {
            return Err(fail("local paths must use an ordinary local drive"));
        }
    }
    let mut checked = PathBuf::new();
    for component in absolute.components() {
        if component == Component::ParentDir {
            return Err(fail("local paths must not contain parent traversal"));
        }
        checked.push(component.as_os_str());
        let metadata =
            fs::symlink_metadata(&checked).map_err(|_| fail("read existing local path"))?;
        if metadata.file_type().is_symlink() {
            return Err(fail("links are not supported in deployment paths"));
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err(fail("reparse points are not supported in deployment paths"));
            }
        }
        if checked != absolute && !metadata.is_dir() {
            return Err(fail("local path ancestry must be directories"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            if metadata.is_dir()
                && metadata.permissions().mode() & 0o022 != 0
                && metadata.permissions().mode() & 0o1000 == 0
            {
                return Err(fail("local directory ancestry must not be writable by other users"));
            }
            if metadata.is_file() && metadata.nlink() != 1 {
                return Err(fail("hard-linked source files are not supported"));
            }
        }
    }
    let metadata = fs::symlink_metadata(&absolute).map_err(|_| fail("read existing local path"))?;
    if if directory { !metadata.is_dir() } else { !metadata.is_file() } {
        return Err(fail("local resource has the wrong file type"));
    }
    let canonical = fs::canonicalize(absolute).map_err(|_| fail("resolve existing local path"))?;
    #[cfg(windows)]
    {
        let value = canonical.to_str().ok_or_else(|| fail("local paths must be UTF-8"))?;
        Ok(PathBuf::from(value.strip_prefix(r"\\?\").unwrap_or(value)))
    }
    #[cfg(not(windows))]
    Ok(canonical)
}

pub(super) fn destination(path: &Path) -> Result<PathBuf> {
    let absolute = std::path::absolute(path).map_err(|_| fail("resolve destination"))?;
    if absolute.components().any(|part| part == Component::ParentDir) {
        return Err(fail("destination must not contain parent traversal"));
    }
    if fs::symlink_metadata(&absolute).is_ok() {
        return Err(fail("destination already exists; choose an absent destination"));
    }
    let name = absolute
        .file_name()
        .ok_or_else(|| fail("destination must be a new child directory or file"))?;
    let parent = existing(absolute.parent().ok_or_else(|| fail("destination parent"))?, true)?;
    #[cfg(windows)]
    crate::windows_private_directory::prepare_directory(&parent, &[])
        .map_err(|_| fail("private destination parent permissions"))?;
    Ok(parent.join(name))
}

pub(super) fn private_file(path: &Path) -> Result<File> {
    #[cfg(windows)]
    crate::windows_private_directory::prepare_directory(
        path.parent().ok_or_else(|| fail("private staging file parent"))?,
        &[path.to_path_buf()],
    )
    .map_err(|_| fail("private staging file path or permissions"))?;
    let mut options = OpenOptions::new();
    options.write(true).read(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).map_err(|_| fail("create private staging file"))
}

pub(super) fn private_directory(path: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        if fs::symlink_metadata(path).is_ok() {
            return Err(fail("staging directory already exists"));
        }
        crate::windows_private_directory::prepare_directory(path, &[])
            .map_err(|_| fail("create private staging directory"))?;
    }
    #[cfg(not(windows))]
    {
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(path).map_err(|_| fail("create private staging directory"))?;
    }
    Ok(())
}

pub(super) fn parents(root: &Path, path: &Path) -> Result<()> {
    let parent = path.parent().ok_or_else(|| fail("payload parent"))?;
    let relative = parent.strip_prefix(root).map_err(|_| fail("payload path escapes staging"))?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        if !matches!(component, Component::Normal(_)) {
            return Err(fail("invalid payload parent"));
        }
        current.push(component);
        if !current.exists() {
            private_directory(&current)?;
        }
    }
    Ok(())
}

pub(super) fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    File::open(path).and_then(|file| file.sync_all()).map_err(|_| fail("synchronize directory"))?;
    #[cfg(not(unix))]
    {
        existing(path, true)?;
    }
    Ok(())
}

pub(super) fn sync_tree(path: &Path) -> Result<()> {
    for entry in fs::read_dir(path).map_err(|_| fail("read staging directory"))? {
        let entry = entry.map_err(|_| fail("read staging entry"))?;
        if entry.file_type().map_err(|_| fail("read staging entry type"))?.is_dir() {
            sync_tree(&entry.path())?;
        }
    }
    sync_directory(path)
}

pub(super) fn publish_directory(source: &Path, destination: &Path) -> Result<()> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        rustix::fs::renameat_with(
            rustix::fs::CWD,
            source,
            rustix::fs::CWD,
            destination,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(|_| fail("publish restore without replacing an existing destination"))?;
    }
    #[cfg(windows)]
    crate::windows_private_directory::move_directory(source, destination)
        .map_err(|_| fail("publish restore without replacing an existing destination"))?;
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    return Err(fail("atomic no-replace restore is unsupported on this platform"));
    sync_directory(destination.parent().ok_or_else(|| fail("restore parent"))?)
}

pub(super) struct Staging(pub PathBuf);

impl Staging {
    pub(super) fn new(parent: &Path) -> Result<Self> {
        let path = parent.join(format!(".scoplen-backup-{}", uuid::Uuid::new_v4()));
        private_directory(&path)?;
        Ok(Self(path))
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub(super) fn io_error(phase: &'static str) -> impl FnOnce(io::Error) -> BackupError {
    move |_| fail(phase)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directory_publication_never_replaces_an_existing_empty_directory() {
        let staging = Staging::new(&std::env::temp_dir()).expect("private test parent");
        let source = staging.0.join("source");
        let destination = staging.0.join("destination");
        private_directory(&source).expect("source");
        private_directory(&destination).expect("occupied destination");
        fs::write(source.join("retained"), b"payload").expect("source marker");
        assert!(publish_directory(&source, &destination).is_err());
        assert!(source.join("retained").is_file());
        assert_eq!(fs::read_dir(&destination).expect("unchanged destination").count(), 0);
        fs::remove_dir(&destination).expect("remove owned empty test destination");
        publish_directory(&source, &destination).expect("publish absent child");
        assert_eq!(fs::read(destination.join("retained")).expect("published marker"), b"payload");
    }
}
