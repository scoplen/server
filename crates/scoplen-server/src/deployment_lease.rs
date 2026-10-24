// SPDX-License-Identifier: AGPL-3.0-only
//! Process-lifetime admission for local deployment state.

use std::{
    fs::{self, File, OpenOptions, TryLockError},
    io,
    path::Path,
    sync::Arc,
};

use crate::ServerError;

pub(crate) const FILE_NAME: &str = "deployment.lease";
#[cfg(windows)]
const FILE_SHARE_READ_WRITE: u32 = 0x0000_0003;
#[cfg(windows)]
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

/// A lock on the stable deployment lease file. Clones retain the same locked handle.
#[derive(Clone)]
pub struct DeploymentLease(Arc<File>);

impl DeploymentLease {
    /// Admit a server process or local mutation for its complete state-access lifetime.
    ///
    /// # Errors
    ///
    /// Fails if the private lease file is unsafe, unavailable, or exclusively locked.
    pub fn try_shared(data_dir: &Path) -> Result<Self, ServerError> {
        Self::acquire(data_dir, false)
    }

    /// Admit an offline operation only when no server or other local accessor remains.
    ///
    /// # Errors
    ///
    /// Fails if the private lease file is unsafe, unavailable, or already locked.
    pub fn try_exclusive(data_dir: &Path) -> Result<Self, ServerError> {
        Self::acquire(data_dir, true)
    }

    pub(crate) fn file(&self) -> Arc<File> {
        self.0.clone()
    }

    fn acquire(data_dir: &Path, exclusive: bool) -> Result<Self, ServerError> {
        let path = data_dir.join(FILE_NAME);
        check_directory(data_dir).map_err(ServerError::DeploymentLeaseUnavailable)?;
        #[cfg(windows)]
        crate::windows_private_directory::prepare_directory(data_dir, std::slice::from_ref(&path))
            .map_err(ServerError::DeploymentLeaseUnavailable)?;
        let file = open_private(&path).map_err(ServerError::DeploymentLeaseUnavailable)?;
        #[cfg(windows)]
        crate::windows_private_directory::prepare_directory(data_dir, std::slice::from_ref(&path))
            .map_err(ServerError::DeploymentLeaseUnavailable)?;
        let result = if exclusive { file.try_lock() } else { file.try_lock_shared() };
        match result {
            Ok(()) => Ok(Self(Arc::new(file))),
            Err(TryLockError::WouldBlock) => Err(ServerError::DeploymentLeaseOccupied),
            Err(TryLockError::Error(error)) => Err(ServerError::DeploymentLeaseUnavailable(error)),
        }
    }
}

fn open_private(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // Shared access admits other servers, while denying deletion keeps the lock-file name
        // bound to this inode until the final lease holder exits.
        options.share_mode(FILE_SHARE_READ_WRITE).custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            check_file(path, None)?;
            let mut existing = OpenOptions::new();
            existing.read(true).write(true);
            #[cfg(windows)]
            {
                use std::os::windows::fs::OpenOptionsExt;
                existing
                    .share_mode(FILE_SHARE_READ_WRITE)
                    .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
            }
            existing.open(path)?
        }
        Err(error) => return Err(error),
    };
    check_file(path, Some(&file))?;
    Ok(file)
}

fn check_directory(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(unsafe_path());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(unsafe_path());
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(unsafe_path());
        }
    }
    Ok(())
}

fn check_file(path: &Path, opened: Option<&File>) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(unsafe_path());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.permissions().mode() & 0o077 != 0 || metadata.nlink() != 1 {
            return Err(unsafe_path());
        }
        if let Some(opened) = opened {
            let handle = opened.metadata()?;
            if handle.dev() != metadata.dev() || handle.ino() != metadata.ino() {
                return Err(unsafe_path());
            }
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0
            || opened.is_some_and(|file| {
                file.metadata().map_or(true, |handle| handle.file_attributes() & 0x400 != 0)
            })
        {
            return Err(unsafe_path());
        }
    }
    Ok(())
}

fn unsafe_path() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "unsafe deployment lease path")
}

#[cfg(all(test, unix))]
mod unix_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn lease_path_must_still_name_the_open_file() {
        let root =
            std::env::temp_dir().join(format!("scoplen-lease-identity-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).expect("owned fixture root");
        let path = root.join("deployment.lease");
        let replacement = root.join("replacement");
        fs::write(&path, b"original").expect("original lease file");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("private original lease");
        let opened = File::open(&path).expect("retain original inode");
        fs::write(&replacement, b"replacement").expect("replacement lease file");
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600))
            .expect("private replacement lease");
        fs::rename(&replacement, &path).expect("replace path after opening original inode");

        let error = check_file(&path, Some(&opened)).expect_err("handle/path identity changed");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(fs::read(&path).expect("retained replacement"), b"replacement");
        drop(opened);
        fs::remove_dir_all(&root).expect("remove owned fixture root");
    }
}
