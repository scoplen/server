// SPDX-License-Identifier: AGPL-3.0-only
//! Creation of first-run material without exposing or replacing existing files.

use std::{fs::OpenOptions, io::Write, path::Path};

pub(crate) fn write_private(path: &Path, contents: &str) -> std::io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    // Set permissions in the creation syscall, before any secret bytes are written.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(contents.as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::ErrorKind,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::write_private;

    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let nonce = SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_nanos();
            let path = std::env::temp_dir().join(format!(
                "scoplen-private-material-{}-{nonce}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).expect("create owned scratch directory");
            Self(path)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("remove owned scratch directory");
        }
    }

    #[test]
    fn new_material_is_complete_and_existing_material_is_not_replaced() {
        let scratch = Scratch::new();
        let path = scratch.0.join("synthetic.key");
        write_private(&path, "synthetic material").expect("create material");
        assert_eq!(fs::read(&path).expect("read material"), b"synthetic material\n");
        let error = write_private(&path, "replacement").expect_err("refuse overwrite");
        assert_eq!(error.kind(), ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&path).expect("read retained material"), b"synthetic material\n");
    }

    #[cfg(unix)]
    #[test]
    fn new_material_has_no_group_or_other_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let scratch = Scratch::new();
        let path = scratch.0.join("synthetic.key");
        write_private(&path, "synthetic material").expect("create material");
        assert_eq!(fs::metadata(path).expect("metadata").permissions().mode() & 0o777, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_destinations_are_never_followed() {
        use std::os::unix::fs::symlink;

        let scratch = Scratch::new();
        let target = scratch.0.join("target");
        fs::write(&target, "retained contents").expect("create target");
        let link = scratch.0.join("synthetic.key");
        symlink(&target, &link).expect("create symlink");
        assert_eq!(
            write_private(&link, "replacement").unwrap_err().kind(),
            ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read(&target).expect("unchanged target"), b"retained contents");
        let dangling = scratch.0.join("dangling.key");
        let absent = scratch.0.join("absent");
        symlink(&absent, &dangling).expect("create dangling symlink");
        assert_eq!(
            write_private(&dangling, "replacement").unwrap_err().kind(),
            ErrorKind::AlreadyExists
        );
        assert!(!absent.exists());
    }
}
