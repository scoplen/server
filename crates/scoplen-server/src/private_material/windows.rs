// SPDX-License-Identifier: AGPL-3.0-only
//! Windows ACL admission without exposing native pointers or interpreting caller text as code.

use std::{
    io,
    os::windows::process::CommandExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

const SCRIPT: &str = include_str!("windows-acl.ps1");
const DEADLINE: Duration = Duration::from_secs(15);
const UNAVAILABLE: &str = "Windows data-directory access could not be verified. Windows PowerShell 5.1 with .NET filesystem access-control support is required. Enable it for the server account and retry; see docs/windows-data-directory.md.";
const DENIED: &str = "Windows data-directory or key permissions are unsafe or unsupported. No existing permissions were changed. Provision a private directory for the server account and review existing key files and writable parents; see docs/windows-data-directory.md.";

#[derive(serde::Serialize)]
struct AdmissionInput<'a> {
    directory: &'a Path,
    files: &'a [PathBuf],
}

pub(crate) fn prepare_directory(directory: &Path, files: &[PathBuf]) -> io::Result<()> {
    let system_root = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, UNAVAILABLE))?;
    // Use the OS executable directly: PATH and shell profiles cannot select another program.
    let executable = system_root.join("System32/WindowsPowerShell/v1.0/powershell.exe");
    let input = serde_json::to_string(&AdmissionInput { directory, files })
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, DENIED))?;
    let child = Command::new(executable)
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-OutputFormat",
            "Text",
            "-Command",
            SCRIPT,
        ])
        .env("SCOPLEN_PRIVATE_DIRECTORY_INPUT", input)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
        .spawn()
        .map_err(|_| io::Error::new(io::ErrorKind::NotFound, UNAVAILABLE))?;
    wait_for_admission(child, DEADLINE)
}

fn wait_for_admission(mut child: Child, deadline: Duration) -> io::Result<()> {
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(status)) if status.code() == Some(2) => {
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, DENIED));
            }
            Ok(Some(_)) => return Err(io::Error::other(UNAVAILABLE)),
            Ok(None) if started.elapsed() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            result => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(io::Error::new(
                    if result.is_err() { io::ErrorKind::Other } else { io::ErrorKind::TimedOut },
                    UNAVAILABLE,
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unpaired_utf16_path_is_rejected_without_panicking() {
        use std::{ffi::OsString, os::windows::ffi::OsStringExt};

        let path =
            OsString::from_wide(&[u16::from(b'C'), u16::from(b':'), u16::from(b'\\'), 0xd800]);
        let error = prepare_directory(Path::new(&path), &[]).expect_err("invalid path");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn stalled_permission_check_is_terminated_and_reaped() {
        let executable =
            PathBuf::from(std::env::var_os("SystemRoot").expect("Windows system root"))
                .join("System32/WindowsPowerShell/v1.0/powershell.exe");
        let child = Command::new(executable)
            .args(["-NoProfile", "-NonInteractive", "-Command", "Start-Sleep -Seconds 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(0x0800_0000)
            .spawn()
            .expect("owned stalled helper");
        let started = Instant::now();
        let error =
            wait_for_admission(child, Duration::from_millis(80)).expect_err("bounded check");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
