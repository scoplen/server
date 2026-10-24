// SPDX-License-Identifier: AGPL-3.0-only

use std::{
    fs,
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use scoplen_server::{Config, ServerError, bootstrap, deployment_lease::DeploymentLease};

const DEADLINE: Duration = Duration::from_secs(10);

struct Fixture {
    root: PathBuf,
    config: Config,
    config_file: PathBuf,
    port: u16,
}

impl Fixture {
    fn new() -> Self {
        let root =
            std::env::temp_dir().join(format!("scoplen-deployment-lease-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).expect("owned fixture root");
        let port = TcpListener::bind("127.0.0.1:0")
            .expect("reserve test port")
            .local_addr()
            .expect("test listener address")
            .port();
        let mut config = Config::default();
        config.server.public_host = "localhost".into();
        config.server.listen_addr = "127.0.0.1".into();
        config.server.listen_port = port;
        config.server.data_dir = root.join("data");
        let config_file = root.join("server.toml");
        fs::write(
            &config_file,
            format!(
                "[server]\npublic_host = 'localhost'\nlisten_addr = '127.0.0.1'\nlisten_port = {port}\ndata_dir = '{}'\n[tls]\nmode = 'plain'\n",
                config.server.data_dir.to_string_lossy().replace('\\', "/")
            ),
        )
        .expect("write server configuration");
        Self { root, config, config_file, port }
    }

    fn server(&self) -> ChildGuard {
        let mut command = Command::new(env!("CARGO_BIN_EXE_spl-server"));
        command
            .args(["--role", "api", "--config"])
            .arg(&self.config_file)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x0800_0000);
        }
        ChildGuard(command.spawn().expect("start real server"))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).expect("remove owned fixture root");
    }
}

struct ChildGuard(Child);

impl ChildGuard {
    fn stop(&mut self) {
        if self.0.try_wait().expect("server exit status").is_none() {
            self.0.kill().expect("stop owned server");
        }
        self.0.wait().expect("reap owned server");
    }

    fn wait_for_exit(&mut self) -> bool {
        let started = Instant::now();
        loop {
            if let Some(status) = self.0.try_wait().expect("server exit status") {
                return status.success();
            }
            if started.elapsed() >= DEADLINE {
                self.stop();
                panic!("server did not exit while deployment lease was occupied");
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.stop();
    }
}

fn wait_for_listener(child: &mut ChildGuard, port: u16) {
    let started = Instant::now();
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        assert!(child.0.try_wait().expect("server status").is_none(), "server exited before ready");
        assert!(started.elapsed() < DEADLINE, "server listener did not start");
        thread::sleep(Duration::from_millis(20));
    }
}

fn assert_exclusive_occupied(data_dir: &Path) {
    assert!(
        matches!(
            DeploymentLease::try_exclusive(data_dir),
            Err(ServerError::DeploymentLeaseOccupied)
        ),
        "running server must exclude a local backup"
    );
}

#[test]
fn real_server_holds_shared_lease_until_process_exit() {
    let fixture = Fixture::new();
    let mut server = fixture.server();
    wait_for_listener(&mut server, fixture.port);

    let second_shared = DeploymentLease::try_shared(&fixture.config.server.data_dir)
        .expect("another local accessor may share the lease");
    assert_exclusive_occupied(&fixture.config.server.data_dir);
    drop(second_shared);
    assert_exclusive_occupied(&fixture.config.server.data_dir);

    server.stop();
    let exclusive = DeploymentLease::try_exclusive(&fixture.config.server.data_dir)
        .expect("server process exit releases the lease");
    drop(exclusive);
}

#[test]
fn occupied_exclusive_lease_rejects_server_before_storage_creation() {
    let fixture = Fixture::new();
    bootstrap(&fixture.config).expect("private fixture data directory");
    assert!(!fixture.config.server.data_dir.join("scoplen.sqlite").exists());
    let exclusive = DeploymentLease::try_exclusive(&fixture.config.server.data_dir)
        .expect("offline operation owns exclusive admission");
    let mut server = fixture.server();
    assert!(!server.wait_for_exit(), "server must refuse the occupied lease");
    assert!(!fixture.config.server.data_dir.join("scoplen.sqlite").exists());
    assert!(!fixture.config.server.data_dir.join("objects").exists());
    drop(exclusive);
}

#[cfg(unix)]
#[test]
fn unix_lease_rejects_group_writable_data_directory() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = Fixture::new();
    bootstrap(&fixture.config).expect("private deployment");
    fs::set_permissions(&fixture.config.server.data_dir, fs::Permissions::from_mode(0o770))
        .expect("owned fixture permissions");
    assert!(matches!(
        DeploymentLease::try_shared(&fixture.config.server.data_dir),
        Err(ServerError::DeploymentLeaseUnavailable(_))
    ));
}

#[cfg(unix)]
#[test]
fn unix_lease_rejects_group_readable_file() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = Fixture::new();
    bootstrap(&fixture.config).expect("private deployment");
    let path = fixture.config.server.data_dir.join("deployment.lease");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640))
        .expect("owned fixture permissions");
    assert!(matches!(
        DeploymentLease::try_shared(&fixture.config.server.data_dir),
        Err(ServerError::DeploymentLeaseUnavailable(_))
    ));
    assert!(path.is_file(), "unsafe lease remains available for operator inspection");
}

#[cfg(unix)]
#[test]
fn unix_lease_rejects_hard_link() {
    let fixture = Fixture::new();
    bootstrap(&fixture.config).expect("private deployment");
    let path = fixture.config.server.data_dir.join("deployment.lease");
    let alias = fixture.root.join("linked-lease");
    fs::hard_link(&path, &alias).expect("owned hard link fixture");
    assert!(matches!(
        DeploymentLease::try_shared(&fixture.config.server.data_dir),
        Err(ServerError::DeploymentLeaseUnavailable(_))
    ));
    assert!(path.is_file() && alias.is_file(), "rejected links remain unchanged");
}

#[cfg(unix)]
#[test]
fn unix_lease_rejects_symbolic_link_file_and_directory() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new();
    bootstrap(&fixture.config).expect("private deployment");
    let data_dir = &fixture.config.server.data_dir;
    let path = data_dir.join("deployment.lease");
    let target = fixture.root.join("lease-target");
    fs::rename(&path, &target).expect("move owned lease into fixture root");
    symlink(&target, &path).expect("owned symbolic link fixture");
    assert!(matches!(
        DeploymentLease::try_shared(data_dir),
        Err(ServerError::DeploymentLeaseUnavailable(_))
    ));

    let alias = fixture.root.join("linked-data");
    symlink(data_dir, &alias).expect("owned directory symbolic link fixture");
    assert!(matches!(
        DeploymentLease::try_shared(&alias),
        Err(ServerError::DeploymentLeaseUnavailable(_))
    ));
    assert!(target.is_file(), "rejected target remains unchanged");
}

#[cfg(windows)]
#[test]
fn windows_lease_path_cannot_be_renamed_or_deleted_while_held() {
    let fixture = Fixture::new();
    bootstrap(&fixture.config).expect("private deployment");
    let path = fixture.config.server.data_dir.join("deployment.lease");
    let renamed = fixture.config.server.data_dir.join("deployment-renamed.lease");
    let held = DeploymentLease::try_shared(&fixture.config.server.data_dir)
        .expect("hold deployment lease file open");

    assert!(fs::rename(&path, &renamed).is_err(), "held lease must deny rename");
    assert!(fs::remove_file(&path).is_err(), "held lease must deny deletion");
    assert!(path.is_file() && !renamed.exists(), "stable lease path remains bound");

    drop(held);
    fs::rename(&path, &renamed).expect("rename allowed after final lease release");
    fs::remove_file(&renamed).expect("deletion allowed after final lease release");
}
