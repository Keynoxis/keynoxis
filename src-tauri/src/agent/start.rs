// SPDX-License-Identifier: MPL-2.0

use crate::{agent::server, state::RuntimeState};
use std::{
    fs,
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
    time::Duration,
};
use tauri::Manager;

const MAX_AGENT_CONNECTIONS: usize = 32;

struct ConnectionLimiter {
    active: AtomicUsize,
    limit: usize,
}

impl ConnectionLimiter {
    fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            active: AtomicUsize::new(0),
            limit,
        })
    }

    fn try_acquire(self: &Arc<Self>) -> Option<ConnectionPermit> {
        self.active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < self.limit).then_some(active + 1)
            })
            .ok()
            .map(|_| ConnectionPermit(self.clone()))
    }
}

struct ConnectionPermit(Arc<ConnectionLimiter>);

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::AcqRel);
    }
}

pub struct Agent {
    pub socket: String,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    socket_identity: (u64, u64),
}

impl Agent {
    pub fn is_healthy(&self) -> bool {
        fs::metadata(&self.socket)
            .map(|metadata| metadata.file_type().is_socket())
            .unwrap_or(false)
            && UnixStream::connect(&self.socket).is_ok()
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        // A newer Keynoxis may already have replaced the pathname while this
        // process was shutting down. Remove only the socket inode we created.
        if fs::metadata(&self.socket)
            .map(|metadata| (metadata.dev(), metadata.ino()))
            .ok()
            == Some(self.socket_identity)
        {
            let _ = fs::remove_file(&self.socket);
        }
    }
}

pub fn ensure(app: &tauri::AppHandle, state: Arc<RuntimeState>) -> Result<Agent, String> {
    let home = app.path().home_dir().map_err(|e| e.to_string())?;
    let ssh_directory = home.join(".ssh");
    fs::create_dir_all(&ssh_directory).map_err(|e| format!("Could not create ~/.ssh: {e}"))?;
    let _ = fs::set_permissions(&ssh_directory, fs::Permissions::from_mode(0o700));

    cleanup_legacy_socket(&ssh_directory);
    let socket_path: PathBuf = ssh_directory.join("keynoxis.sock");
    if socket_path.exists() {
        fs::remove_file(&socket_path)
            .map_err(|e| format!("Could not clear stale Keynoxis socket: {e}"))?;
    }
    let listener = UnixListener::bind(&socket_path)
        .map_err(|e| format!("Could not create Keynoxis socket: {e}"))?;
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("Could not secure Keynoxis socket: {e}"))?;
    let socket_metadata = fs::metadata(&socket_path)
        .map_err(|e| format!("Could not inspect Keynoxis socket: {e}"))?;
    let socket_identity = (socket_metadata.dev(), socket_metadata.ino());
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("Could not configure Keynoxis socket: {e}"))?;

    super::integration::install(&home, &socket_path)?;

    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = stop.clone();
    let thread_app = app.clone();
    let connections = ConnectionLimiter::new(MAX_AGENT_CONNECTIONS);
    let thread = thread::spawn(move || {
        while !thread_stop.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((stream, _)) => {
                    if let Some(permit) = connections.try_acquire() {
                        let connection_state = state.clone();
                        let connection_app = thread_app.clone();
                        thread::spawn(move || {
                            let _permit = permit;
                            let _ = server::serve(stream, connection_app, connection_state);
                        });
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(40));
                }
                Err(_) => thread::sleep(Duration::from_millis(100)),
            }
        }
    });

    Ok(Agent {
        socket: socket_path.to_string_lossy().into_owned(),
        stop,
        thread: Some(thread),
        socket_identity,
    })
}

fn cleanup_legacy_socket(ssh_directory: &std::path::Path) {
    let legacy = ssh_directory.join("yubiagent.sock");
    let is_socket = fs::symlink_metadata(&legacy)
        .map(|metadata| metadata.file_type().is_socket())
        .unwrap_or(false);
    if is_socket && UnixStream::connect(&legacy).is_err() {
        let _ = fs::remove_file(legacy);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_limit_rejects_excess_and_releases_capacity() {
        let limiter = ConnectionLimiter::new(2);
        let first = limiter.try_acquire().expect("first connection");
        let second = limiter.try_acquire().expect("second connection");
        assert!(limiter.try_acquire().is_none());

        drop(first);
        assert!(limiter.try_acquire().is_some());
        drop(second);
    }
}
