// SPDX-License-Identifier: MPL-2.0

use crate::{
    agent,
    settings::{self, LockReason},
    state::{ActivityCategory, ActivityStatus, Phase, RuntimeState},
};
use std::sync::{atomic::Ordering, mpsc, Arc, OnceLock};
use tauri::{AppHandle, Emitter};

const SCREEN_LOCKED: u64 = 1 << 0;
const SLEEPING: u64 = 1 << 1;
const SESSION_INACTIVE: u64 = 1 << 2;

#[cfg(target_os = "macos")]
static EVENTS: OnceLock<mpsc::Sender<i32>> = OnceLock::new();

#[cfg(target_os = "macos")]
#[link(name = "KeynoxisSecureEnclave")]
extern "C" {
    fn keynoxis_lifecycle_start(callback: Option<extern "C" fn(i32)>);
}

#[cfg(target_os = "macos")]
pub fn start(app: AppHandle, runtime: Arc<RuntimeState>) {
    let (sender, receiver) = mpsc::channel();
    let _ = EVENTS.set(sender);
    std::thread::spawn(move || {
        while let Ok(event) = receiver.recv() {
            handle_event(app.clone(), runtime.clone(), event);
        }
    });
    unsafe { keynoxis_lifecycle_start(Some(lifecycle_callback)) };
}

#[cfg(not(target_os = "macos"))]
pub fn start(_app: AppHandle, _runtime: Arc<RuntimeState>) {}

#[cfg(target_os = "macos")]
extern "C" fn lifecycle_callback(event: i32) {
    if let Some(events) = EVENTS.get() {
        let _ = events.send(event);
    }
}

#[cfg(target_os = "macos")]
fn handle_event(app: AppHandle, runtime: Arc<RuntimeState>, event: i32) {
    match event {
        1 => deactivate(&app, &runtime, SCREEN_LOCKED, LockReason::ScreenLocked),
        2 => reactivate(&app, &runtime, SCREEN_LOCKED, "Screen unlocked"),
        3 => deactivate(&app, &runtime, SLEEPING, LockReason::Sleep),
        4 => reactivate(&app, &runtime, SLEEPING, "Mac woke from sleep"),
        5 => deactivate(
            &app,
            &runtime,
            SESSION_INACTIVE,
            LockReason::SessionInactive,
        ),
        6 => reactivate(
            &app,
            &runtime,
            SESSION_INACTIVE,
            "User session became active",
        ),
        _ => {}
    }
}

#[cfg(target_os = "macos")]
fn deactivate(app: &AppHandle, runtime: &Arc<RuntimeState>, flag: u64, reason: LockReason) {
    let previous = runtime.lifecycle_flags.fetch_or(flag, Ordering::AcqRel);
    if previous & flag != 0 || previous != 0 {
        return;
    }

    runtime
        .auth_dismiss_generation
        .fetch_add(1, Ordering::AcqRel);
    if let Ok(mut state) = runtime.app.lock() {
        state.pending_key_creation = None;
        state.pending_key_algorithm = None;
        state.pending_key_deletion = None;
        state.pending_key_rename = None;
        state.error = None;
    }
    crate::hide_auth(app);

    match settings::lock_fido_session(app, runtime, reason) {
        Ok(locked) => {
            if !locked {
                crate::activity::record(
                    app,
                    runtime,
                    ActivityCategory::Agent,
                    ActivityStatus::Info,
                    "macOS security state changed",
                    Some("No unlocked FIDO2 session was present".into()),
                );
            }
        }
        Err(error) => {
            if let Ok(mut state) = runtime.app.lock() {
                state.security_notice = Some(format!(
                    "Keynoxis could not completely lock the FIDO2 session: {error}"
                ));
                let snapshot = state.clone();
                drop(state);
                crate::update_tray(app, &snapshot);
                let _ = app.emit("state-changed", snapshot);
            }
            crate::activity::record(
                app,
                runtime,
                ActivityCategory::Agent,
                ActivityStatus::Error,
                "System lock protection failed",
                Some(error),
            );
        }
    }
}

#[cfg(target_os = "macos")]
fn reactivate(app: &AppHandle, runtime: &Arc<RuntimeState>, flag: u64, event_name: &str) {
    let previous = runtime.lifecycle_flags.fetch_and(!flag, Ordering::AcqRel);
    if previous & flag == 0 || previous & !flag != 0 {
        return;
    }

    let recovery = (|| {
        let mut running_agent = runtime.agent.lock().map_err(|_| "Agent lock failed")?;
        let healthy = running_agent
            .as_ref()
            .is_some_and(agent::start::Agent::is_healthy);
        if !healthy {
            *running_agent = None;
            *running_agent = Some(agent::start::ensure(app, runtime.clone())?);
        }
        running_agent
            .as_ref()
            .map(|agent| agent.socket.clone())
            .ok_or_else(|| "SSH Agent did not recover".to_owned())
    })();

    match recovery {
        Ok(socket) => {
            let snapshot = {
                let mut state = match runtime.app.lock() {
                    Ok(state) => state,
                    Err(_) => return,
                };
                state.agent_running = true;
                state.ssh_socket = Some(socket);
                state.error = None;
                if state.yubikey_connected && !state.fido_session_unlocked {
                    state.device = state.devices.iter().find(|device| device.fido2).cloned();
                    state.phase = Phase::NeedsPin;
                    if runtime.prompt_pin_after_mac_unlock.load(Ordering::Acquire) {
                        state.unlock_sequence = true;
                    }
                } else if !state.keys.is_empty() {
                    state.phase = Phase::Ready;
                }
                state.clone()
            };
            crate::update_tray(app, &snapshot);
            let _ = app.emit("state-changed", snapshot.clone());
            crate::activity::record(
                app,
                runtime,
                ActivityCategory::Agent,
                ActivityStatus::Success,
                "SSH Agent recovered",
                Some(format!("{event_name} · Agent socket verified")),
            );
            if snapshot.yubikey_connected
                && runtime.prompt_pin_after_mac_unlock.load(Ordering::Acquire)
            {
                crate::show_auth(app);
            }
        }
        Err(error) => {
            if let Ok(mut state) = runtime.app.lock() {
                state.agent_running = false;
                state.phase = Phase::Error;
                state.error = Some(error.clone());
                state.security_notice =
                    Some("Keynoxis could not restore its SSH Agent after macOS resumed.".into());
                let snapshot = state.clone();
                drop(state);
                crate::update_tray(app, &snapshot);
                let _ = app.emit("state-changed", snapshot);
            }
            crate::activity::record(
                app,
                runtime,
                ActivityCategory::Agent,
                ActivityStatus::Error,
                "SSH Agent recovery failed",
                Some(error),
            );
            crate::show_main(app);
        }
    }
}
