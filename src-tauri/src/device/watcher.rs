// SPDX-License-Identifier: MPL-2.0

use crate::{
    device::detect,
    state::{ActivityCategory, ActivityStatus, KeyBackend, Phase, RuntimeState},
};
use std::{sync::Arc, thread, time::Duration};
use tauri::{AppHandle, Emitter, Manager};

pub fn start(app: AppHandle) {
    thread::spawn(move || loop {
        let managed = app.state::<Arc<RuntimeState>>();
        let initial_scan = !managed
            .device_scan_completed
            .swap(true, std::sync::atomic::Ordering::AcqRel);
        let previous_devices = managed
            .app
            .lock()
            .expect("state lock poisoned")
            .devices
            .clone();
        let detected = {
            let _device_access = managed.fido.lock().expect("FIDO lock poisoned");
            detect::yubikeys(&previous_devices)
        };
        let mut state = managed.app.lock().expect("state lock poisoned");
        let previous_path = state.device.as_ref().map(|d| d.path.clone());
        let was_waiting_for_pin = state.phase == Phase::NeedsPin;

        let changed = match detected {
            Ok(mut devices) => {
                if let Err(error) = crate::settings::apply_device_labels(&app, &mut devices) {
                    eprintln!("Could not restore security key names: {error}");
                }
                let connected_paths = devices
                    .iter()
                    .map(|device| device.path.clone())
                    .collect::<Vec<_>>();
                state
                    .unlocked_device_paths
                    .retain(|path| connected_paths.contains(path));
                if let Ok(mut pins) = managed.pins.lock() {
                    pins.retain(|path, _| connected_paths.contains(path));
                }
                state.keys.retain(|key| {
                    key.backend != KeyBackend::Fido2
                        || key
                            .device_path
                            .as_ref()
                            .is_some_and(|path| connected_paths.contains(path))
                });

                // Once a PIN window targets a device, keep that device stable.
                // Otherwise a background scan can switch to another locked
                // key and validate the entered PIN against the wrong YubiKey.
                let operation_in_progress = matches!(
                    state.phase,
                    Phase::NeedsPin | Phase::Loading | Phase::WaitingForTouch
                ) || state.pending_key_creation.is_some()
                    || state.pending_key_deletion.is_some()
                    || state.pending_key_rename.is_some();
                let current_is_connected = previous_path
                    .as_ref()
                    .is_some_and(|path| connected_paths.contains(path));
                let newly_connected_fido = devices
                    .iter()
                    .find(|device| {
                        device.fido2 && !previous_devices.iter().any(|old| old.path == device.path)
                    })
                    .cloned();
                let has_new_fido_device = newly_connected_fido.is_some();
                let next_locked = devices
                    .iter()
                    .find(|device| {
                        device.fido2 && !state.unlocked_device_paths.contains(&device.path)
                    })
                    .cloned();
                let active = if operation_in_progress && current_is_connected {
                    previous_path
                        .as_ref()
                        .and_then(|path| devices.iter().find(|device| &device.path == path))
                        .cloned()
                } else {
                    newly_connected_fido
                        .clone()
                        .or_else(|| {
                            previous_path
                                .as_ref()
                                .and_then(|path| devices.iter().find(|device| &device.path == path))
                                .cloned()
                        })
                        .or_else(|| next_locked.clone())
                        .or_else(|| devices.iter().find(|device| device.fido2).cloned())
                };
                let active_changed =
                    previous_path != active.as_ref().map(|device| device.path.clone());
                let changed = state.devices != devices || active_changed;
                state.devices = devices;
                state.device = active;
                state.yubikey_connected = !state.devices.is_empty();
                state.fido_session_unlocked = !state.devices.is_empty()
                    && state
                        .devices
                        .iter()
                        .filter(|device| device.fido2)
                        .all(|device| state.unlocked_device_paths.contains(&device.path));
                if !operation_in_progress {
                    state.phase = if has_new_fido_device {
                        Phase::NeedsPin
                    } else if state.yubikey_connected || !state.keys.is_empty() {
                        Phase::Ready
                    } else {
                        Phase::WaitingForDevice
                    };
                    state.error = None;
                }
                changed
            }
            Err(error) => {
                // A connected authenticator can be temporarily busy in the
                // external OpenSSH agent. Preserve Ready/NeedsPin state and
                // retry instead of falsely declaring CTAP2 unsupported.
                if state.yubikey_connected {
                    drop(state);
                    thread::sleep(Duration::from_millis(900));
                    continue;
                }
                let changed = state.error.as_deref() != Some(&error);
                state.error = Some(error);
                state.phase = Phase::Error;
                changed
            }
        };
        if changed {
            let auto_prompt = state.phase == Phase::NeedsPin
                && !was_waiting_for_pin
                && managed
                    .lifecycle_flags
                    .load(std::sync::atomic::Ordering::Acquire)
                    == 0
                && if initial_scan {
                    managed
                        .prompt_pin_on_startup
                        .load(std::sync::atomic::Ordering::Acquire)
                } else {
                    state.devices.iter().any(|device| {
                        device.fido2 && !previous_devices.iter().any(|old| old.path == device.path)
                    }) && managed
                        .prompt_pin_on_device_connection
                        .load(std::sync::atomic::Ordering::Acquire)
                };
            if auto_prompt {
                state.unlock_sequence = true;
            } else if state.phase == Phase::NeedsPin && !was_waiting_for_pin {
                // A connected-but-locked device is normal. Do not show a
                // permanent "Waiting for PIN" state unless a PIN interaction
                // was actually requested.
                state.phase = Phase::Ready;
            }
            let snapshot = state.clone();
            crate::update_tray(&app, &snapshot);
            let _ = app.emit("state-changed", snapshot);
            let connected = state
                .devices
                .iter()
                .filter(|device| !previous_devices.iter().any(|old| old.path == device.path))
                .cloned()
                .collect::<Vec<_>>();
            let disconnected = previous_devices
                .iter()
                .filter(|device| !state.devices.iter().any(|new| new.path == device.path))
                .cloned()
                .collect::<Vec<_>>();
            if let Some(device) = connected.first().filter(|device| device.fido2) {
                crate::activity::record(
                    &app,
                    managed.inner(),
                    ActivityCategory::Device,
                    ActivityStatus::Success,
                    "Security key connected",
                    device.label.clone().or_else(|| device.product.clone()),
                );
            } else if let Some(device) = connected.first() {
                crate::activity::record(
                    &app,
                    managed.inner(),
                    ActivityCategory::Device,
                    ActivityStatus::Error,
                    "Unsupported security key",
                    device.label.clone().or_else(|| device.product.clone()),
                );
            } else if let Some(device) = disconnected.first() {
                crate::activity::record(
                    &app,
                    managed.inner(),
                    ActivityCategory::Device,
                    ActivityStatus::Info,
                    "Security key disconnected",
                    device.label.clone().or_else(|| device.product.clone()),
                );
            } else if state.error.is_some() {
                crate::activity::record(
                    &app,
                    managed.inner(),
                    ActivityCategory::Device,
                    ActivityStatus::Error,
                    "Security key detection failed",
                    state.error.clone(),
                );
            }
            if auto_prompt {
                crate::show_auth(&app);
            }
        }
        drop(state);
        thread::sleep(Duration::from_millis(900));
    });
}
