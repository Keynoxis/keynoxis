// SPDX-License-Identifier: MPL-2.0

use crate::{
    agent, fido, secure_enclave,
    state::{
        ActivityCategory, ActivityEntry, ActivityStatus, AppState, KeyBackend, PendingKeyRename,
        Phase, RuntimeState,
    },
};
use std::sync::{atomic::Ordering, Arc};
use tauri::{AppHandle, Emitter, State};

#[tauri::command]
pub fn get_state(state: State<'_, Arc<RuntimeState>>) -> AppState {
    state.app.lock().expect("state lock poisoned").clone()
}

#[tauri::command]
pub fn set_key_enabled(
    app: AppHandle,
    state: State<'_, Arc<RuntimeState>>,
    fingerprint: String,
    enabled: bool,
) -> Result<AppState, String> {
    let _signing = state
        .signing_gate
        .lock()
        .map_err(|_| "Signing gate failed")?;
    crate::key_preferences::set_enabled(&app, &fingerprint, enabled)?;
    let snapshot = {
        let mut current = state.app.lock().map_err(|_| "State lock failed")?;
        let key = current
            .keys
            .iter_mut()
            .find(|key| key.fingerprint == fingerprint)
            .ok_or("SSH identity was not found")?;
        key.enabled = enabled;
        current.clone()
    };
    crate::update_tray(&app, &snapshot);
    let _ = app.emit("state-changed", snapshot.clone());
    crate::activity::record(
        &app,
        state.inner(),
        ActivityCategory::Key,
        ActivityStatus::Info,
        if enabled {
            "SSH identity enabled"
        } else {
            "SSH identity disabled"
        },
        snapshot
            .keys
            .iter()
            .find(|key| key.fingerprint == fingerprint)
            .and_then(|key| key.comment.clone()),
    );
    Ok(snapshot)
}

#[tauri::command]
pub fn get_activity(state: State<'_, Arc<RuntimeState>>) -> Result<Vec<ActivityEntry>, String> {
    crate::activity::list(state.inner())
}

#[tauri::command]
pub fn clear_activity(
    app: AppHandle,
    state: State<'_, Arc<RuntimeState>>,
) -> Result<Vec<ActivityEntry>, String> {
    crate::activity::clear(&app, state.inner())?;
    Ok(Vec::new())
}

#[tauri::command]
pub fn get_settings(app: AppHandle) -> Result<crate::settings::Settings, String> {
    crate::settings::load(&app)
}

#[tauri::command]
pub fn set_launch_at_login(
    app: AppHandle,
    enabled: bool,
) -> Result<crate::settings::Settings, String> {
    crate::settings::set_autostart(&app, enabled)
}

#[tauri::command]
pub fn set_auto_lock_timeout(
    app: AppHandle,
    state: State<'_, Arc<RuntimeState>>,
    minutes: u64,
) -> Result<crate::settings::Settings, String> {
    crate::settings::set_auto_lock(&app, state.inner(), minutes)
}

#[tauri::command]
pub fn set_preferred_backend(
    app: AppHandle,
    state: State<'_, Arc<RuntimeState>>,
    preferred_backend: crate::settings::PreferredBackend,
) -> Result<crate::settings::Settings, String> {
    crate::settings::set_preferred_backend(&app, state.inner(), preferred_backend)
}

#[tauri::command]
pub fn set_pin_settings(
    app: AppHandle,
    state: State<'_, Arc<RuntimeState>>,
    pin_settings: crate::settings::PinSettings,
) -> Result<crate::settings::Settings, String> {
    crate::settings::set_pin_settings(&app, state.inner(), pin_settings)
}

#[tauri::command]
pub fn set_touch_id_settings(
    app: AppHandle,
    state: State<'_, Arc<RuntimeState>>,
    touch_id_settings: crate::settings::TouchIdSettings,
) -> Result<crate::settings::Settings, String> {
    crate::settings::set_touch_id_settings(&app, state.inner(), touch_id_settings)
}

#[tauri::command]
pub fn lock_agent(app: AppHandle, state: State<'_, Arc<RuntimeState>>) -> Result<AppState, String> {
    crate::settings::set_agent_locked(&app, state.inner(), true)
}

#[tauri::command]
pub fn unlock_agent(
    app: AppHandle,
    state: State<'_, Arc<RuntimeState>>,
) -> Result<AppState, String> {
    crate::settings::set_agent_locked(&app, state.inner(), false)
}

#[tauri::command]
pub fn request_unlock(
    app: AppHandle,
    state: State<'_, Arc<RuntimeState>>,
) -> Result<AppState, String> {
    let mut current = state.app.lock().map_err(|_| "State lock failed")?;
    if !current.yubikey_connected {
        return Err("No FIDO2 security key is connected".into());
    }
    let all_unlocked = current
        .devices
        .iter()
        .filter(|device| device.fido2)
        .all(|device| current.unlocked_device_paths.contains(&device.path));
    if all_unlocked {
        current.unlocked_device_paths.clear();
        current.keys.retain(|key| key.backend != KeyBackend::Fido2);
        state.pins.lock().map_err(|_| "PIN lock failed")?.clear();
    }
    let target = current
        .devices
        .iter()
        .find(|device| device.fido2 && !current.unlocked_device_paths.contains(&device.path))
        .cloned()
        .ok_or("No locked FIDO2 security key is connected")?;
    current.device = Some(target);
    current.unlock_sequence = true;
    current.phase = Phase::NeedsPin;
    current.error = None;
    current.pending_key_creation = None;
    current.pending_key_algorithm = None;
    current.pending_key_deletion = None;
    current.pending_key_rename = None;
    current.fido_session_unlocked = false;
    let snapshot = current.clone();
    drop(current);
    crate::update_tray(&app, &snapshot);
    let _ = app.emit("state-changed", snapshot.clone());
    crate::show_auth(&app);
    Ok(snapshot)
}

#[tauri::command]
pub fn request_device_unlock(
    app: AppHandle,
    state: State<'_, Arc<RuntimeState>>,
    path: String,
) -> Result<AppState, String> {
    let mut current = state.app.lock().map_err(|_| "State lock failed")?;
    let target = current
        .devices
        .iter()
        .find(|device| device.path == path && device.fido2)
        .cloned()
        .ok_or("The selected FIDO2 security key is no longer connected")?;

    // Reload only this device. Other unlocked devices and their identities
    // remain available to the SSH agent.
    current.keys.retain(|key| {
        key.backend != KeyBackend::Fido2 || key.device_path.as_deref() != Some(path.as_str())
    });
    current
        .unlocked_device_paths
        .retain(|unlocked| unlocked != &path);
    state
        .pins
        .lock()
        .map_err(|_| "PIN lock failed")?
        .remove(&path);
    current.device = Some(target);
    current.unlock_sequence = false;
    current.fido_session_unlocked = false;
    current.phase = Phase::NeedsPin;
    current.error = None;
    current.pending_key_creation = None;
    current.pending_key_algorithm = None;
    current.pending_key_deletion = None;
    current.pending_key_rename = None;
    let snapshot = current.clone();
    drop(current);
    crate::update_tray(&app, &snapshot);
    let _ = app.emit("state-changed", snapshot.clone());
    crate::show_auth(&app);
    Ok(snapshot)
}

#[tauri::command]
pub fn set_security_key_label(
    app: AppHandle,
    state: State<'_, Arc<RuntimeState>>,
    path: String,
    label: String,
) -> Result<AppState, String> {
    let mut current = state.app.lock().map_err(|_| "State lock failed")?;
    let device = current
        .devices
        .iter()
        .find(|device| device.path == path)
        .cloned()
        .ok_or("The security key is no longer connected")?;
    let normalized = label.trim();
    crate::settings::set_device_label(
        &app,
        &device,
        if normalized.is_empty() {
            None
        } else {
            Some(normalized)
        },
    )?;
    for item in &mut current.devices {
        if item.path == path {
            item.label = (!normalized.is_empty()).then(|| normalized.to_owned());
        }
    }
    if let Some(active) = current.device.as_mut().filter(|device| device.path == path) {
        active.label = (!normalized.is_empty()).then(|| normalized.to_owned());
    }
    let snapshot = current.clone();
    drop(current);
    crate::update_tray(&app, &snapshot);
    let _ = app.emit("state-changed", snapshot.clone());
    crate::activity::record(
        &app,
        state.inner(),
        ActivityCategory::Device,
        ActivityStatus::Info,
        if normalized.is_empty() {
            "Security key name reset"
        } else {
            "Security key renamed"
        },
        Some(if normalized.is_empty() {
            device
                .product
                .unwrap_or_else(|| "FIDO2 security key".into())
        } else {
            normalized.to_owned()
        }),
    );
    Ok(snapshot)
}

#[tauri::command]
pub fn dismiss_auth(
    app: AppHandle,
    state: State<'_, Arc<RuntimeState>>,
) -> Result<AppState, String> {
    let mut current = state.app.lock().map_err(|_| "State lock failed")?;
    if current.phase == Phase::WaitingForTouch {
        state.auth_dismiss_generation.fetch_add(1, Ordering::AcqRel);
    }
    let was_creating = current.pending_key_creation.is_some();
    let was_deleting = current.pending_key_deletion.is_some();
    let was_renaming = current.pending_key_rename.is_some();
    let was_pin_prompt = current.phase == Phase::NeedsPin;
    current.pending_key_creation = None;
    current.pending_key_algorithm = None;
    current.pending_key_deletion = None;
    current.pending_key_rename = None;
    current.unlock_sequence = false;
    if was_deleting || was_renaming {
        if let Some(path) = current.device.as_ref().map(|device| device.path.clone()) {
            current.keys.retain(|key| {
                key.backend != KeyBackend::Fido2 || key.device_path.as_deref() != Some(&path)
            });
            current
                .unlocked_device_paths
                .retain(|unlocked| unlocked != &path);
            if let Ok(mut pins) = state.pins.lock() {
                pins.remove(&path);
            }
        }
        current.fido_session_unlocked = false;
    }
    if current.phase == Phase::Error
        || was_pin_prompt
        || was_creating
        || was_deleting
        || was_renaming
    {
        current.phase = if !current.keys.is_empty() {
            Phase::Ready
        } else if current.yubikey_connected {
            Phase::Ready
        } else {
            Phase::WaitingForDevice
        };
        current.error = None;
    }
    let snapshot = current.clone();
    drop(current);
    crate::update_tray(&app, &snapshot);
    let _ = app.emit("state-changed", snapshot.clone());
    crate::hide_auth(&app);
    Ok(snapshot)
}

#[tauri::command]
pub async fn load_keys(
    app: AppHandle,
    state: State<'_, Arc<RuntimeState>>,
    pin: String,
) -> Result<AppState, String> {
    fido::pin::validate(&pin)?;
    perform_fido_operation(
        app,
        state.inner().clone(),
        fido::pin::SecretString::new(pin),
    )
    .await
}

#[tauri::command]
pub async fn continue_fido_operation(
    app: AppHandle,
    state: State<'_, Arc<RuntimeState>>,
) -> Result<AppState, String> {
    let device_path = state
        .app
        .lock()
        .map_err(|_| "State lock failed")?
        .device
        .as_ref()
        .map(|device| device.path.clone())
        .ok_or("YubiKey was removed")?;
    let pin = state
        .pins
        .lock()
        .map_err(|_| "PIN lock failed")?
        .get(&device_path)
        .map(|pin| fido::pin::SecretString::new(pin.expose().to_owned()))
        .ok_or("The FIDO2 session is locked")?;
    perform_fido_operation(app, state.inner().clone(), pin).await
}

async fn perform_fido_operation(
    app: AppHandle,
    runtime: Arc<RuntimeState>,
    pin: fido::pin::SecretString,
) -> Result<AppState, String> {
    let (
        device_path,
        pending_key_creation,
        pending_key_algorithm,
        pending_key_deletion,
        pending_key_rename,
    ) = {
        let mut current = runtime.app.lock().map_err(|_| "State lock failed")?;
        let path = current
            .device
            .as_ref()
            .map(|d| d.path.clone())
            .ok_or("YubiKey was removed")?;
        let pending = current.pending_key_creation.clone();
        let algorithm = current
            .pending_key_algorithm
            .clone()
            .unwrap_or_else(|| fido::credentials::ED25519_SK.into());
        let deleting = match current.pending_key_deletion.as_deref() {
            Some(fingerprint) => Some(
                current
                    .keys
                    .iter()
                    .find(|key| key.fingerprint == fingerprint && key.backend == KeyBackend::Fido2)
                    .cloned()
                    .ok_or("The FIDO2 SSH key selected for deletion was not found")?,
            ),
            None => None,
        };
        let renaming = match current.pending_key_rename.as_ref() {
            Some(rename) => Some((
                current
                    .keys
                    .iter()
                    .find(|key| {
                        key.fingerprint == rename.fingerprint && key.backend == KeyBackend::Fido2
                    })
                    .cloned()
                    .ok_or("The FIDO2 SSH key selected for rename was not found")?,
                rename.name.clone(),
            )),
            None => None,
        };
        current.phase = if pending.is_some() || deleting.is_some() {
            Phase::WaitingForTouch
        } else {
            Phase::Loading
        };
        current.error = None;
        crate::update_tray(&app, &current);
        let _ = app.emit("state-changed", current.clone());
        if pending.is_some() || deleting.is_some() {
            crate::show_auth(&app);
        }
        (path, pending, algorithm, deleting, renaming)
    };
    let created_key_name = pending_key_creation.clone();
    let deleted_key_name = pending_key_deletion
        .as_ref()
        .and_then(|key| key.comment.clone())
        .unwrap_or_else(|| "Unnamed SSH identity".into());
    let deleting_key = pending_key_deletion.is_some();
    let renamed_key_name = pending_key_rename.as_ref().map(|(_, name)| name.clone());
    let renaming_key = pending_key_rename.is_some();
    let normal_unlock = pending_key_creation.is_none()
        && pending_key_deletion.is_none()
        && pending_key_rename.is_none();
    let operation_device_path = device_path.clone();

    // libfido2 waits synchronously for user presence. Keep that wait away from
    // Tauri's IPC handler so the auth window can render the touch prompt.
    let fido_runtime = runtime.clone();
    let (keys, returned_pin) = tauri::async_runtime::spawn_blocking(move || {
        let keys = (|| {
            let _device_access = fido_runtime.fido.lock().map_err(|_| "FIDO lock failed")?;
            if let Some(name) = pending_key_creation.as_deref() {
                fido::create::resident(&device_path, name, pin.expose(), &pending_key_algorithm)?;
            }
            if let Some(key) = pending_key_deletion.as_ref() {
                fido::sign::sign(
                    &device_path,
                    key,
                    b"Keynoxis resident credential deletion confirmation",
                    pin.expose(),
                )?;
                fido::delete::credential(&device_path, key, pin.expose())?;
            }
            if let Some((key, name)) = pending_key_rename.as_ref() {
                fido::rename::credential(&device_path, key, name, pin.expose())?;
            }
            fido::resident::load(&device_path, pin.expose())
        })();
        (keys, pin)
    })
    .await
    .map_err(|error| format!("FIDO operation task failed: {error}"))?;
    let pin = returned_pin;

    let outcome = (|| {
        let mut keys = keys?;
        crate::key_preferences::apply(&app, &mut keys)?;
        let mut agent_guard = runtime.agent.lock().map_err(|_| "Agent lock failed")?;
        if agent_guard.is_none() {
            *agent_guard = Some(agent::start::ensure(&app, runtime.clone())?);
        }
        let socket = agent_guard
            .as_ref()
            .map(|agent| agent.socket.clone())
            .ok_or("Keynoxis did not start")?;
        Ok::<_, String>((keys, socket))
    })();

    let mut current = runtime.app.lock().map_err(|_| "State lock failed")?;
    match outcome {
        Ok((keys, socket)) => {
            runtime.pins.lock().map_err(|_| "PIN lock failed")?.insert(
                operation_device_path.clone(),
                crate::state::SecretPin::new(pin.expose()),
            );
            current.keys.retain(|key| {
                key.backend != KeyBackend::Fido2
                    || key.device_path.as_deref() != Some(operation_device_path.as_str())
            });
            current.keys.extend(keys);
            if !current
                .unlocked_device_paths
                .contains(&operation_device_path)
            {
                current
                    .unlocked_device_paths
                    .push(operation_device_path.clone());
            }
            current.agent_running = true;
            current.ssh_socket = Some(socket);
            let next_locked = (normal_unlock && current.unlock_sequence)
                .then(|| {
                    current
                        .devices
                        .iter()
                        .find(|device| {
                            device.fido2 && !current.unlocked_device_paths.contains(&device.path)
                        })
                        .cloned()
                })
                .flatten();
            current.device = next_locked.clone().or_else(|| {
                current
                    .devices
                    .iter()
                    .find(|device| device.path == operation_device_path)
                    .cloned()
            });
            current.phase = if next_locked.is_some() {
                Phase::NeedsPin
            } else {
                Phase::Ready
            };
            if next_locked.is_none() {
                current.unlock_sequence = false;
            }
            current.error = None;
            current.pending_key_creation = None;
            current.pending_key_algorithm = None;
            current.pending_key_deletion = None;
            current.pending_key_rename = None;
            current.fido_session_unlocked = current
                .devices
                .iter()
                .filter(|device| device.fido2)
                .all(|device| current.unlocked_device_paths.contains(&device.path));
            current.security_notice = None;
            crate::settings::mark_fido_activity(&runtime);
            let loaded_count = current
                .keys
                .iter()
                .filter(|key| {
                    key.backend == KeyBackend::Fido2
                        && key.device_path.as_deref() == Some(operation_device_path.as_str())
                })
                .count();
            if renaming_key {
                crate::activity::record(
                    &app,
                    &runtime,
                    ActivityCategory::Key,
                    ActivityStatus::Success,
                    "SSH identity renamed",
                    renamed_key_name.clone(),
                );
            } else if deleting_key {
                crate::activity::record(
                    &app,
                    &runtime,
                    ActivityCategory::Key,
                    ActivityStatus::Success,
                    "SSH identity deleted",
                    Some(format!("{deleted_key_name} · FIDO2")),
                );
            } else if let Some(name) = created_key_name.as_deref() {
                crate::activity::record(
                    &app,
                    &runtime,
                    ActivityCategory::Key,
                    ActivityStatus::Success,
                    "Security key created",
                    Some(format!("{name} · FIDO2")),
                );
            } else {
                crate::activity::record(
                    &app,
                    &runtime,
                    ActivityCategory::Key,
                    ActivityStatus::Success,
                    "Security key unlocked",
                    Some(format!("{loaded_count} resident identities loaded")),
                );
            }
        }
        Err(error) => {
            current.phase = if error == "Invalid PIN" {
                Phase::NeedsPin
            } else {
                Phase::Error
            };
            current.error = Some(error.clone());
            current
                .unlocked_device_paths
                .retain(|path| path != &operation_device_path);
            current.fido_session_unlocked = false;
            if let Ok(mut pins) = runtime.pins.lock() {
                pins.remove(&operation_device_path);
            }
            if error != "Invalid PIN" {
                current.pending_key_creation = None;
                current.pending_key_algorithm = None;
                if !renaming_key {
                    current.pending_key_rename = None;
                }
                if !deleting_key {
                    current.pending_key_deletion = None;
                }
            }
            let snapshot = current.clone();
            crate::update_tray(&app, &snapshot);
            let _ = app.emit("state-changed", snapshot);
            crate::activity::record(
                &app,
                &runtime,
                ActivityCategory::Key,
                ActivityStatus::Error,
                if renaming_key {
                    "SSH identity rename failed"
                } else if deleting_key {
                    "SSH identity deletion failed"
                } else if created_key_name.is_some() {
                    "Security key creation failed"
                } else {
                    "Security key unlock failed"
                },
                Some(error.clone()),
            );
            return Err(error);
        }
    }
    // `SecretString` wipes the command argument on every exit path. Keep only
    // the guarded `SecretPin` cache entry while the YubiKey session is active.
    drop(pin);
    let snapshot = current.clone();
    crate::update_tray(&app, &snapshot);
    let _ = app.emit("state-changed", snapshot.clone());
    if snapshot.phase == Phase::NeedsPin {
        crate::show_auth(&app);
    } else {
        crate::hide_auth(&app);
    }
    Ok(snapshot)
}

#[tauri::command]
pub fn request_fido_key_creation(
    app: AppHandle,
    state: State<'_, Arc<RuntimeState>>,
    name: String,
    algorithm: Option<String>,
    device_path: Option<String>,
) -> Result<AppState, String> {
    let name = name.trim();
    if name.is_empty() {
        return Err("Key name cannot be empty".into());
    }
    if name.len() > 64 {
        return Err("Key name must be 64 UTF-8 bytes or fewer".into());
    }
    if name.chars().any(char::is_control) {
        return Err("Key name cannot contain control characters".into());
    }

    let algorithm = algorithm.unwrap_or_else(|| fido::credentials::ED25519_SK.into());
    if !matches!(
        algorithm.as_str(),
        fido::credentials::ED25519_SK | fido::credentials::ECDSA_SK
    ) {
        return Err("Choose ED25519-SK or ECDSA-SK".into());
    }
    let mut current = state.app.lock().map_err(|_| "State lock failed")?;
    if !current.yubikey_connected {
        return Err("Connect a FIDO2 security key before creating the key".into());
    }
    let target = match device_path {
        Some(path) => current
            .devices
            .iter()
            .find(|device| device.path == path && device.fido2)
            .cloned(),
        None => current.device.clone().filter(|device| device.fido2),
    }
    .ok_or("The selected FIDO2 security key is no longer connected")?;
    current.device = Some(target.clone());
    let advertised_algorithm = if algorithm == fido::credentials::ECDSA_SK {
        "ECDSA-SK"
    } else {
        "ED25519-SK"
    };
    if current.device.as_ref().is_some_and(|device| {
        !device.algorithms.is_empty()
            && !device
                .algorithms
                .iter()
                .any(|item| item == advertised_algorithm)
    }) {
        return Err(format!(
            "The selected security key does not support {advertised_algorithm}"
        ));
    }
    if current.keys.iter().any(|key| {
        key.backend == KeyBackend::Fido2
            && key
                .comment
                .as_deref()
                .is_some_and(|comment| comment.eq_ignore_ascii_case(name))
    }) {
        return Err("A YubiKey SSH key with this name already exists".into());
    }
    current.pending_key_creation = Some(name.to_owned());
    current.pending_key_algorithm = Some(algorithm);
    current.pending_key_deletion = None;
    current.pending_key_rename = None;
    let reuse_session = !state.require_pin_for_create.load(Ordering::Acquire)
        && state
            .pins
            .lock()
            .map_err(|_| "PIN lock failed")?
            .contains_key(&target.path);
    current.phase = if reuse_session {
        Phase::WaitingForTouch
    } else {
        Phase::NeedsPin
    };
    current.error = None;
    if !reuse_session {
        current.fido_session_unlocked = false;
        current
            .unlocked_device_paths
            .retain(|path| path != &target.path);
        current.keys.retain(|key| {
            key.backend != KeyBackend::Fido2
                || key.device_path.as_deref() != Some(target.path.as_str())
        });
        state
            .pins
            .lock()
            .map_err(|_| "PIN lock failed")?
            .remove(&target.path);
    }
    let snapshot = current.clone();
    drop(current);
    crate::update_tray(&app, &snapshot);
    let _ = app.emit("state-changed", snapshot.clone());
    crate::show_auth(&app);
    Ok(snapshot)
}

#[tauri::command]
pub fn request_fido_key_deletion(
    app: AppHandle,
    state: State<'_, Arc<RuntimeState>>,
    fingerprint: String,
) -> Result<AppState, String> {
    let mut current = state.app.lock().map_err(|_| "State lock failed")?;
    if !current.yubikey_connected {
        return Err("Connect the FIDO2 security key before deleting the key".into());
    }
    let key = current
        .keys
        .iter()
        .find(|key| key.fingerprint == fingerprint && key.backend == KeyBackend::Fido2)
        .cloned()
        .ok_or("The FIDO2 SSH key was not found")?;
    let device_path = key
        .device_path
        .clone()
        .ok_or("The source security key is unknown")?;
    current.device = current
        .devices
        .iter()
        .find(|device| device.path == device_path)
        .cloned();
    if current.device.is_none() {
        return Err("Connect the security key that contains this SSH identity".into());
    }

    current.pending_key_creation = None;
    current.pending_key_algorithm = None;
    current.pending_key_deletion = Some(fingerprint);
    current.pending_key_rename = None;
    let reuse_session = !state.require_pin_for_delete.load(Ordering::Acquire)
        && state
            .pins
            .lock()
            .map_err(|_| "PIN lock failed")?
            .contains_key(&device_path);
    current.phase = if reuse_session {
        Phase::WaitingForTouch
    } else {
        Phase::NeedsPin
    };
    current.error = None;
    if !reuse_session {
        current.fido_session_unlocked = false;
        current
            .unlocked_device_paths
            .retain(|path| path != &device_path);
        state
            .pins
            .lock()
            .map_err(|_| "PIN lock failed")?
            .remove(&device_path);
    }
    let snapshot = current.clone();
    drop(current);
    crate::update_tray(&app, &snapshot);
    let _ = app.emit("state-changed", snapshot.clone());
    crate::show_auth(&app);
    Ok(snapshot)
}

#[tauri::command]
pub fn rename_key(
    app: AppHandle,
    state: State<'_, Arc<RuntimeState>>,
    fingerprint: String,
    name: String,
) -> Result<AppState, String> {
    let name = name.trim();
    if name.is_empty() {
        return Err("Key name cannot be empty".into());
    }
    if name.len() > 64 {
        return Err("Key name must be 64 UTF-8 bytes or fewer".into());
    }
    if name.chars().any(char::is_control) {
        return Err("Key name cannot contain control characters".into());
    }

    let key = {
        let current = state.app.lock().map_err(|_| "State lock failed")?;
        current
            .keys
            .iter()
            .find(|key| key.fingerprint == fingerprint)
            .cloned()
            .ok_or("SSH key was not found")?
    };

    if key.backend == KeyBackend::Fido2 {
        let device_path = key
            .device_path
            .clone()
            .ok_or("The source security key is unknown")?;
        let has_session = state
            .pins
            .lock()
            .map_err(|_| "PIN lock failed")?
            .contains_key(&device_path);
        if state.require_pin_for_rename.load(Ordering::Acquire) || !has_session {
            let mut current = state.app.lock().map_err(|_| "State lock failed")?;
            current.device = current
                .devices
                .iter()
                .find(|device| device.path == device_path)
                .cloned();
            if current.device.is_none() {
                return Err("Connect the security key that contains this SSH identity".into());
            }
            current.pending_key_creation = None;
            current.pending_key_algorithm = None;
            current.pending_key_deletion = None;
            current.pending_key_rename = Some(PendingKeyRename {
                fingerprint,
                name: name.to_owned(),
            });
            current.phase = Phase::NeedsPin;
            current.error = None;
            current.fido_session_unlocked = false;
            current
                .unlocked_device_paths
                .retain(|path| path != &device_path);
            state
                .pins
                .lock()
                .map_err(|_| "PIN lock failed")?
                .remove(&device_path);
            let snapshot = current.clone();
            drop(current);
            crate::update_tray(&app, &snapshot);
            let _ = app.emit("state-changed", snapshot.clone());
            crate::show_auth(&app);
            return Ok(snapshot);
        }
    }

    {
        let mut current = state.app.lock().map_err(|_| "State lock failed")?;
        current.phase = Phase::Loading;
        current.error = None;
        crate::update_tray(&app, &current);
        let _ = app.emit("state-changed", current.clone());
    }

    let outcome = match key.backend {
        KeyBackend::Fido2 => (|| {
            let device_path = key
                .device_path
                .as_deref()
                .ok_or("The source security key is unknown")?;
            let _device_access = state.fido.lock().map_err(|_| "FIDO lock failed")?;
            let pins = state.pins.lock().map_err(|_| "PIN lock failed")?;
            let pin = pins
                .get(device_path)
                .ok_or("Unlock the YubiKey before renaming a key")?;
            fido::rename::credential(device_path, &key, name, pin.expose())?;
            let mut updated = key.clone();
            updated.comment = Some(name.to_owned());
            fido::credentials::finish(updated)
        })(),
        KeyBackend::SecureEnclave => {
            let _access = state
                .secure_enclave
                .lock()
                .map_err(|_| "Secure Enclave lock failed")?;
            if state.require_touch_id_for_rename.load(Ordering::Acquire) {
                let authorization = secure_enclave::authorize_touch_id();
                crate::show_main(&app);
                authorization?;
            }
            secure_enclave::rename(&app, &key, name)
        }
        KeyBackend::Tpm => Err("TPM provider is not implemented yet".into()),
    };

    let mut current = state.app.lock().map_err(|_| "State lock failed")?;
    match outcome {
        Ok(updated) => {
            let existing = current
                .keys
                .iter_mut()
                .find(|existing| existing.fingerprint == fingerprint)
                .ok_or("Resident key disappeared while it was being renamed")?;
            *existing = updated;
            current.phase = Phase::Ready;
            current.error = None;
            if key.backend == KeyBackend::Fido2 {
                crate::settings::mark_fido_activity(state.inner());
            }
            crate::activity::record(
                &app,
                state.inner(),
                ActivityCategory::Key,
                ActivityStatus::Success,
                "SSH identity renamed",
                Some(name.to_owned()),
            );
        }
        Err(error) => {
            current.phase = Phase::Ready;
            current.error = Some(error.clone());
            let snapshot = current.clone();
            crate::update_tray(&app, &snapshot);
            let _ = app.emit("state-changed", snapshot);
            return Err(error);
        }
    }

    let snapshot = current.clone();
    crate::update_tray(&app, &snapshot);
    let _ = app.emit("state-changed", snapshot.clone());
    Ok(snapshot)
}

#[tauri::command]
pub async fn delete_key(
    app: AppHandle,
    state: State<'_, Arc<RuntimeState>>,
    fingerprint: String,
) -> Result<AppState, String> {
    let runtime = state.inner().clone();
    let key = {
        let current = runtime.app.lock().map_err(|_| "State lock failed")?;
        current
            .keys
            .iter()
            .find(|key| key.fingerprint == fingerprint)
            .cloned()
            .ok_or("SSH key was not found")?
    };
    if key.backend == KeyBackend::Fido2 {
        return Err("FIDO2 deletion requires fresh PIN and touch authorization".into());
    }
    let key_name = key
        .comment
        .clone()
        .unwrap_or_else(|| "Unnamed SSH identity".into());
    let key_backend = key.backend.clone();
    let operation_runtime = runtime.clone();
    let operation_app = app.clone();
    let deletion_task = tauri::async_runtime::spawn_blocking(move || match &key.backend {
        KeyBackend::Fido2 => {
            Err("FIDO2 deletion requires fresh PIN and touch authorization".into())
        }
        KeyBackend::SecureEnclave => {
            let _access = operation_runtime
                .secure_enclave
                .lock()
                .map_err(|_| "Secure Enclave lock failed")?;
            secure_enclave::delete(&operation_app, &key)
        }
        KeyBackend::Tpm => Err("TPM provider is not implemented yet".into()),
    })
    .await;

    // The macOS Touch ID sheet temporarily owns focus. Bring the Keynoxis
    // window back after biometric authorization succeeds or is cancelled.
    crate::show_main(&app);
    let result = deletion_task.map_err(|error| format!("Key deletion task failed: {error}"))?;

    if let Err(error) = result {
        crate::activity::record(
            &app,
            &runtime,
            ActivityCategory::Key,
            ActivityStatus::Error,
            "SSH identity deletion failed",
            Some(format!("{key_name} · {error}")),
        );
        return Err(error);
    }

    let snapshot = {
        let mut current = runtime.app.lock().map_err(|_| "State lock failed")?;
        current.keys.retain(|key| key.fingerprint != fingerprint);
        current.phase = Phase::Ready;
        current.error = None;
        current.clone()
    };
    crate::update_tray(&app, &snapshot);
    let _ = app.emit("state-changed", snapshot.clone());
    crate::activity::record(
        &app,
        &runtime,
        ActivityCategory::Key,
        ActivityStatus::Success,
        "SSH identity deleted",
        Some(format!(
            "{key_name} · {}",
            if key_backend == KeyBackend::Fido2 {
                "FIDO2"
            } else {
                "Secure Enclave"
            }
        )),
    );
    Ok(snapshot)
}

#[tauri::command]
pub fn create_secure_enclave_key(
    app: AppHandle,
    state: State<'_, Arc<RuntimeState>>,
    name: String,
) -> Result<AppState, String> {
    let name = name.trim();
    let key = {
        let _access = state
            .secure_enclave
            .lock()
            .map_err(|_| "Secure Enclave lock failed")?;
        if state.require_touch_id_for_create.load(Ordering::Acquire) {
            let authorization = secure_enclave::authorize_touch_id();
            crate::show_main(&app);
            authorization?;
        }
        secure_enclave::create(&app, name)?
    };

    let mut current = state.app.lock().map_err(|_| "State lock failed")?;
    current.keys.push(key);
    current.phase = Phase::Ready;
    current.error = None;
    let snapshot = current.clone();
    drop(current);
    crate::update_tray(&app, &snapshot);
    let _ = app.emit("state-changed", snapshot.clone());
    crate::activity::record(
        &app,
        state.inner(),
        ActivityCategory::Key,
        ActivityStatus::Success,
        "Secure Enclave key created",
        Some(format!("{name} · ECDSA P-256")),
    );
    Ok(snapshot)
}
