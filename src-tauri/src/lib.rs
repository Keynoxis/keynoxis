// SPDX-License-Identifier: MPL-2.0

mod activity;
mod agent;
mod device;
mod fido;
mod ipc;
mod key_preferences;
mod lifecycle;
mod provider;
mod secure_enclave;
mod settings;
mod ssh;
mod state;
mod windowing;

use state::{ActivityCategory, ActivityStatus, AppState, Phase, RuntimeState};
use std::sync::Arc;
use tauri::{
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Emitter, Manager, WindowEvent,
};

pub struct TrayStatus {
    overall: MenuItem<tauri::Wry>,
    device: MenuItem<tauri::Wry>,
    agent: MenuItem<tauri::Wry>,
    keys: MenuItem<tauri::Wry>,
    lock: MenuItem<tauri::Wry>,
}

pub fn update_tray(app: &tauri::AppHandle, state: &AppState) {
    if let Some(status) = app.try_state::<TrayStatus>() {
        let _ = status.overall.set_text(format!(
            "Keynoxis — {}",
            match state.phase {
                Phase::Ready => "Ready",
                Phase::WaitingForTouch => "Touch Required",
                Phase::NeedsPin => "PIN Required",
                Phase::Error => "Attention Required",
                _ => "Active",
            }
        ));
        let _ = status.device.set_text(if state.devices.len() > 1 {
            format!("● {} Security Keys — Connected", state.devices.len())
        } else if state.yubikey_connected {
            format!(
                "● {} — Connected",
                state
                    .device
                    .as_ref()
                    .and_then(|device| device.label.as_deref().or(device.product.as_deref()))
                    .unwrap_or("FIDO2 Security Key")
            )
        } else {
            "○ No Security Key".into()
        });
        let _ = status.agent.set_text(if state.agent_locked {
            "○ SSH Agent Locked"
        } else if state.agent_running {
            "● SSH Agent Running"
        } else {
            "○ SSH Agent Not Running"
        });
        let _ = status.lock.set_text(if state.agent_locked {
            "Unlock SSH Agent"
        } else {
            "Lock SSH Agent"
        });
        let names = state
            .keys
            .iter()
            .filter(|key| !state.agent_locked && key.enabled)
            .filter_map(|key| key.comment.as_deref())
            .take(3)
            .collect::<Vec<_>>()
            .join(", ");
        let _ = status.keys.set_text(if names.is_empty() {
            format!(
                "{} identities",
                if state.agent_locked {
                    0
                } else {
                    state.keys.iter().filter(|key| key.enabled).count()
                }
            )
        } else {
            format!(
                "{} identities · {names}",
                state.keys.iter().filter(|key| key.enabled).count()
            )
        });
    }
}

pub(crate) fn show_main(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

pub(crate) fn show_auth(app: &tauri::AppHandle) {
    windowing::show_auth(app);
}

pub(crate) fn hide_auth(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("auth") {
        let _ = window.hide();
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);

            let shared = Arc::new(RuntimeState::default());
            app.manage(shared.clone());
            if let Err(error) = activity::initialize(app.handle(), &shared) {
                eprintln!("Could not restore activity log: {error}");
            }
            let (settings, security_settings_error) = match settings::load(app.handle()) {
                Ok(settings) => (settings, None),
                Err(error) => {
                    eprintln!("Secure settings recovery activated: {error}");
                    (settings::Settings::default(), Some(error))
                }
            };
            settings::apply(&shared, &settings);
            if let Some(error) = security_settings_error.as_ref() {
                if let Ok(mut state) = shared.app.lock() {
                    state.security_notice = Some(format!(
                        "Secure settings could not be loaded. Keynoxis applied fail-safe defaults: {error}"
                    ));
                }
            }

            match secure_enclave::list(app.handle()) {
                Ok(mut keys) => {
                    let _ = key_preferences::apply(app.handle(), &mut keys);
                    let mut state = shared.app.lock().expect("state lock poisoned");
                    state.keys.extend(keys);
                    if !state.keys.is_empty() {
                        state.phase = Phase::Ready;
                    }
                }
                Err(error) => eprintln!("Could not load Secure Enclave keys: {error}"),
            }

            // Own the SSH socket from application start, just like Secretive.
            // Keys appear on this stable agent as soon as the user unlocks the
            // connected authenticator.
            let native_agent = agent::start::ensure(app.handle(), shared.clone())?;
            {
                let mut state = shared.app.lock().expect("state lock poisoned");
                state.agent_running = true;
                state.ssh_socket = Some(native_agent.socket.clone());
            }
            *shared.agent.lock().expect("agent lock poisoned") = Some(native_agent);
            activity::record(
                app.handle(),
                &shared,
                ActivityCategory::Agent,
                ActivityStatus::Success,
                "SSH agent started",
                Some("Ready for OpenSSH-compatible clients".into()),
            );
            if let Some(error) = security_settings_error {
                activity::record(
                    app.handle(),
                    &shared,
                    ActivityCategory::Agent,
                    ActivityStatus::Error,
                    "Secure settings recovery activated",
                    Some(error),
                );
            }

            let overall = MenuItem::with_id(
                app,
                "overall_status",
                "Keynoxis — Active",
                false,
                None::<&str>,
            )?;
            let section_agent =
                MenuItem::with_id(app, "agent_section", "SSH AGENT", false, None::<&str>)?;
            let device = MenuItem::with_id(
                app,
                "device_status",
                "○ Waiting for YubiKey",
                false,
                None::<&str>,
            )?;
            let agent = MenuItem::with_id(
                app,
                "agent_status",
                "○ SSH Agent Not Running",
                false,
                None::<&str>,
            )?;
            let keys =
                MenuItem::with_id(app, "keys_status", "0 SSH Keys Loaded", false, None::<&str>)?;
            let separator_top = PredefinedMenuItem::separator(app)?;
            let separator_actions = PredefinedMenuItem::separator(app)?;
            let open = MenuItem::with_id(app, "open", "Open Keynoxis", true, None::<&str>)?;
            let reload = MenuItem::with_id(app, "reload", "Reload Keys", true, None::<&str>)?;
            let lock = MenuItem::with_id(app, "lock", "Lock Security Key Session", true, None::<&str>)?;
            let settings = MenuItem::with_id(app, "settings", "Settings…", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit Keynoxis", true, None::<&str>)?;
            let menu = Menu::with_items(
                app,
                &[
                    &overall,
                    &separator_top,
                    &section_agent,
                    &agent,
                    &keys,
                    &device,
                    &separator_actions,
                    &open,
                    &reload,
                    &lock,
                    &settings,
                    &quit,
                ],
            )?;
            app.manage(TrayStatus {
                overall,
                device,
                agent,
                keys,
                lock,
            });
            if let Ok(state) = shared.app.lock() {
                update_tray(app.handle(), &state);
            }

            TrayIconBuilder::with_id("main-tray")
                .icon(tauri::image::Image::from_bytes(include_bytes!(
                    "../icons/tray-icon-template.png"
                ))?)
                .icon_as_template(true)
                .tooltip("Keynoxis")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "open" => show_main(app),
                    "reload" => {
                        let runtime = app.state::<Arc<RuntimeState>>();
                        let mut state = runtime.app.lock().expect("state lock poisoned");
                        if state.yubikey_connected {
                            state.phase = Phase::NeedsPin;
                            state.error = None;
                            let snapshot = state.clone();
                            drop(state);
                            update_tray(app, &snapshot);
                            let _ = app.emit("state-changed", snapshot);
                            show_auth(app);
                        }
                    }
                    "lock" => {
                        let runtime = app.state::<Arc<RuntimeState>>();
                        let locked = runtime
                            .app
                            .lock()
                            .map(|state| state.agent_locked)
                            .unwrap_or(false);
                        let _ = settings::set_agent_locked(app, runtime.inner(), !locked);
                    }
                    "settings" => {
                        show_main(app);
                        let _ = app.emit("navigate", "settings");
                    }
                    "quit" => app.exit(0),
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        show_main(tray.app_handle());
                    }
                })
                .build(app)?;

            if let Some(window) = app.get_webview_window("main") {
                let window_to_hide = window.clone();
                window.on_window_event(move |event| {
                    if let WindowEvent::CloseRequested { api, .. } = event {
                        api.prevent_close();
                        let _ = window_to_hide.hide();
                    }
                });
            }
            if let Some(window) = app.get_webview_window("auth") {
                let window_to_hide = window.clone();
                window.on_window_event(move |event| {
                    if let WindowEvent::CloseRequested { api, .. } = event {
                        api.prevent_close();
                        let _ = window_to_hide.hide();
                    }
                });
            }

            device::watcher::start(app.handle().clone());
            settings::start_auto_lock_watcher(app.handle().clone(), shared);
            lifecycle::start(
                app.handle().clone(),
                app.state::<Arc<RuntimeState>>().inner().clone(),
            );
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            ipc::commands::get_state,
            ipc::commands::set_key_enabled,
            ipc::commands::request_unlock,
            ipc::commands::request_device_unlock,
            ipc::commands::set_security_key_label,
            ipc::commands::dismiss_auth,
            ipc::commands::load_keys,
            ipc::commands::continue_fido_operation,
            ipc::commands::rename_key,
            ipc::commands::create_secure_enclave_key,
            ipc::commands::request_fido_key_creation,
            ipc::commands::request_fido_key_deletion,
            ipc::commands::get_activity,
            ipc::commands::clear_activity,
            ipc::commands::get_settings,
            ipc::commands::set_launch_at_login,
            ipc::commands::set_auto_lock_timeout,
            ipc::commands::lock_agent,
            ipc::commands::unlock_agent,
            ipc::commands::set_preferred_backend,
            ipc::commands::set_pin_settings,
            ipc::commands::set_touch_id_settings,
            ipc::commands::delete_key
        ])
        .build(tauri::generate_context!())
        .expect("error while building Keynoxis")
        .run(|app, event| {
            if matches!(event, tauri::RunEvent::Exit) {
                let state = app.state::<Arc<RuntimeState>>();
                if let Ok(mut pins) = state.pins.lock() {
                    pins.clear();
                }
                if let Ok(mut agent) = state.agent.lock() {
                    *agent = None;
                };
            }
        });
}
