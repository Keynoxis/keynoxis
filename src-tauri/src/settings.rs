// SPDX-License-Identifier: MPL-2.0

use crate::{
    state::{ActivityCategory, ActivityStatus, AppState, KeyBackend, Phase, RuntimeState},
    update_tray,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{atomic::Ordering, Arc},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tauri::{AppHandle, Emitter, Manager};

const SETTINGS_FILE: &str = "settings.json";
const DEVICE_LABELS_FILE: &str = "device-labels.json";
const DEFAULT_AUTO_LOCK_MINUTES: u64 = 15;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub launch_at_login: bool,
    pub launch_at_login_requires_approval: bool,
    pub auto_lock_minutes: u64,
    pub preferred_backend: PreferredBackend,
    pub pin: PinSettings,
    pub touch_id: TouchIdSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PinSettings {
    pub prompt_on_startup: bool,
    pub prompt_on_device_connection: bool,
    pub prompt_after_mac_unlock: bool,
    pub require_for_create: bool,
    pub require_for_rename: bool,
    pub require_for_delete: bool,
}

impl Default for PinSettings {
    fn default() -> Self {
        Self {
            prompt_on_startup: false,
            prompt_on_device_connection: true,
            prompt_after_mac_unlock: true,
            require_for_create: true,
            require_for_rename: true,
            require_for_delete: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TouchIdSettings {
    pub require_for_create: bool,
    pub require_for_rename: bool,
}

impl Default for TouchIdSettings {
    fn default() -> Self {
        Self {
            require_for_create: true,
            require_for_rename: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
struct SecurityPolicy {
    auto_lock_minutes: u64,
    pin: PinSettings,
    touch_id: TouchIdSettings,
    device_labels: BTreeMap<String, String>,
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self {
            auto_lock_minutes: DEFAULT_AUTO_LOCK_MINUTES,
            pin: PinSettings::default(),
            touch_id: TouchIdSettings::default(),
            device_labels: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreferredBackend {
    SecureEnclave,
    Fido2,
}

#[derive(Clone, Copy)]
pub enum LockReason {
    Manual,
    Inactivity,
    ScreenLocked,
    Sleep,
    SessionInactive,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            launch_at_login: false,
            launch_at_login_requires_approval: false,
            auto_lock_minutes: DEFAULT_AUTO_LOCK_MINUTES,
            preferred_backend: PreferredBackend::SecureEnclave,
            pin: PinSettings::default(),
            touch_id: TouchIdSettings::default(),
        }
    }
}

pub fn load(app: &AppHandle) -> Result<Settings, String> {
    let mut settings = read(&settings_path(app)?)?;
    match platform::read_security_policy() {
        Ok(Some(data)) => {
            match serde_json::from_slice::<SecurityPolicy>(&data) {
                Ok(policy) => {
                    settings.auto_lock_minutes = policy.auto_lock_minutes;
                    settings.pin = policy.pin;
                    settings.touch_id = policy.touch_id;
                }
                Err(error) => {
                    eprintln!("Keychain security policy is invalid; using the protected local copy: {error}");
                }
            }
        }
        Ok(None) => {
            if let Err(error) = write_security_policy(&settings) {
                eprintln!("Could not initialize Keychain security policy: {error}");
            }
        }
        Err(error) => {
            // Ad-hoc development signatures change on every build and macOS
            // can revoke their access to an existing Keychain item. Preserve
            // the chmod-0600 local copy instead of silently resetting values.
            eprintln!(
                "Could not read Keychain security policy; using the protected local copy: {error}"
            );
        }
    }
    let status = platform::autostart_status();
    settings.launch_at_login = status == 1;
    settings.launch_at_login_requires_approval = status == 2;
    save_public(app, &settings)?;
    Ok(settings)
}

pub fn save(app: &AppHandle, settings: &Settings) -> Result<(), String> {
    save_public(app, settings)?;
    if let Err(error) = write_security_policy(settings) {
        eprintln!("Could not mirror settings to Keychain: {error}");
    }
    Ok(())
}

fn write_security_policy(settings: &Settings) -> Result<(), String> {
    let mut policy = read_security_policy()?.unwrap_or_default();
    policy.auto_lock_minutes = settings.auto_lock_minutes;
    policy.pin = settings.pin.clone();
    policy.touch_id = settings.touch_id.clone();
    write_security_policy_value(&policy)
}

fn read_security_policy() -> Result<Option<SecurityPolicy>, String> {
    platform::read_security_policy()?
        .map(|data| {
            serde_json::from_slice(&data)
                .map_err(|error| format!("Keychain security policy is invalid: {error}"))
        })
        .transpose()
}

fn write_security_policy_value(policy: &SecurityPolicy) -> Result<(), String> {
    let data = serde_json::to_vec(policy)
        .map_err(|error| format!("Could not encode security policy: {error}"))?;
    platform::write_security_policy(&data)
}

pub fn apply_device_labels(
    app: &AppHandle,
    devices: &mut [crate::state::DeviceInfo],
) -> Result<(), String> {
    let mut labels = read_device_labels(app)?;
    if let Ok(Some(policy)) = read_security_policy() {
        labels.extend(policy.device_labels);
    }
    for device in devices {
        device.label = labels
            .get(&device_identity(device))
            .or_else(|| labels.get(&fallback_device_identity(device)))
            .cloned();
    }
    Ok(())
}

pub fn set_device_label(
    app: &AppHandle,
    device: &crate::state::DeviceInfo,
    label: Option<&str>,
) -> Result<(), String> {
    let mut labels = read_device_labels(app)?;
    let identity = device_identity(device);
    match label.map(str::trim).filter(|label| !label.is_empty()) {
        Some(label) => {
            if label.len() > 64 || label.chars().any(char::is_control) {
                return Err(
                    "Device name must be 64 characters or fewer and contain no control characters"
                        .into(),
                );
            }
            labels.insert(identity.clone(), label.to_owned());
        }
        None => {
            labels.remove(&identity);
        }
    }
    write_device_labels(app, &labels)?;
    if let Ok(mut policy) = read_security_policy().map(|policy| policy.unwrap_or_default()) {
        policy.device_labels = labels;
        if let Err(error) = write_security_policy_value(&policy) {
            eprintln!("Could not mirror security key names to Keychain: {error}");
        }
    }
    Ok(())
}

fn device_identity(device: &crate::state::DeviceInfo) -> String {
    if let Some(serial) = device.serial_number {
        return format!("serial:{serial}");
    }
    fallback_device_identity(device)
}

fn fallback_device_identity(device: &crate::state::DeviceInfo) -> String {
    let mut digest = Sha256::new();
    digest.update(device.vendor_id.to_be_bytes());
    digest.update(device.product_id.to_be_bytes());
    digest.update(device.aaguid.as_deref().unwrap_or_default().as_bytes());
    if let Some(local_id) = device.local_id {
        digest.update(local_id.to_be_bytes());
    } else {
        digest.update(device.path.as_bytes());
    }
    format!("fallback:{:x}", digest.finalize())
}

fn save_public(app: &AppHandle, settings: &Settings) -> Result<(), String> {
    let path = settings_path(app)?;
    let parent = path.parent().ok_or("Invalid Keynoxis data directory")?;
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("Could not create Keynoxis data directory: {error}"))?;
    let data = serde_json::to_vec_pretty(settings)
        .map_err(|error| format!("Could not encode settings: {error}"))?;
    let temporary = path.with_extension("json.tmp");
    std::fs::write(&temporary, data)
        .map_err(|error| format!("Could not save settings: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("Could not secure settings file: {error}"))?;
    }
    std::fs::rename(&temporary, path).map_err(|error| format!("Could not commit settings: {error}"))
}

fn device_labels_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(app
        .path()
        .app_data_dir()
        .map_err(|error| format!("Could not locate Keynoxis data directory: {error}"))?
        .join(DEVICE_LABELS_FILE))
}

fn read_device_labels(app: &AppHandle) -> Result<BTreeMap<String, String>, String> {
    match std::fs::read(device_labels_path(app)?) {
        Ok(data) => serde_json::from_slice(&data)
            .map_err(|error| format!("Security key names are invalid: {error}")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
        Err(error) => Err(format!("Could not read security key names: {error}")),
    }
}

fn write_device_labels(app: &AppHandle, labels: &BTreeMap<String, String>) -> Result<(), String> {
    let path = device_labels_path(app)?;
    let parent = path.parent().ok_or("Invalid Keynoxis data directory")?;
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("Could not create Keynoxis data directory: {error}"))?;
    let temporary = path.with_extension("json.tmp");
    let data = serde_json::to_vec_pretty(labels)
        .map_err(|error| format!("Could not encode security key names: {error}"))?;
    std::fs::write(&temporary, data)
        .map_err(|error| format!("Could not save security key names: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("Could not secure security key names: {error}"))?;
    }
    std::fs::rename(&temporary, path)
        .map_err(|error| format!("Could not commit security key names: {error}"))
}

pub fn set_autostart(app: &AppHandle, enabled: bool) -> Result<Settings, String> {
    platform::set_autostart(enabled)?;
    let settings = load(app)?;
    save(app, &settings)?;
    Ok(settings)
}

pub fn set_auto_lock(
    app: &AppHandle,
    runtime: &Arc<RuntimeState>,
    minutes: u64,
) -> Result<Settings, String> {
    if ![0, 5, 15, 30, 60].contains(&minutes) {
        return Err("Unsupported automatic lock timeout".into());
    }
    let mut settings = load(app)?;
    if auto_lock_settings_weakened(settings.auto_lock_minutes, minutes) {
        authorize_security_settings_change(app)?;
    }
    settings.auto_lock_minutes = minutes;
    save(app, &settings)?;
    runtime.auto_lock_minutes.store(minutes, Ordering::Release);
    mark_fido_activity(runtime);
    Ok(settings)
}

pub fn set_preferred_backend(
    app: &AppHandle,
    runtime: &Arc<RuntimeState>,
    preferred_backend: PreferredBackend,
) -> Result<Settings, String> {
    let mut settings = load(app)?;
    settings.preferred_backend = preferred_backend;
    save(app, &settings)?;
    runtime.preferred_backend.store(
        match preferred_backend {
            PreferredBackend::SecureEnclave => 0,
            PreferredBackend::Fido2 => 1,
        },
        Ordering::Release,
    );
    Ok(settings)
}

pub fn set_pin_settings(
    app: &AppHandle,
    runtime: &Arc<RuntimeState>,
    pin: PinSettings,
) -> Result<Settings, String> {
    let mut settings = load(app)?;
    if pin_settings_weakened(&settings.pin, &pin) {
        authorize_security_settings_change(app)?;
    }
    settings.pin = pin;
    save(app, &settings)?;
    apply_pin_settings(runtime, &settings.pin);
    Ok(settings)
}

pub fn set_touch_id_settings(
    app: &AppHandle,
    runtime: &Arc<RuntimeState>,
    touch_id: TouchIdSettings,
) -> Result<Settings, String> {
    let mut settings = load(app)?;
    if touch_id_settings_weakened(&settings.touch_id, &touch_id) {
        authorize_security_settings_change(app)?;
    }
    settings.touch_id = touch_id;
    save(app, &settings)?;
    apply_touch_id_settings(runtime, &settings.touch_id);
    Ok(settings)
}

fn pin_settings_weakened(current: &PinSettings, next: &PinSettings) -> bool {
    (current.prompt_on_startup && !next.prompt_on_startup)
        || (current.prompt_on_device_connection && !next.prompt_on_device_connection)
        || (current.prompt_after_mac_unlock && !next.prompt_after_mac_unlock)
        || (current.require_for_create && !next.require_for_create)
        || (current.require_for_rename && !next.require_for_rename)
        || (current.require_for_delete && !next.require_for_delete)
}

fn touch_id_settings_weakened(current: &TouchIdSettings, next: &TouchIdSettings) -> bool {
    (current.require_for_create && !next.require_for_create)
        || (current.require_for_rename && !next.require_for_rename)
}

fn auto_lock_settings_weakened(current_minutes: u64, next_minutes: u64) -> bool {
    next_minutes == 0 || (current_minutes != 0 && next_minutes > current_minutes)
}

fn authorize_security_settings_change(app: &AppHandle) -> Result<(), String> {
    let authorization = platform::authorize_security_settings_change();
    // LocalAuthentication temporarily makes its system sheet key. Restore the
    // settings window whether authentication succeeded or was cancelled.
    crate::show_main(app);
    authorization
}

pub fn apply(runtime: &RuntimeState, settings: &Settings) {
    runtime
        .auto_lock_minutes
        .store(settings.auto_lock_minutes, Ordering::Release);
    runtime
        .last_fido_activity_ms
        .store(now_ms(), Ordering::Release);
    runtime.preferred_backend.store(
        match settings.preferred_backend {
            PreferredBackend::SecureEnclave => 0,
            PreferredBackend::Fido2 => 1,
        },
        Ordering::Release,
    );
    apply_pin_settings(runtime, &settings.pin);
    apply_touch_id_settings(runtime, &settings.touch_id);
}

fn apply_touch_id_settings(runtime: &RuntimeState, touch_id: &TouchIdSettings) {
    runtime
        .require_touch_id_for_create
        .store(touch_id.require_for_create, Ordering::Release);
    runtime
        .require_touch_id_for_rename
        .store(touch_id.require_for_rename, Ordering::Release);
}

fn apply_pin_settings(runtime: &RuntimeState, pin: &PinSettings) {
    runtime
        .prompt_pin_on_startup
        .store(pin.prompt_on_startup, Ordering::Release);
    runtime
        .prompt_pin_on_device_connection
        .store(pin.prompt_on_device_connection, Ordering::Release);
    runtime
        .prompt_pin_after_mac_unlock
        .store(pin.prompt_after_mac_unlock, Ordering::Release);
    runtime
        .require_pin_for_create
        .store(pin.require_for_create, Ordering::Release);
    runtime
        .require_pin_for_rename
        .store(pin.require_for_rename, Ordering::Release);
    runtime
        .require_pin_for_delete
        .store(pin.require_for_delete, Ordering::Release);
}

pub fn mark_fido_activity(runtime: &RuntimeState) {
    runtime
        .last_fido_activity_ms
        .store(now_ms(), Ordering::Release);
}

pub fn lock_fido_session(
    app: &AppHandle,
    runtime: &Arc<RuntimeState>,
    reason: LockReason,
) -> Result<bool, String> {
    let was_unlocked = {
        let mut pins = runtime.pins.lock().map_err(|_| "PIN lock failed")?;
        let was_unlocked = !pins.is_empty();
        pins.clear();
        was_unlocked
    };
    let (snapshot, had_fido_keys) = {
        let mut state = runtime.app.lock().map_err(|_| "State lock failed")?;
        let had_fido_keys = state
            .keys
            .iter()
            .any(|key| key.backend == KeyBackend::Fido2);
        state.fido_session_unlocked = false;
        state.unlocked_device_paths.clear();
        state.unlock_sequence = false;
        state.keys.retain(|key| key.backend != KeyBackend::Fido2);
        let protected_session = was_unlocked || had_fido_keys;
        if protected_session {
            if let Some(notice) = system_lock_notice(&reason) {
                state.security_notice = Some(notice.into());
            }
        }
        if state.yubikey_connected {
            state.phase = Phase::NeedsPin;
        }
        (state.clone(), had_fido_keys)
    };
    if !was_unlocked && !had_fido_keys {
        return Ok(false);
    }
    update_tray(app, &snapshot);
    let _ = app.emit("state-changed", snapshot);
    crate::activity::record(
        app,
        runtime,
        ActivityCategory::Agent,
        if matches!(
            reason,
            LockReason::ScreenLocked | LockReason::Sleep | LockReason::SessionInactive
        ) {
            ActivityStatus::Warning
        } else {
            ActivityStatus::Info
        },
        match reason {
            LockReason::Manual => "FIDO2 session locked",
            LockReason::Inactivity => "FIDO2 session locked automatically",
            LockReason::ScreenLocked => "FIDO2 session locked with macOS",
            LockReason::Sleep => "FIDO2 session locked before sleep",
            LockReason::SessionInactive => "FIDO2 session locked for inactive user session",
        },
        system_lock_notice(&reason).map(str::to_owned),
    );
    Ok(true)
}

pub fn set_agent_locked(
    app: &AppHandle,
    runtime: &Arc<RuntimeState>,
    locked: bool,
) -> Result<AppState, String> {
    let _signing = runtime
        .signing_gate
        .lock()
        .map_err(|_| "Signing gate failed")?;
    if locked {
        let _ = lock_fido_session(app, runtime, LockReason::Manual)?;
    }
    let snapshot = {
        let mut state = runtime.app.lock().map_err(|_| "State lock failed")?;
        if state.agent_locked == locked {
            return Ok(state.clone());
        }
        state.agent_locked = locked;
        state.clone()
    };
    crate::update_tray(app, &snapshot);
    let _ = app.emit("state-changed", snapshot.clone());
    crate::activity::record(
        app,
        runtime,
        ActivityCategory::Agent,
        ActivityStatus::Info,
        if locked {
            "SSH agent locked"
        } else {
            "SSH agent unlocked"
        },
        Some(if locked {
            "All identities are unavailable to SSH clients".into()
        } else {
            "Enabled identities are available to SSH clients".into()
        }),
    );
    Ok(snapshot)
}

fn system_lock_notice(reason: &LockReason) -> Option<&'static str> {
    match reason {
        LockReason::ScreenLocked => Some("FIDO2 identities were locked because this Mac was locked. Unlock the security key to restore them."),
        LockReason::Sleep => Some("FIDO2 identities were locked before this Mac went to sleep. Unlock the security key to restore them."),
        LockReason::SessionInactive => Some("FIDO2 identities were locked because the macOS user session became inactive. Unlock the security key to restore them."),
        LockReason::Manual | LockReason::Inactivity => None,
    }
}

pub fn start_auto_lock_watcher(app: AppHandle, runtime: Arc<RuntimeState>) {
    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(15));
        let minutes = runtime.auto_lock_minutes.load(Ordering::Acquire);
        if minutes == 0 {
            continue;
        }
        let last_activity = runtime.last_fido_activity_ms.load(Ordering::Acquire);
        if last_activity > 0 && now_ms().saturating_sub(last_activity) >= minutes * 60_000 {
            let _ = lock_fido_session(&app, &runtime, LockReason::Inactivity);
        }
    });
}

fn settings_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(app
        .path()
        .app_data_dir()
        .map_err(|error| format!("Could not locate Keynoxis data directory: {error}"))?
        .join(SETTINGS_FILE))
}

fn read(path: &Path) -> Result<Settings, String> {
    match std::fs::read(path) {
        Ok(data) => serde_json::from_slice(&data)
            .map_err(|error| format!("Keynoxis settings are invalid: {error}")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Settings::default()),
        Err(error) => Err(format!("Could not read Keynoxis settings: {error}")),
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fail_safe_policy_enables_every_operation_check() {
        let policy = SecurityPolicy::default();
        assert!(!policy.pin.prompt_on_startup);
        assert!(policy.pin.prompt_on_device_connection);
        assert!(policy.pin.prompt_after_mac_unlock);
        assert!(policy.pin.require_for_create);
        assert!(policy.pin.require_for_rename);
        assert!(policy.pin.require_for_delete);
        assert!(policy.touch_id.require_for_create);
        assert!(policy.touch_id.require_for_rename);
    }

    #[test]
    fn only_disabling_pin_protection_is_a_downgrade() {
        let secure = PinSettings::default();
        let mut weaker = secure.clone();
        weaker.require_for_delete = false;
        assert!(pin_settings_weakened(&secure, &weaker));

        let mut initially_disabled = secure.clone();
        initially_disabled.require_for_rename = false;
        assert!(!pin_settings_weakened(&initially_disabled, &secure));
    }

    #[test]
    fn only_disabling_touch_id_protection_is_a_downgrade() {
        let secure = TouchIdSettings::default();
        let mut weaker = secure.clone();
        weaker.require_for_rename = false;
        assert!(touch_id_settings_weakened(&secure, &weaker));

        let mut initially_disabled = secure.clone();
        initially_disabled.require_for_create = false;
        assert!(!touch_id_settings_weakened(&initially_disabled, &secure));
    }

    #[test]
    fn only_longer_or_disabled_auto_lock_is_a_downgrade() {
        assert!(auto_lock_settings_weakened(5, 15));
        assert!(auto_lock_settings_weakened(15, 0));
        assert!(!auto_lock_settings_weakened(15, 5));
        assert!(!auto_lock_settings_weakened(0, 15));
    }

    fn device(path: &str, serial_number: Option<u32>) -> crate::state::DeviceInfo {
        crate::state::DeviceInfo {
            label: None,
            serial_number,
            local_id: None,
            product: Some("YubiKey".into()),
            manufacturer: Some("Yubico".into()),
            path: path.into(),
            vendor_id: 0x1050,
            product_id: 0x0407,
            fido2: true,
            credential_management: true,
            pin_configured: true,
            algorithms: Vec::new(),
            aaguid: Some("test-aaguid".into()),
            firmware: None,
            resident_credentials_remaining: None,
            pin_retries: None,
        }
    }

    #[test]
    fn device_names_follow_serial_across_usb_paths() {
        assert_eq!(
            device_identity(&device("path-a", Some(34924370))),
            device_identity(&device("path-b", Some(34924370)))
        );
    }

    #[test]
    fn fallback_device_names_are_scoped_to_the_usb_identity() {
        assert_ne!(
            device_identity(&device("path-a", None)),
            device_identity(&device("path-b", None))
        );
    }

    #[test]
    fn local_device_names_survive_ioreg_path_changes() {
        let mut first = device("ioreg://1", None);
        first.local_id = Some(0x1420_0000);
        let mut reconnected = device("ioreg://99", None);
        reconnected.local_id = Some(0x1420_0000);
        assert_eq!(device_identity(&first), device_identity(&reconnected));
    }

    #[test]
    fn legacy_settings_default_to_no_startup_pin_prompt() {
        let settings: Settings = serde_json::from_slice(
            br#"{"launch_at_login":false,"preferred_backend":"secure_enclave"}"#,
        )
        .unwrap();
        assert!(!settings.pin.prompt_on_startup);
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use std::{ffi::c_void, ptr, slice};

    #[link(name = "KeynoxisSecureEnclave")]
    extern "C" {
        fn keynoxis_autostart_status() -> i32;
        fn keynoxis_autostart_set(enabled: bool, error: *mut *mut u8, error_len: *mut usize)
            -> i32;
        fn keynoxis_se_free(pointer: *mut c_void);
        fn keynoxis_security_policy_read(
            output: *mut *mut u8,
            output_len: *mut usize,
            error: *mut *mut u8,
            error_len: *mut usize,
        ) -> i32;
        fn keynoxis_security_policy_write(
            bytes: *const u8,
            len: usize,
            error: *mut *mut u8,
            error_len: *mut usize,
        ) -> i32;
        fn keynoxis_authorize_security_settings_change(
            error: *mut *mut u8,
            error_len: *mut usize,
        ) -> i32;
    }

    pub fn autostart_status() -> i32 {
        unsafe { keynoxis_autostart_status() }
    }

    pub fn set_autostart(enabled: bool) -> Result<(), String> {
        let mut error = ptr::null_mut();
        let mut error_len = 0;
        let status = unsafe { keynoxis_autostart_set(enabled, &mut error, &mut error_len) };
        if status == 0 {
            return Ok(());
        }
        let message = if error.is_null() {
            "macOS could not update the login item".into()
        } else {
            let value = unsafe { slice::from_raw_parts(error, error_len).to_vec() };
            unsafe { keynoxis_se_free(error.cast()) };
            String::from_utf8(value).unwrap_or_else(|_| "macOS rejected the login item".into())
        };
        Err(message)
    }

    pub fn read_security_policy() -> Result<Option<Vec<u8>>, String> {
        let mut output = ptr::null_mut();
        let mut output_len = 0;
        let mut error = ptr::null_mut();
        let mut error_len = 0;
        let status = unsafe {
            keynoxis_security_policy_read(&mut output, &mut output_len, &mut error, &mut error_len)
        };
        match status {
            0 => Ok(Some(take_buffer(output, output_len))),
            2 => Ok(None),
            _ => Err(take_error(
                error,
                error_len,
                "Could not read Keychain security policy",
            )),
        }
    }

    pub fn write_security_policy(data: &[u8]) -> Result<(), String> {
        let mut error = ptr::null_mut();
        let mut error_len = 0;
        let status = unsafe {
            keynoxis_security_policy_write(data.as_ptr(), data.len(), &mut error, &mut error_len)
        };
        if status == 0 {
            Ok(())
        } else {
            Err(take_error(
                error,
                error_len,
                "Could not save Keychain security policy",
            ))
        }
    }

    pub fn authorize_security_settings_change() -> Result<(), String> {
        let mut error = ptr::null_mut();
        let mut error_len = 0;
        let status =
            unsafe { keynoxis_authorize_security_settings_change(&mut error, &mut error_len) };
        if status == 0 {
            Ok(())
        } else {
            Err(take_error(
                error,
                error_len,
                "Touch ID authorization failed",
            ))
        }
    }

    fn take_buffer(pointer: *mut u8, length: usize) -> Vec<u8> {
        if pointer.is_null() {
            return Vec::new();
        }
        let result = unsafe { slice::from_raw_parts(pointer, length).to_vec() };
        unsafe { keynoxis_se_free(pointer.cast()) };
        result
    }

    fn take_error(pointer: *mut u8, length: usize, fallback: &str) -> String {
        String::from_utf8(take_buffer(pointer, length)).unwrap_or_else(|_| fallback.into())
    }
}

#[cfg(not(target_os = "macos"))]
mod platform {
    pub fn autostart_status() -> i32 {
        0
    }
    pub fn set_autostart(_enabled: bool) -> Result<(), String> {
        Err("Launch at login is implemented only on macOS".into())
    }
    pub fn read_security_policy() -> Result<Option<Vec<u8>>, String> {
        Ok(None)
    }
    pub fn write_security_policy(_data: &[u8]) -> Result<(), String> {
        Err("Secure settings storage is implemented only on macOS".into())
    }
    pub fn authorize_security_settings_change() -> Result<(), String> {
        Err("Touch ID is available only on macOS".into())
    }
}
