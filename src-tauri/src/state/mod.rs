// SPDX-License-Identifier: MPL-2.0

use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
    sync::{
        atomic::{AtomicBool, AtomicU64},
        Mutex,
    },
};
use zeroize::Zeroize;

pub struct SecretPin(Vec<u8>);

impl SecretPin {
    pub fn new(value: &str) -> Self {
        Self(value.as_bytes().to_vec())
    }

    pub fn expose(&self) -> &str {
        // Constructed exclusively from a Rust UTF-8 string.
        unsafe { std::str::from_utf8_unchecked(&self.0) }
    }
}

impl Drop for SecretPin {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    WaitingForDevice,
    NeedsPin,
    Loading,
    WaitingForTouch,
    Ready,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KeyBackend {
    Fido2,
    SecureEnclave,
    Tpm,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Fido2KeyHandle {
    pub application: String,
    pub credential_id: Vec<u8>,
    pub user_id: Vec<u8>,
    pub public_key_bytes: Vec<u8>,
    pub flags: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SecureEnclaveKeyHandle {
    pub encrypted_key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum KeyHandle {
    Fido2(Fido2KeyHandle),
    SecureEnclave(SecureEnclaveKeyHandle),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SshKey {
    pub algorithm: String,
    pub public_key: String,
    pub fingerprint: String,
    pub comment: Option<String>,
    pub backend: KeyBackend,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub device_path: Option<String>,
    #[serde(skip)]
    pub(crate) public_blob: Vec<u8>,
    #[serde(skip)]
    pub(crate) handle: Option<KeyHandle>,
}

fn default_enabled() -> bool {
    true
}

impl SshKey {
    pub(crate) fn fido2(&self) -> Result<&Fido2KeyHandle, String> {
        match self.handle.as_ref() {
            Some(KeyHandle::Fido2(handle)) => Ok(handle),
            _ => Err("Key is not backed by a FIDO2 credential".into()),
        }
    }

    pub(crate) fn secure_enclave(&self) -> Result<&SecureEnclaveKeyHandle, String> {
        match self.handle.as_ref() {
            Some(KeyHandle::SecureEnclave(handle)) => Ok(handle),
            _ => Err("Key is not backed by Secure Enclave".into()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceInfo {
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub serial_number: Option<u32>,
    #[serde(default)]
    pub local_id: Option<u32>,
    pub product: Option<String>,
    pub manufacturer: Option<String>,
    pub path: String,
    pub vendor_id: u16,
    pub product_id: u16,
    pub fido2: bool,
    #[serde(default)]
    pub credential_management: bool,
    #[serde(default)]
    pub pin_configured: bool,
    #[serde(default)]
    pub algorithms: Vec<String>,
    pub aaguid: Option<String>,
    pub firmware: Option<String>,
    pub resident_credentials_remaining: Option<i64>,
    pub pin_retries: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ActivityCategory {
    Agent,
    Device,
    Key,
    Signing,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ActivityStatus {
    Info,
    Success,
    Warning,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActivityEntry {
    pub id: u64,
    pub timestamp_ms: u64,
    pub category: ActivityCategory,
    pub status: ActivityStatus,
    pub title: String,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingKeyRename {
    pub fingerprint: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppState {
    pub phase: Phase,
    pub yubikey_connected: bool,
    pub agent_running: bool,
    #[serde(default)]
    pub agent_locked: bool,
    pub ssh_socket: Option<String>,
    pub keys: Vec<SshKey>,
    pub device: Option<DeviceInfo>,
    #[serde(default)]
    pub devices: Vec<DeviceInfo>,
    pub error: Option<String>,
    pub pending_key_creation: Option<String>,
    #[serde(default)]
    pub pending_key_algorithm: Option<String>,
    pub pending_key_deletion: Option<String>,
    pub pending_key_rename: Option<PendingKeyRename>,
    pub fido_session_unlocked: bool,
    #[serde(default)]
    pub unlocked_device_paths: Vec<String>,
    #[serde(default)]
    pub unlock_sequence: bool,
    pub security_notice: Option<String>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            phase: Phase::WaitingForDevice,
            yubikey_connected: false,
            agent_running: false,
            agent_locked: false,
            ssh_socket: None,
            keys: Vec::new(),
            device: None,
            devices: Vec::new(),
            error: None,
            pending_key_creation: None,
            pending_key_algorithm: None,
            pending_key_deletion: None,
            pending_key_rename: None,
            fido_session_unlocked: false,
            unlocked_device_paths: Vec::new(),
            unlock_sequence: false,
            security_notice: None,
        }
    }
}

pub struct RuntimeState {
    pub app: Mutex<AppState>,
    pub agent: Mutex<Option<crate::agent::start::Agent>>,
    /// Serializes signing authorization with lock and key-availability changes.
    pub signing_gate: Mutex<()>,
    pub pins: Mutex<HashMap<String, SecretPin>>,
    pub fido: Mutex<()>,
    pub secure_enclave: Mutex<()>,
    pub auth_dismiss_generation: AtomicU64,
    pub activity: Mutex<VecDeque<ActivityEntry>>,
    pub next_activity_id: AtomicU64,
    pub auto_lock_minutes: AtomicU64,
    pub last_fido_activity_ms: AtomicU64,
    pub preferred_backend: AtomicU64,
    pub lifecycle_flags: AtomicU64,
    pub device_scan_completed: AtomicBool,
    pub prompt_pin_on_startup: AtomicBool,
    pub prompt_pin_on_device_connection: AtomicBool,
    pub prompt_pin_after_mac_unlock: AtomicBool,
    pub require_pin_for_create: AtomicBool,
    pub require_pin_for_rename: AtomicBool,
    pub require_pin_for_delete: AtomicBool,
    pub require_touch_id_for_create: AtomicBool,
    pub require_touch_id_for_rename: AtomicBool,
}

impl Default for RuntimeState {
    fn default() -> Self {
        Self {
            app: Mutex::new(AppState::default()),
            agent: Mutex::new(None),
            signing_gate: Mutex::new(()),
            pins: Mutex::new(HashMap::new()),
            fido: Mutex::new(()),
            secure_enclave: Mutex::new(()),
            auth_dismiss_generation: AtomicU64::new(0),
            activity: Mutex::new(VecDeque::new()),
            next_activity_id: AtomicU64::new(1),
            auto_lock_minutes: AtomicU64::new(15),
            last_fido_activity_ms: AtomicU64::new(0),
            preferred_backend: AtomicU64::new(0),
            lifecycle_flags: AtomicU64::new(0),
            device_scan_completed: AtomicBool::new(false),
            prompt_pin_on_startup: AtomicBool::new(false),
            prompt_pin_on_device_connection: AtomicBool::new(true),
            prompt_pin_after_mac_unlock: AtomicBool::new(true),
            require_pin_for_create: AtomicBool::new(true),
            require_pin_for_rename: AtomicBool::new(true),
            require_pin_for_delete: AtomicBool::new(true),
            require_touch_id_for_create: AtomicBool::new(true),
            require_touch_id_for_rename: AtomicBool::new(true),
        }
    }
}
