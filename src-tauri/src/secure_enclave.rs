// SPDX-License-Identifier: MPL-2.0

use crate::{
    ssh,
    state::{KeyBackend, KeyHandle, SecureEnclaveKeyHandle, SshKey},
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tauri::{AppHandle, Manager};

const REGISTRY_FILE: &str = "secure-enclave-keys.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RegistryEntry {
    name: String,
    public_point: Vec<u8>,
    encrypted_key: Vec<u8>,
}

pub fn list(app: &AppHandle) -> Result<Vec<SshKey>, String> {
    read_registry(&registry_path(app)?)?
        .into_iter()
        .map(build_ssh_key)
        .collect()
}

pub fn create(app: &AppHandle, name: &str) -> Result<SshKey, String> {
    validate_name(name)?;
    let path = registry_path(app)?;
    let mut entries = read_registry(&path)?;
    if entries
        .iter()
        .any(|entry| entry.name.eq_ignore_ascii_case(name))
    {
        return Err("A Secure Enclave key with this name already exists".into());
    }

    let (encrypted_key, public_point) = platform::create()?;
    let entry = RegistryEntry {
        name: name.into(),
        public_point,
        encrypted_key,
    };
    let key = build_ssh_key(entry.clone())?;
    entries.push(entry);
    write_registry(&path, &entries)?;
    Ok(key)
}

pub fn rename(app: &AppHandle, key: &SshKey, name: &str) -> Result<SshKey, String> {
    validate_name(name)?;
    let encrypted_key = &key.secure_enclave()?.encrypted_key;
    let path = registry_path(app)?;
    let mut entries = read_registry(&path)?;
    if entries
        .iter()
        .any(|entry| entry.encrypted_key != *encrypted_key && entry.name.eq_ignore_ascii_case(name))
    {
        return Err("A Secure Enclave key with this name already exists".into());
    }
    let entry = entries
        .iter_mut()
        .find(|entry| entry.encrypted_key == *encrypted_key)
        .ok_or("Secure Enclave key metadata was not found")?;
    entry.name = name.to_owned();
    let updated = build_ssh_key(entry.clone())?;
    write_registry(&path, &entries)?;
    Ok(updated)
}

pub fn delete(app: &AppHandle, key: &SshKey) -> Result<(), String> {
    platform::authorize_touch_id()?;
    let encrypted_key = &key.secure_enclave()?.encrypted_key;
    let path = registry_path(app)?;
    let mut entries = read_registry(&path)?;
    let previous_len = entries.len();
    entries.retain(|entry| entry.encrypted_key != *encrypted_key);
    if entries.len() == previous_len {
        return Err("Secure Enclave key metadata was not found".into());
    }
    write_registry(&path, &entries)
}

pub fn authorize_touch_id() -> Result<(), String> {
    platform::authorize_touch_id()
}

pub fn sign(key: &SshKey, data: &[u8]) -> Result<Vec<u8>, String> {
    let encrypted_key = &key.secure_enclave()?.encrypted_key;
    let der = platform::sign(encrypted_key, data)?;
    ssh::der_ecdsa_to_ssh(&der)
}

fn validate_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("Key name cannot be empty".into());
    }
    if name.len() > 64 {
        return Err("Key name must be 64 UTF-8 bytes or fewer".into());
    }
    if name.chars().any(char::is_control) {
        return Err("Key name cannot contain control characters".into());
    }
    Ok(())
}

fn build_ssh_key(entry: RegistryEntry) -> Result<SshKey, String> {
    let public_blob = ssh::ecdsa_public_blob(&entry.public_point)?;
    let (public_key, fingerprint) =
        ssh::public_line_and_fingerprint(&public_blob, ssh::ECDSA_P256, &entry.name);
    Ok(SshKey {
        algorithm: ssh::ECDSA_P256.into(),
        public_key,
        fingerprint,
        comment: Some(entry.name),
        backend: KeyBackend::SecureEnclave,
        enabled: true,
        device_path: None,
        public_blob,
        handle: Some(KeyHandle::SecureEnclave(SecureEnclaveKeyHandle {
            encrypted_key: entry.encrypted_key,
        })),
    })
}

fn registry_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(app
        .path()
        .app_data_dir()
        .map_err(|error| format!("Could not locate Keynoxis data directory: {error}"))?
        .join(REGISTRY_FILE))
}

fn read_registry(path: &Path) -> Result<Vec<RegistryEntry>, String> {
    match std::fs::read(path) {
        Ok(data) => serde_json::from_slice(&data)
            .map_err(|error| format!("Secure Enclave key metadata is invalid: {error}")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(format!(
            "Could not read Secure Enclave key metadata: {error}"
        )),
    }
}

fn write_registry(path: &Path, entries: &[RegistryEntry]) -> Result<(), String> {
    let parent = path.parent().ok_or("Invalid Keynoxis data directory")?;
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("Could not create Keynoxis data directory: {error}"))?;
    let data = serde_json::to_vec_pretty(entries)
        .map_err(|error| format!("Could not encode Secure Enclave metadata: {error}"))?;
    let temporary = path.with_extension("json.tmp");
    std::fs::write(&temporary, data)
        .map_err(|error| format!("Could not save Secure Enclave metadata: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("Could not secure Secure Enclave metadata: {error}"))?;
    }
    std::fs::rename(&temporary, path)
        .map_err(|error| format!("Could not commit Secure Enclave metadata: {error}"))
}

#[cfg(target_os = "macos")]
mod platform {
    use std::{ffi::c_void, ptr, slice};

    #[link(name = "KeynoxisSecureEnclave")]
    extern "C" {
        fn keynoxis_se_create(
            encrypted_key: *mut *mut u8,
            encrypted_key_len: *mut usize,
            public_key: *mut *mut u8,
            public_key_len: *mut usize,
            error: *mut *mut u8,
            error_len: *mut usize,
        ) -> i32;
        fn keynoxis_se_sign(
            encrypted_key: *const u8,
            encrypted_key_len: usize,
            message: *const u8,
            message_len: usize,
            signature: *mut *mut u8,
            signature_len: *mut usize,
            error: *mut *mut u8,
            error_len: *mut usize,
        ) -> i32;
        fn keynoxis_se_free(pointer: *mut c_void);
        fn keynoxis_authorize_touch_id(error: *mut *mut u8, error_len: *mut usize) -> i32;
    }

    pub fn create() -> Result<(Vec<u8>, Vec<u8>), String> {
        if !cfg!(target_arch = "aarch64") {
            return Err("Secure Enclave SSH keys require an Apple Silicon Mac".into());
        }
        let mut encrypted_key = ptr::null_mut();
        let mut encrypted_key_len = 0;
        let mut public_key = ptr::null_mut();
        let mut public_key_len = 0;
        let mut error = ptr::null_mut();
        let mut error_len = 0;
        let status = unsafe {
            keynoxis_se_create(
                &mut encrypted_key,
                &mut encrypted_key_len,
                &mut public_key,
                &mut public_key_len,
                &mut error,
                &mut error_len,
            )
        };
        if status != 0 {
            return Err(take_error(
                error,
                error_len,
                "Secure Enclave could not create the SSH key",
            ));
        }
        let encrypted_key = take_buffer(encrypted_key, encrypted_key_len);
        let public_key = take_buffer(public_key, public_key_len);
        Ok((encrypted_key, public_key))
    }

    pub fn sign(encrypted_key: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
        let mut signature = ptr::null_mut();
        let mut signature_len = 0;
        let mut error = ptr::null_mut();
        let mut error_len = 0;
        let status = unsafe {
            keynoxis_se_sign(
                encrypted_key.as_ptr(),
                encrypted_key.len(),
                message.as_ptr(),
                message.len(),
                &mut signature,
                &mut signature_len,
                &mut error,
                &mut error_len,
            )
        };
        if status != 0 {
            return Err(take_error(
                error,
                error_len,
                "Secure Enclave refused the SSH signature",
            ));
        }
        Ok(take_buffer(signature, signature_len))
    }

    pub fn authorize_touch_id() -> Result<(), String> {
        let mut error = ptr::null_mut();
        let mut error_len = 0;
        let status = unsafe { keynoxis_authorize_touch_id(&mut error, &mut error_len) };
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
        let message = take_buffer(pointer, length);
        String::from_utf8(message).unwrap_or_else(|_| fallback.into())
    }
}

#[cfg(not(target_os = "macos"))]
mod platform {
    pub fn create() -> Result<(Vec<u8>, Vec<u8>), String> {
        Err("Secure Enclave is available only on macOS".into())
    }
    pub fn sign(_encrypted_key: &[u8], _message: &[u8]) -> Result<Vec<u8>, String> {
        Err("Secure Enclave is available only on macOS".into())
    }
    pub fn authorize_touch_id() -> Result<(), String> {
        Err("Touch ID is available only on macOS".into())
    }
}
