// SPDX-License-Identifier: MPL-2.0

use crate::{
    fido::{
        credentials::{self, ECDSA_SK, ED25519_SK},
        ffi,
        pin::SecretCString,
    },
    state::{Fido2KeyHandle, KeyBackend, KeyHandle, SshKey},
};
use std::ffi::CString;

pub fn load(device_path: &str, pin: &str) -> Result<Vec<SshKey>, String> {
    let path = CString::new(device_path).map_err(|_| "Invalid device path")?;
    let pin = SecretCString::new(pin)?;
    unsafe {
        ffi::fido_init(ffi::FIDO_DISABLE_U2F_FALLBACK);
        let mut dev = ffi::fido_dev_new();
        if dev.is_null() {
            return Err("Could not allocate a libfido2 device".into());
        }
        let open_rc = ffi::fido_dev_open(dev, path.as_ptr());
        if open_rc != ffi::FIDO_OK {
            ffi::fido_dev_free(&mut dev);
            return Err(ffi::error_message(open_rc));
        }
        if !ffi::fido_dev_is_fido2(dev) || !ffi::fido_dev_supports_credman(dev) {
            ffi::fido_dev_close(dev);
            ffi::fido_dev_free(&mut dev);
            return Err("This YubiKey does not support FIDO2 credential management".into());
        }

        let result = enumerate(dev, &pin).map(|mut keys| {
            for key in &mut keys {
                key.device_path = Some(device_path.to_owned());
            }
            keys
        });
        ffi::fido_dev_close(dev);
        ffi::fido_dev_free(&mut dev);
        result
    }
}

unsafe fn enumerate(dev: *mut ffi::fido_dev_t, pin: &SecretCString) -> Result<Vec<SshKey>, String> {
    let mut rps = ffi::fido_credman_rp_new();
    if rps.is_null() {
        return Err("Could not allocate a credential list".into());
    }
    let rc = ffi::fido_credman_get_dev_rp(dev, rps, pin.as_ptr());
    if rc == ffi::FIDO_ERR_NO_CREDENTIALS {
        // A valid PIN on an empty authenticator is a successful unlock with
        // zero resident SSH identities, not an authentication failure.
        ffi::fido_credman_rp_free(&mut rps);
        return Ok(Vec::new());
    }
    if rc != ffi::FIDO_OK {
        ffi::fido_credman_rp_free(&mut rps);
        return Err(friendly_error(rc));
    }

    let mut result = Vec::new();
    for rp_index in 0..ffi::fido_credman_rp_count(rps) {
        let Some(application) = ffi::string(ffi::fido_credman_rp_id(rps, rp_index)) else {
            continue;
        };
        if !application.starts_with("ssh:") {
            continue;
        }
        let rp_id =
            CString::new(application.as_str()).map_err(|_| "Invalid resident relying-party ID")?;
        let mut keys = ffi::fido_credman_rk_new();
        if keys.is_null() {
            continue;
        }
        let rc = ffi::fido_credman_get_dev_rk(dev, rp_id.as_ptr(), keys, pin.as_ptr());
        if rc == ffi::FIDO_ERR_NO_CREDENTIALS {
            ffi::fido_credman_rk_free(&mut keys);
            continue;
        }
        if rc != ffi::FIDO_OK {
            ffi::fido_credman_rk_free(&mut keys);
            ffi::fido_credman_rp_free(&mut rps);
            return Err(friendly_error(rc));
        }

        for key_index in 0..ffi::fido_credman_rk_count(keys) {
            let cred = ffi::fido_credman_rk(keys, key_index);
            if cred.is_null() {
                continue;
            }
            let algorithm = match ffi::fido_cred_type(cred) {
                ffi::COSE_EDDSA => ED25519_SK,
                ffi::COSE_ES256 => ECDSA_SK,
                _ => continue,
            };
            let public_key_bytes = ffi::bytes(
                ffi::fido_cred_pubkey_ptr(cred),
                ffi::fido_cred_pubkey_len(cred),
            );
            let credential_id =
                ffi::bytes(ffi::fido_cred_id_ptr(cred), ffi::fido_cred_id_len(cred));
            let user_id = ffi::bytes(
                ffi::fido_cred_user_id_ptr(cred),
                ffi::fido_cred_user_id_len(cred),
            );
            if public_key_bytes.is_empty() || credential_id.is_empty() {
                continue;
            }
            let comment = ffi::string(ffi::fido_cred_display_name(cred))
                .or_else(|| ffi::string(ffi::fido_cred_user_name(cred)))
                .filter(|s| !s.is_empty());
            // OpenSSH always requires presence for resident keys. Preserve the
            // authenticator's UV bit when the credential requires verification.
            let flags = 0x01 | 0x20 | (ffi::fido_cred_flags(cred) & 0x04);
            result.push(credentials::finish(SshKey {
                algorithm: algorithm.into(),
                public_key: String::new(),
                fingerprint: String::new(),
                comment,
                backend: KeyBackend::Fido2,
                enabled: true,
                device_path: None,
                public_blob: Vec::new(),
                handle: Some(KeyHandle::Fido2(Fido2KeyHandle {
                    application: application.clone(),
                    credential_id,
                    user_id,
                    public_key_bytes,
                    flags,
                })),
            })?);
        }
        ffi::fido_credman_rk_free(&mut keys);
    }
    ffi::fido_credman_rp_free(&mut rps);
    Ok(result)
}

fn friendly_error(code: i32) -> String {
    match code {
        ffi::FIDO_ERR_PIN_INVALID => "Invalid PIN".into(),
        ffi::FIDO_ERR_PIN_BLOCKED => "FIDO2 PIN blocked. Reinsert the YubiKey to retry.".into(),
        ffi::FIDO_ERR_PIN_AUTH_BLOCKED => "Too many invalid attempts. Reinsert the YubiKey.".into(),
        _ => ffi::error_message(code),
    }
}
