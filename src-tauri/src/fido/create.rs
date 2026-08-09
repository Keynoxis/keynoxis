// SPDX-License-Identifier: MPL-2.0

use crate::{
    fido::{credentials, ffi, pin::SecretCString},
    state::{Fido2KeyHandle, KeyBackend, KeyHandle, SshKey},
};
use std::{ffi::CString, fs::File, io::Read, ptr};

const SSH_APPLICATION: &str = "ssh:";

pub fn resident(
    device_path: &str,
    name: &str,
    pin: &str,
    algorithm: &str,
) -> Result<SshKey, String> {
    let (cose_type, ssh_algorithm) = match algorithm {
        credentials::ED25519_SK => (ffi::COSE_EDDSA, credentials::ED25519_SK),
        credentials::ECDSA_SK => (ffi::COSE_ES256, credentials::ECDSA_SK),
        _ => return Err("Unsupported FIDO2 SSH key algorithm".into()),
    };
    let path = CString::new(device_path).map_err(|_| "Invalid device path")?;
    let application = CString::new(SSH_APPLICATION).expect("static SSH application");
    let rp_name = CString::new("Keynoxis SSH").expect("static RP name");
    let name = CString::new(name).map_err(|_| "Key name contains an invalid character")?;
    let pin = SecretCString::new(pin)?;
    let user_id = random_bytes()?;
    let client_data_hash = random_bytes()?;

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

        let mut credential = ffi::fido_cred_new();
        if credential.is_null() {
            ffi::fido_dev_close(dev);
            ffi::fido_dev_free(&mut dev);
            return Err("Could not allocate a FIDO2 credential".into());
        }

        let setup = [
            ffi::fido_cred_set_type(credential, cose_type),
            ffi::fido_cred_set_clientdata_hash(
                credential,
                client_data_hash.as_ptr(),
                client_data_hash.len(),
            ),
            ffi::fido_cred_set_rp(credential, application.as_ptr(), rp_name.as_ptr()),
            ffi::fido_cred_set_user(
                credential,
                user_id.as_ptr(),
                user_id.len(),
                name.as_ptr(),
                name.as_ptr(),
                ptr::null(),
            ),
            ffi::fido_cred_set_rk(credential, ffi::FIDO_OPT_TRUE),
            ffi::fido_cred_set_uv(credential, ffi::FIDO_OPT_OMIT),
        ];

        let result = if let Some(rc) = setup.into_iter().find(|rc| *rc != ffi::FIDO_OK) {
            Err(ffi::error_message(rc))
        } else {
            let rc = ffi::fido_dev_make_cred(dev, credential, pin.as_ptr());
            if rc == ffi::FIDO_OK {
                from_credential(
                    credential,
                    name.to_string_lossy().into_owned(),
                    user_id,
                    ssh_algorithm,
                )
            } else {
                Err(friendly_error(rc))
            }
        };

        ffi::fido_cred_free(&mut credential);
        ffi::fido_dev_close(dev);
        ffi::fido_dev_free(&mut dev);
        result
    }
}

unsafe fn from_credential(
    credential: *const ffi::fido_cred_t,
    name: String,
    user_id: Vec<u8>,
    algorithm: &str,
) -> Result<SshKey, String> {
    let credential_id = ffi::bytes(
        ffi::fido_cred_id_ptr(credential),
        ffi::fido_cred_id_len(credential),
    );
    let public_key_bytes = ffi::bytes(
        ffi::fido_cred_pubkey_ptr(credential),
        ffi::fido_cred_pubkey_len(credential),
    );
    if credential_id.is_empty() || public_key_bytes.is_empty() {
        return Err("YubiKey created a credential without public key data".into());
    }
    credentials::finish(SshKey {
        algorithm: algorithm.into(),
        public_key: String::new(),
        fingerprint: String::new(),
        comment: Some(name),
        backend: KeyBackend::Fido2,
        enabled: true,
        device_path: None,
        public_blob: Vec::new(),
        handle: Some(KeyHandle::Fido2(Fido2KeyHandle {
            application: SSH_APPLICATION.into(),
            credential_id,
            user_id,
            public_key_bytes,
            flags: 0x01 | 0x20,
        })),
    })
}

fn random_bytes() -> Result<Vec<u8>, String> {
    let mut bytes = vec![0u8; 32];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(|error| format!("Could not generate credential randomness: {error}"))?;
    Ok(bytes)
}

fn friendly_error(code: i32) -> String {
    match code {
        ffi::FIDO_ERR_PIN_INVALID => "Invalid PIN".into(),
        ffi::FIDO_ERR_PIN_BLOCKED => "FIDO2 PIN blocked. Reinsert the YubiKey to retry.".into(),
        ffi::FIDO_ERR_PIN_AUTH_BLOCKED => "Too many invalid attempts. Reinsert the YubiKey.".into(),
        ffi::FIDO_ERR_OPERATION_DENIED | ffi::FIDO_ERR_KEEPALIVE_CANCEL => {
            "Touch timed out. The SSH key was not created.".into()
        }
        _ => ffi::error_message(code),
    }
}
