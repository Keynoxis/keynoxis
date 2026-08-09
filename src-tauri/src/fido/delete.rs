// SPDX-License-Identifier: MPL-2.0

use crate::{
    fido::{ffi, pin::SecretCString},
    state::SshKey,
};
use std::ffi::CString;

pub fn credential(device_path: &str, key: &SshKey, pin: &str) -> Result<(), String> {
    let handle = key.fido2()?;
    if handle.credential_id.is_empty() {
        return Err("This resident credential has no credential ID".into());
    }

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

        let rc = ffi::fido_credman_del_dev_rk(
            dev,
            handle.credential_id.as_ptr(),
            handle.credential_id.len(),
            pin.as_ptr(),
        );
        ffi::fido_dev_close(dev);
        ffi::fido_dev_free(&mut dev);
        if rc == ffi::FIDO_OK {
            Ok(())
        } else {
            Err(match rc {
                ffi::FIDO_ERR_PIN_INVALID => "Invalid PIN".into(),
                ffi::FIDO_ERR_PIN_BLOCKED => {
                    "FIDO2 PIN blocked. Reinsert the YubiKey to retry.".into()
                }
                ffi::FIDO_ERR_PIN_AUTH_BLOCKED => {
                    "Too many invalid attempts. Reinsert the YubiKey.".into()
                }
                _ => ffi::error_message(rc),
            })
        }
    }
}
