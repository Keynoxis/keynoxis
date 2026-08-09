// SPDX-License-Identifier: MPL-2.0

use crate::{
    fido::{ffi, pin::SecretCString},
    state::SshKey,
};
use std::{ffi::CString, ptr};

pub fn credential(device_path: &str, key: &SshKey, label: &str, pin: &str) -> Result<(), String> {
    let handle = key.fido2()?;
    if handle.user_id.is_empty() {
        return Err("This resident credential has no user ID and cannot be renamed".into());
    }

    let path = CString::new(device_path).map_err(|_| "Invalid device path")?;
    let label = CString::new(label).map_err(|_| "Key name contains an invalid character")?;
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

        let mut cred = ffi::fido_cred_new();
        if cred.is_null() {
            ffi::fido_dev_close(dev);
            ffi::fido_dev_free(&mut dev);
            return Err("Could not allocate a FIDO2 credential".into());
        }

        let id_rc = ffi::fido_cred_set_id(
            cred,
            handle.credential_id.as_ptr(),
            handle.credential_id.len(),
        );
        let user_rc = if id_rc == ffi::FIDO_OK {
            ffi::fido_cred_set_user(
                cred,
                handle.user_id.as_ptr(),
                handle.user_id.len(),
                label.as_ptr(),
                label.as_ptr(),
                ptr::null(),
            )
        } else {
            id_rc
        };
        let result = if user_rc == ffi::FIDO_OK {
            let rc = ffi::fido_credman_set_dev_rk(dev, cred, pin.as_ptr());
            if rc == ffi::FIDO_OK {
                Ok(())
            } else {
                Err(ffi::error_message(rc))
            }
        } else {
            Err(ffi::error_message(user_rc))
        };

        ffi::fido_cred_free(&mut cred);
        ffi::fido_dev_close(dev);
        ffi::fido_dev_free(&mut dev);
        result
    }
}
