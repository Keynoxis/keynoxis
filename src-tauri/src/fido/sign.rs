// SPDX-License-Identifier: MPL-2.0

use crate::{
    fido::{credentials::ECDSA_SK, ffi, pin::SecretCString},
    ssh,
    state::SshKey,
};
use sha2::{Digest, Sha256};
use std::ffi::CString;

pub struct AssertionSignature {
    pub signature: Vec<u8>,
    pub flags: u8,
    pub counter: u32,
}

pub fn sign(
    device_path: &str,
    key: &SshKey,
    data: &[u8],
    pin: &str,
) -> Result<AssertionSignature, String> {
    let handle = key.fido2()?;
    let path = CString::new(device_path).map_err(|_| "Invalid device path")?;
    let rp = CString::new(handle.application.as_str()).map_err(|_| "Invalid SSH application")?;
    let pin = SecretCString::new(pin)?;
    let hash = Sha256::digest(data);

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

        let mut assertion = ffi::fido_assert_new();
        if assertion.is_null() {
            ffi::fido_dev_close(dev);
            ffi::fido_dev_free(&mut dev);
            return Err("Could not allocate a FIDO2 assertion".into());
        }

        let setup = [
            ffi::fido_assert_set_rp(assertion, rp.as_ptr()),
            ffi::fido_assert_set_clientdata_hash(assertion, hash.as_ptr(), hash.len()),
            ffi::fido_assert_allow_cred(
                assertion,
                handle.credential_id.as_ptr(),
                handle.credential_id.len(),
            ),
            ffi::fido_assert_set_up(assertion, ffi::FIDO_OPT_TRUE),
            ffi::fido_assert_set_uv(
                assertion,
                if handle.flags & 0x04 != 0 {
                    ffi::FIDO_OPT_TRUE
                } else {
                    ffi::FIDO_OPT_OMIT
                },
            ),
        ];
        if let Some(rc) = setup.into_iter().find(|rc| *rc != ffi::FIDO_OK) {
            ffi::fido_assert_free(&mut assertion);
            ffi::fido_dev_close(dev);
            ffi::fido_dev_free(&mut dev);
            return Err(ffi::error_message(rc));
        }

        let rc = ffi::fido_dev_get_assert(dev, assertion, pin.as_ptr());
        let result = if rc == ffi::FIDO_OK {
            let raw = ffi::bytes(
                ffi::fido_assert_sig_ptr(assertion, 0),
                ffi::fido_assert_sig_len(assertion, 0),
            );
            if raw.is_empty() {
                Err("YubiKey returned an empty signature".into())
            } else {
                let signature = if key.algorithm == ECDSA_SK {
                    ssh::der_ecdsa_to_ssh(&raw)
                } else {
                    Ok(raw)
                };
                signature.map(|signature| AssertionSignature {
                    signature,
                    flags: ffi::fido_assert_flags(assertion, 0),
                    counter: ffi::fido_assert_sigcount(assertion, 0),
                })
            }
        } else {
            Err(ffi::signing_error_message(rc))
        };
        ffi::fido_assert_free(&mut assertion);
        ffi::fido_dev_close(dev);
        ffi::fido_dev_free(&mut dev);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_der_ecdsa_signature_to_two_mpints() {
        let der = [0x30, 0x08, 0x02, 0x02, 0x00, 0x80, 0x02, 0x02, 0x01, 0x02];
        let ssh = ssh::der_ecdsa_to_ssh(&der).unwrap();
        assert_eq!(&ssh[0..4], &2u32.to_be_bytes());
        assert_eq!(&ssh[4..6], &[0, 0x80]);
        assert_eq!(&ssh[6..10], &2u32.to_be_bytes());
        assert_eq!(&ssh[10..12], &[1, 2]);
    }
}
