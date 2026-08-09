// SPDX-License-Identifier: MPL-2.0

use crate::{fido::ffi, state::DeviceInfo};
use std::{ffi::CStr, ptr};

const MAX_DEVICES: usize = 16;

pub fn yubikeys(previous: &[DeviceInfo]) -> Result<Vec<DeviceInfo>, String> {
    unsafe {
        ffi::fido_init(ffi::FIDO_DISABLE_U2F_FALLBACK);
        let mut list = ffi::fido_dev_info_new(MAX_DEVICES);
        if list.is_null() {
            return Err("Could not allocate a libfido2 device list".into());
        }
        let mut found = 0usize;
        let rc = ffi::fido_dev_info_manifest(list, MAX_DEVICES, &mut found);
        if rc != ffi::FIDO_OK {
            ffi::fido_dev_info_free(&mut list, MAX_DEVICES);
            return Err(ffi::error_message(rc));
        }

        let mut result = Vec::new();
        for index in 0..found {
            let item = ffi::fido_dev_info_ptr(list, index);
            if item.is_null() {
                continue;
            }
            let vendor_id = ffi::fido_dev_info_vendor(item) as u16;
            if vendor_id != 0x1050 {
                continue;
            }
            let path = c_string(ffi::fido_dev_info_path(item)).unwrap_or_default();

            // Presence polling must not reopen a key that we have already
            // verified. OpenSSH may hold the HID device briefly while signing;
            // treating that temporary busy state as "not FIDO2" drops all keys
            // in the middle of an SSH connection.
            if let Some(known) = previous.iter().find(|known| known.path == path) {
                let mut candidate = known.clone();
                candidate.product = c_string(ffi::fido_dev_info_product_string(item));
                candidate.manufacturer = c_string(ffi::fido_dev_info_manufacturer_string(item));
                result.push(candidate);
                continue;
            }

            let mut dev = ffi::fido_dev_new_with_info(item);
            if dev.is_null() {
                ffi::fido_dev_info_free(&mut list, MAX_DEVICES);
                return Err("Could not allocate a libfido2 device".into());
            }
            let open_rc = ffi::fido_dev_open_with_info(dev);
            let opened = open_rc == ffi::FIDO_OK;
            let fido2 = opened && ffi::fido_dev_is_fido2(dev);
            let details = if fido2 {
                device_details(dev)
            } else {
                DeviceDetails::default()
            };
            if opened {
                ffi::fido_dev_close(dev);
            }
            if !dev.is_null() {
                ffi::fido_dev_free(&mut dev);
            }

            if !opened {
                // A known authenticator may be held briefly by an SSH signing
                // operation. Unknown busy devices are retried on the next poll.
                continue;
            }

            let candidate = DeviceInfo {
                label: None,
                // libfido2 does not expose a hardware serial number. Reading
                // it through raw IOHID would make macOS request Input
                // Monitoring permission, which an SSH agent must not require.
                serial_number: None,
                local_id: yubikey_local_id(&path),
                product: c_string(ffi::fido_dev_info_product_string(item)),
                manufacturer: c_string(ffi::fido_dev_info_manufacturer_string(item)),
                path,
                vendor_id,
                product_id: ffi::fido_dev_info_product(item) as u16,
                fido2,
                credential_management: details.credential_management,
                pin_configured: details.pin_configured,
                algorithms: details.algorithms,
                aaguid: details.aaguid,
                firmware: details.firmware,
                resident_credentials_remaining: details.resident_credentials_remaining,
                pin_retries: details.pin_retries,
            };
            if !crate::device::info::is_yubikey(&candidate) {
                continue;
            }
            result.push(candidate);
        }
        ffi::fido_dev_info_free(&mut list, MAX_DEVICES);
        result.sort_by(|left, right| left.path.cmp(&right.path));
        Ok(result)
    }
}

#[cfg(target_os = "macos")]
fn yubikey_local_id(path: &str) -> Option<u32> {
    #[link(name = "KeynoxisSecureEnclave")]
    extern "C" {
        fn keynoxis_yubikey_local_id(registry_id: u64) -> u32;
    }
    let registry_id = path.strip_prefix("ioreg://")?.parse().ok()?;
    let local_id = unsafe { keynoxis_yubikey_local_id(registry_id) };
    (local_id != 0).then_some(local_id)
}

#[cfg(not(target_os = "macos"))]
fn yubikey_local_id(_path: &str) -> Option<u32> {
    None
}

#[derive(Default)]
struct DeviceDetails {
    credential_management: bool,
    pin_configured: bool,
    algorithms: Vec<String>,
    aaguid: Option<String>,
    firmware: Option<String>,
    resident_credentials_remaining: Option<i64>,
    pin_retries: Option<i32>,
}

unsafe fn device_details(dev: *mut ffi::fido_dev_t) -> DeviceDetails {
    let mut details = DeviceDetails {
        credential_management: ffi::fido_dev_supports_credman(dev),
        pin_configured: ffi::fido_dev_has_pin(dev),
        ..DeviceDetails::default()
    };
    let mut retries = 0;
    if ffi::fido_dev_get_retry_count(dev, &mut retries) == ffi::FIDO_OK {
        details.pin_retries = Some(retries);
    }
    let mut info = ffi::fido_cbor_info_new();
    if info.is_null() || ffi::fido_dev_get_cbor_info(dev, info) != ffi::FIDO_OK {
        if !info.is_null() {
            ffi::fido_cbor_info_free(&mut info);
        }
        return details;
    }
    for index in 0..ffi::fido_cbor_info_algorithm_count(info) {
        match ffi::fido_cbor_info_algorithm_cose(info, index) {
            ffi::COSE_EDDSA => details.algorithms.push("ED25519-SK".into()),
            ffi::COSE_ES256 => details.algorithms.push("ECDSA-SK".into()),
            _ => {}
        }
    }
    details.algorithms.sort();
    details.algorithms.dedup();
    let aaguid = ffi::bytes(
        ffi::fido_cbor_info_aaguid_ptr(info),
        ffi::fido_cbor_info_aaguid_len(info),
    );
    if !aaguid.is_empty() {
        details.aaguid = Some(aaguid.iter().map(|byte| format!("{byte:02x}")).collect());
    }
    let firmware = ffi::fido_cbor_info_fwversion(info);
    if firmware != 0 {
        details.firmware = Some(if firmware <= 0x00ff_ffff {
            format!(
                "{}.{}.{}",
                (firmware >> 16) & 0xff,
                (firmware >> 8) & 0xff,
                firmware & 0xff
            )
        } else {
            format!("0x{firmware:x}")
        });
    }
    let remaining = ffi::fido_cbor_info_rk_remaining(info);
    if remaining >= 0 {
        details.resident_credentials_remaining = Some(remaining);
    }
    ffi::fido_cbor_info_free(&mut info);
    details
}

unsafe fn c_string(value: *const std::ffi::c_char) -> Option<String> {
    if value == ptr::null() {
        None
    } else {
        Some(CStr::from_ptr(value).to_string_lossy().into_owned())
    }
}
