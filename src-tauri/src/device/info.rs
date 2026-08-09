// SPDX-License-Identifier: MPL-2.0

use crate::state::DeviceInfo;

pub fn is_yubikey(info: &DeviceInfo) -> bool {
    // Yubico's assigned USB vendor ID. Filtering avoids treating Touch ID or
    // unrelated platform authenticators as a supported external security key.
    info.vendor_id == 0x1050
}
