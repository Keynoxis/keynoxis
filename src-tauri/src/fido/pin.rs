// SPDX-License-Identifier: MPL-2.0

use std::ffi::{c_char, CString};
use zeroize::Zeroize;

pub fn validate(pin: &str) -> Result<(), String> {
    if pin.is_empty() {
        return Err("Enter your FIDO2 PIN".into());
    }
    if pin.as_bytes().contains(&0) {
        return Err("The PIN contains an invalid character".into());
    }
    Ok(())
}

pub struct SecretString(String);

impl SecretString {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    fn wipe(&mut self) {
        // Keep ownership of the allocation so zeroize can overwrite it
        // without creating another plaintext copy.
        self.0.zeroize();
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.wipe();
    }
}

pub struct SecretCString(CString);

impl SecretCString {
    pub fn new(value: &str) -> Result<Self, String> {
        CString::new(value)
            .map(Self)
            .map_err(|_| "Invalid PIN".into())
    }

    pub fn as_ptr(&self) -> *const c_char {
        self.0.as_ptr()
    }

    fn wipe(&mut self) {
        let replacement = CString::new(Vec::<u8>::new()).expect("empty CString");
        let mut bytes = std::mem::replace(&mut self.0, replacement).into_bytes_with_nul();
        bytes.zeroize();
    }
}

impl Drop for SecretCString {
    fn drop(&mut self) {
        self.wipe();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_string_wipes_its_owned_buffer() {
        let mut secret = SecretString::new("123456".into());
        secret.wipe();
        assert!(secret.0.as_bytes().iter().all(|byte| *byte == 0));
    }

    #[test]
    fn secret_cstring_wipes_and_replaces_its_buffer() {
        let mut secret = SecretCString::new("123456").unwrap();
        secret.wipe();
        assert_eq!(secret.0.as_bytes_with_nul(), &[0]);
    }
}
