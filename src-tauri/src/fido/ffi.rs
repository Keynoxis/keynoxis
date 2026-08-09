// SPDX-License-Identifier: MPL-2.0

#![allow(non_camel_case_types)]
use std::ffi::{c_char, c_int, c_uchar, CStr};

pub const FIDO_OK: c_int = 0;
pub const FIDO_DISABLE_U2F_FALLBACK: c_int = 0x02;
pub const COSE_ES256: c_int = -7;
pub const COSE_EDDSA: c_int = -8;
pub const FIDO_ERR_PIN_INVALID: c_int = 0x31;
pub const FIDO_ERR_PIN_BLOCKED: c_int = 0x32;
pub const FIDO_ERR_PIN_AUTH_BLOCKED: c_int = 0x34;
pub const FIDO_ERR_OPERATION_DENIED: c_int = 0x27;
pub const FIDO_ERR_KEEPALIVE_CANCEL: c_int = 0x2d;
pub const FIDO_ERR_NO_CREDENTIALS: c_int = 0x2e;

#[repr(C)]
pub struct fido_dev_t {
    _private: [u8; 0],
}
#[repr(C)]
pub struct fido_dev_info_t {
    _private: [u8; 0],
}
#[repr(C)]
pub struct fido_cred_t {
    _private: [u8; 0],
}
#[repr(C)]
pub struct fido_credman_rp_t {
    _private: [u8; 0],
}
#[repr(C)]
pub struct fido_credman_rk_t {
    _private: [u8; 0],
}
#[repr(C)]
pub struct fido_assert_t {
    _private: [u8; 0],
}
#[repr(C)]
pub struct fido_cbor_info_t {
    _private: [u8; 0],
}

pub const FIDO_OPT_OMIT: c_int = 0;
pub const FIDO_OPT_TRUE: c_int = 2;

extern "C" {
    pub fn fido_init(flags: c_int);
    pub fn fido_strerr(error: c_int) -> *const c_char;
    pub fn fido_dev_info_new(count: usize) -> *mut fido_dev_info_t;
    pub fn fido_dev_info_free(list: *mut *mut fido_dev_info_t, count: usize);
    pub fn fido_dev_info_manifest(
        list: *mut fido_dev_info_t,
        count: usize,
        found: *mut usize,
    ) -> c_int;
    pub fn fido_dev_info_ptr(list: *const fido_dev_info_t, index: usize) -> *const fido_dev_info_t;
    pub fn fido_dev_info_path(info: *const fido_dev_info_t) -> *const c_char;
    pub fn fido_dev_info_product_string(info: *const fido_dev_info_t) -> *const c_char;
    pub fn fido_dev_info_manufacturer_string(info: *const fido_dev_info_t) -> *const c_char;
    pub fn fido_dev_info_vendor(info: *const fido_dev_info_t) -> i16;
    pub fn fido_dev_info_product(info: *const fido_dev_info_t) -> i16;
    pub fn fido_dev_new_with_info(info: *const fido_dev_info_t) -> *mut fido_dev_t;
    pub fn fido_dev_new() -> *mut fido_dev_t;
    pub fn fido_dev_free(dev: *mut *mut fido_dev_t);
    pub fn fido_dev_open_with_info(dev: *mut fido_dev_t) -> c_int;
    pub fn fido_dev_open(dev: *mut fido_dev_t, path: *const c_char) -> c_int;
    pub fn fido_dev_close(dev: *mut fido_dev_t) -> c_int;
    pub fn fido_dev_is_fido2(dev: *const fido_dev_t) -> bool;
    pub fn fido_dev_supports_credman(dev: *const fido_dev_t) -> bool;
    pub fn fido_dev_has_pin(dev: *const fido_dev_t) -> bool;
    pub fn fido_dev_get_retry_count(dev: *mut fido_dev_t, retries: *mut c_int) -> c_int;
    pub fn fido_cbor_info_new() -> *mut fido_cbor_info_t;
    pub fn fido_cbor_info_free(value: *mut *mut fido_cbor_info_t);
    pub fn fido_dev_get_cbor_info(dev: *mut fido_dev_t, info: *mut fido_cbor_info_t) -> c_int;
    pub fn fido_cbor_info_algorithm_count(info: *const fido_cbor_info_t) -> usize;
    pub fn fido_cbor_info_algorithm_cose(info: *const fido_cbor_info_t, index: usize) -> c_int;
    pub fn fido_cbor_info_aaguid_ptr(info: *const fido_cbor_info_t) -> *const c_uchar;
    pub fn fido_cbor_info_aaguid_len(info: *const fido_cbor_info_t) -> usize;
    pub fn fido_cbor_info_fwversion(info: *const fido_cbor_info_t) -> u64;
    pub fn fido_cbor_info_rk_remaining(info: *const fido_cbor_info_t) -> i64;
    pub fn fido_credman_rp_new() -> *mut fido_credman_rp_t;
    pub fn fido_credman_rp_free(value: *mut *mut fido_credman_rp_t);
    pub fn fido_credman_get_dev_rp(
        dev: *mut fido_dev_t,
        rps: *mut fido_credman_rp_t,
        pin: *const c_char,
    ) -> c_int;
    pub fn fido_credman_rp_count(rps: *const fido_credman_rp_t) -> usize;
    pub fn fido_credman_rp_id(rps: *const fido_credman_rp_t, index: usize) -> *const c_char;
    pub fn fido_credman_rk_new() -> *mut fido_credman_rk_t;
    pub fn fido_credman_rk_free(value: *mut *mut fido_credman_rk_t);
    pub fn fido_credman_get_dev_rk(
        dev: *mut fido_dev_t,
        rp_id: *const c_char,
        keys: *mut fido_credman_rk_t,
        pin: *const c_char,
    ) -> c_int;
    pub fn fido_credman_rk_count(keys: *const fido_credman_rk_t) -> usize;
    pub fn fido_credman_rk(keys: *const fido_credman_rk_t, index: usize) -> *const fido_cred_t;
    pub fn fido_cred_type(cred: *const fido_cred_t) -> c_int;
    pub fn fido_cred_flags(cred: *const fido_cred_t) -> u8;
    pub fn fido_cred_id_ptr(cred: *const fido_cred_t) -> *const c_uchar;
    pub fn fido_cred_id_len(cred: *const fido_cred_t) -> usize;
    pub fn fido_cred_user_id_ptr(cred: *const fido_cred_t) -> *const c_uchar;
    pub fn fido_cred_user_id_len(cred: *const fido_cred_t) -> usize;
    pub fn fido_cred_pubkey_ptr(cred: *const fido_cred_t) -> *const c_uchar;
    pub fn fido_cred_pubkey_len(cred: *const fido_cred_t) -> usize;
    pub fn fido_cred_user_name(cred: *const fido_cred_t) -> *const c_char;
    pub fn fido_cred_display_name(cred: *const fido_cred_t) -> *const c_char;
    pub fn fido_cred_new() -> *mut fido_cred_t;
    pub fn fido_cred_free(value: *mut *mut fido_cred_t);
    pub fn fido_cred_set_id(
        cred: *mut fido_cred_t,
        credential_id: *const c_uchar,
        len: usize,
    ) -> c_int;
    pub fn fido_cred_set_clientdata_hash(
        cred: *mut fido_cred_t,
        hash: *const c_uchar,
        len: usize,
    ) -> c_int;
    pub fn fido_cred_set_rp(
        cred: *mut fido_cred_t,
        rp_id: *const c_char,
        rp_name: *const c_char,
    ) -> c_int;
    pub fn fido_cred_set_type(cred: *mut fido_cred_t, cose_algorithm: c_int) -> c_int;
    pub fn fido_cred_set_rk(cred: *mut fido_cred_t, option: c_int) -> c_int;
    pub fn fido_cred_set_uv(cred: *mut fido_cred_t, option: c_int) -> c_int;
    pub fn fido_cred_set_user(
        cred: *mut fido_cred_t,
        user_id: *const c_uchar,
        user_id_len: usize,
        name: *const c_char,
        display_name: *const c_char,
        icon: *const c_char,
    ) -> c_int;
    pub fn fido_credman_set_dev_rk(
        dev: *mut fido_dev_t,
        cred: *mut fido_cred_t,
        pin: *const c_char,
    ) -> c_int;
    pub fn fido_credman_del_dev_rk(
        dev: *mut fido_dev_t,
        credential_id: *const c_uchar,
        credential_id_len: usize,
        pin: *const c_char,
    ) -> c_int;
    pub fn fido_dev_make_cred(
        dev: *mut fido_dev_t,
        cred: *mut fido_cred_t,
        pin: *const c_char,
    ) -> c_int;
    pub fn fido_assert_new() -> *mut fido_assert_t;
    pub fn fido_assert_free(value: *mut *mut fido_assert_t);
    pub fn fido_assert_set_rp(value: *mut fido_assert_t, rp_id: *const c_char) -> c_int;
    pub fn fido_assert_set_clientdata_hash(
        value: *mut fido_assert_t,
        hash: *const c_uchar,
        len: usize,
    ) -> c_int;
    pub fn fido_assert_allow_cred(
        value: *mut fido_assert_t,
        credential_id: *const c_uchar,
        len: usize,
    ) -> c_int;
    pub fn fido_assert_set_up(value: *mut fido_assert_t, option: c_int) -> c_int;
    pub fn fido_assert_set_uv(value: *mut fido_assert_t, option: c_int) -> c_int;
    pub fn fido_dev_get_assert(
        dev: *mut fido_dev_t,
        value: *mut fido_assert_t,
        pin: *const c_char,
    ) -> c_int;
    pub fn fido_assert_sig_ptr(value: *const fido_assert_t, index: usize) -> *const c_uchar;
    pub fn fido_assert_sig_len(value: *const fido_assert_t, index: usize) -> usize;
    pub fn fido_assert_flags(value: *const fido_assert_t, index: usize) -> u8;
    pub fn fido_assert_sigcount(value: *const fido_assert_t, index: usize) -> u32;
}

pub fn error_message(code: c_int) -> String {
    unsafe {
        let message = fido_strerr(code);
        if message.is_null() {
            format!("libfido2 error {code}")
        } else {
            CStr::from_ptr(message).to_string_lossy().into_owned()
        }
    }
}

pub fn signing_error_message(code: c_int) -> String {
    match code {
        FIDO_ERR_OPERATION_DENIED | FIDO_ERR_KEEPALIVE_CANCEL => {
            "Touch timed out. No SSH signature was created.".into()
        }
        _ => error_message(code),
    }
}

pub unsafe fn bytes(pointer: *const c_uchar, len: usize) -> Vec<u8> {
    if pointer.is_null() || len == 0 {
        Vec::new()
    } else {
        std::slice::from_raw_parts(pointer, len).to_vec()
    }
}

pub unsafe fn string(pointer: *const c_char) -> Option<String> {
    if pointer.is_null() {
        None
    } else {
        Some(CStr::from_ptr(pointer).to_string_lossy().into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_touch_timeout_codes_to_a_stable_error() {
        assert!(signing_error_message(FIDO_ERR_OPERATION_DENIED).starts_with("Touch timed out."));
        assert!(signing_error_message(FIDO_ERR_KEEPALIVE_CANCEL).starts_with("Touch timed out."));
    }
}
