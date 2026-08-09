// SPDX-License-Identifier: MPL-2.0

use base64::{engine::general_purpose::STANDARD, Engine};
use sha2::{Digest, Sha256};

pub const ECDSA_P256: &str = "ecdsa-sha2-nistp256";

pub fn ecdsa_public_blob(point: &[u8]) -> Result<Vec<u8>, String> {
    if point.len() != 65 || point[0] != 4 {
        return Err("Secure Enclave returned an invalid P-256 public key".into());
    }
    let mut blob = Vec::new();
    put_string(&mut blob, ECDSA_P256.as_bytes());
    put_string(&mut blob, b"nistp256");
    put_string(&mut blob, point);
    Ok(blob)
}

pub fn public_line_and_fingerprint(blob: &[u8], algorithm: &str, name: &str) -> (String, String) {
    let digest = Sha256::digest(blob);
    let fingerprint = format!("SHA256:{}", STANDARD.encode(digest).trim_end_matches('='));
    let public_key = format!("{algorithm} {} {name}", STANDARD.encode(blob));
    (public_key, fingerprint)
}

pub fn der_ecdsa_to_ssh(der: &[u8]) -> Result<Vec<u8>, String> {
    let mut at = 0;
    expect_tag(der, &mut at, 0x30)?;
    let sequence_len = read_der_len(der, &mut at)?;
    if at + sequence_len != der.len() {
        return Err("Invalid ECDSA signature sequence".into());
    }
    expect_tag(der, &mut at, 0x02)?;
    let r_len = read_der_len(der, &mut at)?;
    let r = der.get(at..at + r_len).ok_or("Invalid ECDSA r value")?;
    at += r_len;
    expect_tag(der, &mut at, 0x02)?;
    let s_len = read_der_len(der, &mut at)?;
    let s = der.get(at..at + s_len).ok_or("Invalid ECDSA s value")?;

    let mut result = Vec::new();
    put_mpint(&mut result, r);
    put_mpint(&mut result, s);
    Ok(result)
}

pub(crate) fn put_string(target: &mut Vec<u8>, value: &[u8]) {
    target.extend_from_slice(&(value.len() as u32).to_be_bytes());
    target.extend_from_slice(value);
}

fn expect_tag(data: &[u8], at: &mut usize, expected: u8) -> Result<(), String> {
    if data.get(*at) != Some(&expected) {
        return Err("Invalid DER ECDSA signature".into());
    }
    *at += 1;
    Ok(())
}

fn read_der_len(data: &[u8], at: &mut usize) -> Result<usize, String> {
    let first = *data.get(*at).ok_or("Truncated DER signature")?;
    *at += 1;
    if first & 0x80 == 0 {
        return Ok(first as usize);
    }
    let count = (first & 0x7f) as usize;
    if count == 0 || count > 2 || *at + count > data.len() {
        return Err("Invalid DER signature length".into());
    }
    let mut length = 0usize;
    for byte in &data[*at..*at + count] {
        length = (length << 8) | *byte as usize;
    }
    *at += count;
    Ok(length)
}

fn put_mpint(target: &mut Vec<u8>, value: &[u8]) {
    let first_nonzero = value
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(value.len());
    let value = &value[first_nonzero..];
    let needs_zero = value.first().is_some_and(|byte| byte & 0x80 != 0);
    target.extend_from_slice(&((value.len() + usize::from(needs_zero)) as u32).to_be_bytes());
    if needs_zero {
        target.push(0);
    }
    target.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_plain_ecdsa_public_key() {
        let mut point = vec![7; 65];
        point[0] = 4;
        let blob = ecdsa_public_blob(&point).unwrap();
        assert!(blob
            .windows(ECDSA_P256.len())
            .any(|value| value == ECDSA_P256.as_bytes()));
    }

    #[test]
    fn converts_der_ecdsa_signature_to_two_mpints() {
        let der = [0x30, 0x08, 0x02, 0x02, 0x00, 0x80, 0x02, 0x02, 0x01, 0x02];
        let ssh = der_ecdsa_to_ssh(&der).unwrap();
        assert_eq!(&ssh[0..4], &2u32.to_be_bytes());
        assert_eq!(&ssh[4..6], &[0, 0x80]);
    }
}
