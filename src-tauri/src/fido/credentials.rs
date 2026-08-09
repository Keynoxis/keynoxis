// SPDX-License-Identifier: MPL-2.0

use crate::state::SshKey;
use base64::{engine::general_purpose::STANDARD, Engine};
use sha2::{Digest, Sha256};

pub const ED25519_SK: &str = "sk-ssh-ed25519@openssh.com";
pub const ECDSA_SK: &str = "sk-ecdsa-sha2-nistp256@openssh.com";

pub fn public_blob(
    algorithm: &str,
    public_key: &[u8],
    application: &str,
) -> Result<Vec<u8>, String> {
    let mut blob = Vec::new();
    put_string(&mut blob, algorithm.as_bytes());
    match algorithm {
        ED25519_SK => put_string(&mut blob, public_key),
        ECDSA_SK => {
            put_string(&mut blob, b"nistp256");
            let point = ecdsa_point(public_key)?;
            put_string(&mut blob, &point);
        }
        _ => {
            return Err(format!(
                "Unsupported SSH security-key algorithm: {algorithm}"
            ))
        }
    }
    put_string(&mut blob, application.as_bytes());
    Ok(blob)
}

pub fn finish(mut key: SshKey) -> Result<SshKey, String> {
    let handle = key.fido2()?;
    let blob = public_blob(
        &key.algorithm,
        &handle.public_key_bytes,
        &handle.application,
    )?;
    let digest = Sha256::digest(&blob);
    key.fingerprint = format!("SHA256:{}", STANDARD.encode(digest).trim_end_matches('='));
    let comment = key
        .comment
        .clone()
        .unwrap_or_else(|| "FIDO2 resident key".into());
    key.public_key = format!("{} {} {}", key.algorithm, STANDARD.encode(&blob), comment);
    key.public_blob = blob;
    Ok(key)
}

pub(crate) fn ecdsa_point(value: &[u8]) -> Result<Vec<u8>, String> {
    match value.len() {
        65 if value[0] == 4 => Ok(value.to_vec()),
        64 => {
            let mut point = Vec::with_capacity(65);
            point.push(4);
            point.extend_from_slice(value);
            Ok(point)
        }
        size => Err(format!("Invalid ES256 public key length: {size}")),
    }
}

pub(crate) fn put_string(target: &mut Vec<u8>, value: &[u8]) {
    target.extend_from_slice(&(value.len() as u32).to_be_bytes());
    target.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_ed25519_public_blob() {
        let blob = public_blob(ED25519_SK, &[7; 32], "ssh:test").unwrap();
        assert!(blob
            .windows(ED25519_SK.len())
            .any(|w| w == ED25519_SK.as_bytes()));
        assert!(blob.ends_with(b"ssh:test"));
    }

    #[test]
    fn prefixes_raw_ecdsa_coordinates() {
        let point = ecdsa_point(&[9; 64]).unwrap();
        assert_eq!(point.len(), 65);
        assert_eq!(point[0], 4);
    }
}
