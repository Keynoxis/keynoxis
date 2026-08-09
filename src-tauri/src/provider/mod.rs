// SPDX-License-Identifier: MPL-2.0

use crate::{
    fido, secure_enclave,
    state::{AppState, KeyBackend, RuntimeState, SshKey},
};
use std::sync::MutexGuard;

pub struct HardwareSignature {
    pub signature: Vec<u8>,
    pub provider_fields: Vec<u8>,
}

pub fn sign(
    runtime: &RuntimeState,
    key: &SshKey,
    data: &[u8],
) -> Result<HardwareSignature, String> {
    match key.backend {
        KeyBackend::Fido2 => sign_with_fido2(runtime, key, data),
        KeyBackend::SecureEnclave => {
            let _access = runtime
                .secure_enclave
                .lock()
                .map_err(|_| "Secure Enclave lock failed")?;
            let _signing = runtime
                .signing_gate
                .lock()
                .map_err(|_| "Signing gate failed")?;
            let _authorization = authorize(runtime, key)?;
            Ok(HardwareSignature {
                signature: secure_enclave::sign(key, data)?,
                provider_fields: Vec::new(),
            })
        }
        KeyBackend::Tpm => Err("TPM provider is not implemented yet".into()),
    }
}

fn sign_with_fido2(
    runtime: &RuntimeState,
    key: &SshKey,
    data: &[u8],
) -> Result<HardwareSignature, String> {
    let device_path = key
        .device_path
        .as_deref()
        .ok_or("FIDO2 security key was removed")?;
    let _device_access = runtime.fido.lock().map_err(|_| "FIDO lock failed")?;
    let _signing = runtime
        .signing_gate
        .lock()
        .map_err(|_| "Signing gate failed")?;
    let pins = runtime.pins.lock().map_err(|_| "PIN lock failed")?;
    let pin = pins
        .get(device_path)
        .ok_or("Enter the FIDO2 PIN in Keynoxis")?;
    let _authorization = authorize(runtime, key)?;
    let assertion = fido::sign::sign(device_path, key, data, pin.expose())?;

    let mut provider_fields = Vec::with_capacity(5);
    provider_fields.push(assertion.flags);
    provider_fields.extend_from_slice(&assertion.counter.to_be_bytes());
    Ok(HardwareSignature {
        signature: assertion.signature,
        provider_fields,
    })
}

fn authorize<'a>(
    runtime: &'a RuntimeState,
    requested: &SshKey,
) -> Result<MutexGuard<'a, AppState>, String> {
    let state = runtime.app.lock().map_err(|_| "State lock failed")?;
    if state.agent_locked {
        return Err("Keynoxis SSH Agent is locked".into());
    }
    let still_enabled = state.keys.iter().any(|key| {
        key.enabled
            && key.fingerprint == requested.fingerprint
            && key.public_blob == requested.public_blob
            && key.backend == requested.backend
    });
    if !still_enabled {
        return Err("Requested key is unavailable".into());
    }
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::{mpsc, Arc},
        thread,
        time::Duration,
    };

    fn test_key() -> SshKey {
        SshKey {
            algorithm: "ssh-ed25519".into(),
            public_key: String::new(),
            fingerprint: "SHA256:test".into(),
            comment: None,
            backend: KeyBackend::SecureEnclave,
            enabled: true,
            device_path: None,
            public_blob: vec![1, 2, 3],
            handle: None,
        }
    }

    #[test]
    fn signing_authorization_rejects_lock_and_disabled_key() {
        let runtime = RuntimeState::default();
        let key = test_key();
        runtime.app.lock().unwrap().keys.push(key.clone());
        assert!(authorize(&runtime, &key).is_ok());

        runtime.app.lock().unwrap().agent_locked = true;
        assert_eq!(
            authorize(&runtime, &key).unwrap_err(),
            "Keynoxis SSH Agent is locked"
        );

        let mut state = runtime.app.lock().unwrap();
        state.agent_locked = false;
        state.keys[0].enabled = false;
        drop(state);
        assert_eq!(
            authorize(&runtime, &key).unwrap_err(),
            "Requested key is unavailable"
        );
    }

    #[test]
    fn lock_transition_waits_for_the_signing_gate() {
        let runtime = Arc::new(RuntimeState::default());
        let active_signature = runtime.signing_gate.lock().unwrap();
        let (locked, receiver) = mpsc::channel();
        let lock_runtime = runtime.clone();
        let worker = thread::spawn(move || {
            let _gate = lock_runtime.signing_gate.lock().unwrap();
            lock_runtime.app.lock().unwrap().agent_locked = true;
            locked.send(()).unwrap();
        });

        assert!(receiver.recv_timeout(Duration::from_millis(25)).is_err());
        drop(active_signature);
        receiver.recv_timeout(Duration::from_secs(1)).unwrap();
        worker.join().unwrap();
        assert!(runtime.app.lock().unwrap().agent_locked);
    }
}
