// SPDX-License-Identifier: MPL-2.0

use crate::{
    provider,
    state::{ActivityCategory, ActivityStatus, KeyBackend, Phase, RuntimeState, SshKey},
};
use signature::Verifier;
use ssh_key::{public::KeyData, Certificate, PublicKey, Signature};
use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
    sync::atomic::Ordering,
    sync::Arc,
    time::Duration,
};
use tauri::Emitter;

const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENT_SUCCESS: u8 = 6;
const SSH2_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH2_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH2_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH2_AGENT_SIGN_RESPONSE: u8 = 14;
const SSH_AGENTC_EXTENSION: u8 = 27;
const SESSION_BIND_EXTENSION: &[u8] = b"session-bind@openssh.com";
const MAX_MESSAGE: usize = 1024 * 1024;
const MAX_SESSION_BINDINGS: usize = 16;
const MAX_SESSION_ID: usize = 128;

#[derive(Default)]
struct ConnectionContext {
    bindings: Vec<SessionBinding>,
    binding_failed: bool,
    forwarded: bool,
}

struct SessionBinding {
    host_key: Vec<u8>,
    session_id: Vec<u8>,
    forwarding: bool,
}

pub fn serve(
    mut stream: UnixStream,
    app: tauri::AppHandle,
    state: Arc<RuntimeState>,
) -> Result<(), String> {
    // macOS may inherit O_NONBLOCK from the listening UNIX socket. Agent
    // clients send several request/reply pairs on one connection, so the
    // accepted stream itself must block between packets.
    stream.set_nonblocking(false).map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(120)))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(120)))
        .map_err(|e| e.to_string())?;
    let mut context = ConnectionContext::default();
    loop {
        let Some(request) = read_message(&mut stream)? else {
            return Ok(());
        };
        let response = handle(&request, &app, &state, &mut context).unwrap_or_else(|error| {
            eprintln!("Keynoxis request failed: {error}");
            vec![SSH_AGENT_FAILURE]
        });
        write_message(&mut stream, &response)?;
    }
}

fn handle(
    request: &[u8],
    app: &tauri::AppHandle,
    runtime: &Arc<RuntimeState>,
    context: &mut ConnectionContext,
) -> Result<Vec<u8>, String> {
    match request.first().copied() {
        Some(SSH2_AGENTC_REQUEST_IDENTITIES) => identities(runtime),
        Some(SSH2_AGENTC_SIGN_REQUEST) => sign_request(&request[1..], app, runtime, context),
        Some(SSH_AGENTC_EXTENSION) => extension(&request[1..], context),
        _ => Ok(vec![SSH_AGENT_FAILURE]),
    }
}

fn extension(request: &[u8], context: &mut ConnectionContext) -> Result<Vec<u8>, String> {
    let mut reader = Reader::new(request);
    if reader.string()? != SESSION_BIND_EXTENSION {
        return Ok(vec![SSH_AGENT_FAILURE]);
    }
    // Once a client attempts session binding, fail closed until a complete,
    // authenticated and consistent binding has been recorded.
    context.binding_failed = true;
    let host_key = reader.string()?;
    let session_id = reader.string()?;
    let signature = reader.string()?;
    let forwarding = reader.byte()?;
    if !reader.is_empty() {
        return Err("Trailing data in SSH session binding".into());
    }
    if session_id.is_empty() || session_id.len() > MAX_SESSION_ID {
        return Err("Invalid SSH session identifier".into());
    }

    let public_key = session_host_key(host_key)?;
    let signature = Signature::try_from(signature).map_err(|_| "Invalid SSH session signature")?;
    Verifier::verify(&public_key, session_id, &signature)
        .map_err(|_| "SSH session signature verification failed")?;

    for binding in &context.bindings {
        if !binding.forwarding {
            return Err("SSH connection was already bound for authentication".into());
        }
        if binding.session_id == session_id {
            if binding.host_key == host_key {
                context.binding_failed = false;
                return Ok(vec![SSH_AGENT_SUCCESS]);
            }
            return Err("SSH session identifier is bound to another host key".into());
        }
    }
    if context.bindings.len() >= MAX_SESSION_BINDINGS {
        return Err("Too many SSH session bindings".into());
    }

    let forwarding = forwarding != 0;
    context.bindings.push(SessionBinding {
        host_key: host_key.to_vec(),
        session_id: session_id.to_vec(),
        forwarding,
    });
    context.forwarded |= forwarding;
    context.binding_failed = false;
    Ok(vec![SSH_AGENT_SUCCESS])
}

fn session_host_key(host_key: &[u8]) -> Result<KeyData, String> {
    if let Ok(key) = PublicKey::from_bytes(host_key) {
        return Ok(key.key_data().clone());
    }
    Certificate::from_bytes(host_key)
        .map(|certificate| certificate.public_key().clone())
        .map_err(|_| "Invalid SSH session host key".into())
}

fn identities(runtime: &RuntimeState) -> Result<Vec<u8>, String> {
    let state = runtime.app.lock().map_err(|_| "State lock failed")?;
    if state.agent_locked {
        return Ok(vec![SSH2_AGENT_IDENTITIES_ANSWER, 0, 0, 0, 0]);
    }
    let preferred_backend = runtime.preferred_backend.load(Ordering::Acquire);
    let mut keys = state
        .keys
        .iter()
        .filter(|key| key.enabled)
        .collect::<Vec<_>>();
    keys.sort_by(|left, right| {
        backend_priority(preferred_backend, &left.backend)
            .cmp(&backend_priority(preferred_backend, &right.backend))
            .then_with(|| {
                left.comment
                    .as_deref()
                    .unwrap_or("")
                    .to_lowercase()
                    .cmp(&right.comment.as_deref().unwrap_or("").to_lowercase())
            })
    });
    let mut response = vec![SSH2_AGENT_IDENTITIES_ANSWER];
    response.extend_from_slice(&(keys.len() as u32).to_be_bytes());
    for key in keys {
        put_string(&mut response, &key.public_blob);
        put_string(
            &mut response,
            key.comment
                .as_deref()
                .unwrap_or("Hardware-backed SSH key")
                .as_bytes(),
        );
    }
    Ok(response)
}

fn backend_priority(preferred_backend: u64, backend: &KeyBackend) -> u8 {
    match (preferred_backend, backend) {
        (0, KeyBackend::SecureEnclave) | (1, KeyBackend::Fido2) => 0,
        _ => 1,
    }
}

fn sign_request(
    request: &[u8],
    app: &tauri::AppHandle,
    runtime: &Arc<RuntimeState>,
    context: &ConnectionContext,
) -> Result<Vec<u8>, String> {
    if runtime
        .app
        .lock()
        .map_err(|_| "State lock failed")?
        .agent_locked
    {
        return Err("Keynoxis SSH Agent is locked".into());
    }
    let mut reader = Reader::new(request);
    let requested_blob = reader.string()?;
    let data = reader.string()?;
    let _requested_flags = reader.u32()?;
    if !reader.is_empty() {
        return Err("Trailing data in SSH signature request".into());
    }
    if context.binding_failed || context.forwarded {
        crate::activity::record(
            app,
            runtime,
            ActivityCategory::Signing,
            ActivityStatus::Warning,
            "Forwarded SSH signature blocked",
            Some(if context.binding_failed {
                "An SSH session binding failed authentication".into()
            } else {
                "Keynoxis does not allow agent forwarding".into()
            }),
        );
        return Err(if context.binding_failed {
            "SSH session binding failed authentication".into()
        } else {
            "Agent forwarding is blocked by Keynoxis".into()
        });
    }

    let auth_generation = runtime.auth_dismiss_generation.load(Ordering::Acquire);
    let key = {
        let mut current = runtime.app.lock().map_err(|_| "State lock failed")?;
        let key = find_key(&current.keys, requested_blob)?.ok_or("Requested key is unavailable")?;
        if key.backend == KeyBackend::Fido2 {
            let device_path = key
                .device_path
                .as_deref()
                .ok_or("FIDO2 security key was removed")?;
            let session_unlocked = runtime
                .pins
                .lock()
                .map_err(|_| "PIN lock failed")?
                .contains_key(device_path);
            current.device = current
                .devices
                .iter()
                .find(|device| device.path == device_path)
                .cloned();
            current.phase = if session_unlocked {
                Phase::WaitingForTouch
            } else {
                Phase::NeedsPin
            };
            current.error = None;
            let snapshot = current.clone();
            drop(current);
            crate::update_tray(app, &snapshot);
            let _ = app.emit("state-changed", snapshot);
            crate::show_auth(app);
        }
        key
    };

    let result = provider::sign(runtime, &key, data);
    if key.backend == KeyBackend::Fido2 && result.is_ok() {
        crate::settings::mark_fido_activity(runtime);
    }
    let key_name = key.comment.as_deref().unwrap_or("Unnamed SSH identity");
    let backend = match key.backend {
        KeyBackend::Fido2 => "FIDO2",
        KeyBackend::SecureEnclave => "Secure Enclave",
        KeyBackend::Tpm => "TPM",
    };
    crate::activity::record(
        app,
        runtime,
        ActivityCategory::Signing,
        if result.is_ok() {
            ActivityStatus::Success
        } else {
            ActivityStatus::Error
        },
        if result.is_ok() {
            "SSH signature completed"
        } else {
            "SSH signature failed"
        },
        Some(match result.as_ref() {
            Ok(_) => format!("{key_name} · {backend}"),
            Err(error) => format!("{key_name} · {error}"),
        }),
    );

    if key.backend != KeyBackend::Fido2 {
        if let Err(error) = &result {
            let mut current = runtime.app.lock().map_err(|_| "State lock failed")?;
            current.phase = Phase::Error;
            current.error = Some(error.clone());
            let snapshot = current.clone();
            drop(current);
            crate::update_tray(app, &snapshot);
            let _ = app.emit("state-changed", snapshot);
        }
        return signature_response(&key, result?);
    }

    let dismissed = runtime.auth_dismiss_generation.load(Ordering::Acquire) != auth_generation;
    let needs_pin = result
        .as_ref()
        .err()
        .is_some_and(|error| error == "Enter the FIDO2 PIN in Keynoxis");
    let mut current = runtime.app.lock().map_err(|_| "State lock failed")?;
    current.phase = if needs_pin {
        Phase::NeedsPin
    } else if result.is_ok() || dismissed {
        Phase::Ready
    } else {
        Phase::Error
    };
    current.error = if dismissed || needs_pin {
        None
    } else {
        result.as_ref().err().cloned()
    };
    let snapshot = current.clone();
    drop(current);
    crate::update_tray(app, &snapshot);
    let _ = app.emit("state-changed", snapshot);

    if result.is_ok() || dismissed {
        crate::hide_auth(app);
    } else {
        crate::show_auth(app);
    }

    signature_response(&key, result?)
}

fn signature_response(
    key: &SshKey,
    signature: provider::HardwareSignature,
) -> Result<Vec<u8>, String> {
    let mut signature_blob = Vec::new();
    put_string(&mut signature_blob, key.algorithm.as_bytes());
    put_string(&mut signature_blob, &signature.signature);
    signature_blob.extend_from_slice(&signature.provider_fields);

    let mut response = vec![SSH2_AGENT_SIGN_RESPONSE];
    put_string(&mut response, &signature_blob);
    Ok(response)
}

fn find_key(keys: &[SshKey], requested_blob: &[u8]) -> Result<Option<SshKey>, String> {
    for key in keys {
        if key.enabled && key.public_blob == requested_blob {
            return Ok(Some(key.clone()));
        }
    }
    Ok(None)
}

fn read_message(stream: &mut UnixStream) -> Result<Option<Vec<u8>>, String> {
    let mut length = [0u8; 4];
    match stream.read_exact(&mut length) {
        Ok(()) => {}
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::BrokenPipe
            ) =>
        {
            return Ok(None)
        }
        Err(error) => return Err(error.to_string()),
    }
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_MESSAGE {
        return Err("Invalid SSH agent message length".into());
    }
    let mut request = vec![0; length];
    stream.read_exact(&mut request).map_err(|e| e.to_string())?;
    Ok(Some(request))
}

fn write_message(stream: &mut UnixStream, response: &[u8]) -> Result<(), String> {
    stream
        .write_all(&(response.len() as u32).to_be_bytes())
        .and_then(|_| stream.write_all(response))
        .map_err(|e| e.to_string())
}

fn put_string(target: &mut Vec<u8>, value: &[u8]) {
    target.extend_from_slice(&(value.len() as u32).to_be_bytes());
    target.extend_from_slice(value);
}

struct Reader<'a> {
    value: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(value: &'a [u8]) -> Self {
        Self { value, at: 0 }
    }

    fn u32(&mut self) -> Result<u32, String> {
        let bytes: [u8; 4] = self
            .value
            .get(self.at..self.at + 4)
            .ok_or("Truncated SSH agent message")?
            .try_into()
            .map_err(|_| "Invalid SSH agent integer")?;
        self.at += 4;
        Ok(u32::from_be_bytes(bytes))
    }

    fn byte(&mut self) -> Result<u8, String> {
        let result = *self
            .value
            .get(self.at)
            .ok_or("Truncated SSH agent message")?;
        self.at += 1;
        Ok(result)
    }

    fn string(&mut self) -> Result<&'a [u8], String> {
        let length = self.u32()? as usize;
        let result = self
            .value
            .get(self.at..self.at + length)
            .ok_or("Truncated SSH agent string")?;
        self.at += length;
        Ok(result)
    }

    fn is_empty(&self) -> bool {
        self.at == self.value.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use signature::Signer;
    use ssh_key::{private::Ed25519Keypair, PrivateKey};

    fn session_binding(session_id: &[u8], forwarding: bool) -> Vec<u8> {
        let private = PrivateKey::from(Ed25519Keypair::from_seed(&[42; 32]));
        let host_key = private.public_key().to_bytes().unwrap();
        let signature = Vec::<u8>::try_from(private.try_sign(session_id).unwrap()).unwrap();
        let mut request = Vec::new();
        put_string(&mut request, SESSION_BIND_EXTENSION);
        put_string(&mut request, &host_key);
        put_string(&mut request, session_id);
        put_string(&mut request, &signature);
        request.push(u8::from(forwarding));
        request
    }

    #[test]
    fn reader_rejects_truncated_strings() {
        let mut reader = Reader::new(&[0, 0, 0, 8, 1]);
        assert!(reader.string().is_err());
    }

    #[test]
    fn accepts_authenticated_session_binding() {
        let request = session_binding(b"session", false);
        let mut context = ConnectionContext::default();
        assert_eq!(
            extension(&request, &mut context).unwrap(),
            vec![SSH_AGENT_SUCCESS]
        );
        assert_eq!(context.bindings.len(), 1);
        assert!(!context.binding_failed);
        assert!(!context.forwarded);
    }

    #[test]
    fn rejects_forged_session_binding_and_fails_closed() {
        let mut request = session_binding(b"session", false);
        let signature_byte = request.len() - 2;
        request[signature_byte] ^= 0x01;
        let mut context = ConnectionContext::default();
        assert!(extension(&request, &mut context).is_err());
        assert!(context.binding_failed);
        assert!(context.bindings.is_empty());
    }

    #[test]
    fn forwarded_binding_is_sticky_across_duplicate_messages() {
        let mut context = ConnectionContext::default();
        extension(&session_binding(b"session", true), &mut context).unwrap();
        extension(&session_binding(b"session", false), &mut context).unwrap();
        assert!(context.forwarded);
        assert_eq!(context.bindings.len(), 1);
    }

    #[test]
    fn authentication_binding_rejects_a_second_hop() {
        let mut context = ConnectionContext::default();
        extension(&session_binding(b"auth-session", false), &mut context).unwrap();
        assert!(extension(&session_binding(b"next-session", true), &mut context).is_err());
        assert!(context.binding_failed);
    }

    #[test]
    fn prioritizes_secure_enclave_when_this_mac_is_preferred() {
        assert!(
            backend_priority(0, &KeyBackend::SecureEnclave)
                < backend_priority(0, &KeyBackend::Fido2)
        );
    }

    #[test]
    fn prioritizes_fido2_when_security_key_is_preferred() {
        assert!(
            backend_priority(1, &KeyBackend::Fido2)
                < backend_priority(1, &KeyBackend::SecureEnclave)
        );
    }

    #[test]
    fn locked_agent_exposes_no_identities() {
        let runtime = RuntimeState::default();
        runtime.app.lock().unwrap().agent_locked = true;
        assert_eq!(
            identities(&runtime).unwrap(),
            vec![SSH2_AGENT_IDENTITIES_ANSWER, 0, 0, 0, 0]
        );
    }
}
