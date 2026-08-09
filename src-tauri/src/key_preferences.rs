// SPDX-License-Identifier: MPL-2.0

use crate::state::SshKey;
use std::{collections::BTreeSet, fs, os::unix::fs::PermissionsExt, path::PathBuf};
use tauri::{AppHandle, Manager};

const FILE_NAME: &str = "key-preferences.json";

pub fn apply(app: &AppHandle, keys: &mut [SshKey]) -> Result<(), String> {
    let disabled = read(app)?;
    for key in keys {
        key.enabled = !disabled.contains(&key.fingerprint);
    }
    Ok(())
}

pub fn set_enabled(app: &AppHandle, fingerprint: &str, enabled: bool) -> Result<(), String> {
    let mut disabled = read(app)?;
    if enabled {
        disabled.remove(fingerprint);
    } else {
        disabled.insert(fingerprint.to_owned());
    }
    write(app, &disabled)
}

fn path(app: &AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_data_dir()
        .map(|directory| directory.join(FILE_NAME))
        .map_err(|error| format!("Could not resolve key preferences directory: {error}"))
}

fn read(app: &AppHandle) -> Result<BTreeSet<String>, String> {
    match fs::read(path(app)?) {
        Ok(data) => serde_json::from_slice(&data)
            .map_err(|error| format!("Key preferences are invalid: {error}")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(BTreeSet::new()),
        Err(error) => Err(format!("Could not read key preferences: {error}")),
    }
}

fn write(app: &AppHandle, disabled: &BTreeSet<String>) -> Result<(), String> {
    let path = path(app)?;
    let parent = path.parent().ok_or("Invalid key preferences directory")?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("Could not create key preferences directory: {error}"))?;
    let temporary = path.with_extension("json.tmp");
    let data = serde_json::to_vec_pretty(disabled)
        .map_err(|error| format!("Could not encode key preferences: {error}"))?;
    fs::write(&temporary, data)
        .map_err(|error| format!("Could not save key preferences: {error}"))?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("Could not secure key preferences: {error}"))?;
    fs::rename(&temporary, path)
        .map_err(|error| format!("Could not commit key preferences: {error}"))
}
