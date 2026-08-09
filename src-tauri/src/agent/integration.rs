// SPDX-License-Identifier: MPL-2.0

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

const INCLUDE_LINE: &str = "Include ~/.ssh/keynoxis.conf";
const LEGACY_INCLUDE_LINE: &str = "Include ~/.ssh/yubiagent.conf";
const LEGACY_HEADER: &str = "# Managed by YubiAgent.";

pub fn install(home: &Path, socket: &Path) -> Result<(), String> {
    let ssh = home.join(".ssh");
    let integration = ssh.join("keynoxis.conf");
    let socket = shell_quote(socket.to_string_lossy().as_ref());
    fs::write(
        &integration,
        format!("# Managed by Keynoxis.\nHost *\n    IdentityAgent {socket}\n"),
    )
    .map_err(|e| format!("Could not write Keynoxis SSH integration: {e}"))?;
    let _ = fs::set_permissions(&integration, fs::Permissions::from_mode(0o600));

    let config = ssh.join("config");
    let existing = match fs::read_to_string(&config) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(format!("Could not read ~/.ssh/config: {error}")),
    };
    let updated = migrated_config(&existing);
    if updated != existing {
        atomic_write(&config, updated.as_bytes())?;
    }
    let _ = fs::set_permissions(&config, fs::Permissions::from_mode(0o600));
    remove_legacy_integration(&ssh)?;
    Ok(())
}

fn migrated_config(existing: &str) -> String {
    let body = existing
        .lines()
        .filter(|line| {
            let line = line.trim();
            line != INCLUDE_LINE && line != LEGACY_INCLUDE_LINE
        })
        .collect::<Vec<_>>()
        .join("\n")
        .trim_start_matches('\n')
        .to_owned();
    if body.is_empty() {
        format!("{INCLUDE_LINE}\n")
    } else {
        format!("{INCLUDE_LINE}\n\n{body}\n")
    }
}

fn remove_legacy_integration(ssh: &Path) -> Result<(), String> {
    let legacy = ssh.join("yubiagent.conf");
    let contents = match fs::read_to_string(&legacy) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(format!(
                "Could not inspect legacy YubiAgent integration: {error}"
            ))
        }
    };
    if contents.lines().next() == Some(LEGACY_HEADER) {
        fs::remove_file(legacy)
            .map_err(|error| format!("Could not remove legacy YubiAgent integration: {error}"))?;
    }
    Ok(())
}

fn atomic_write(path: &Path, value: &[u8]) -> Result<(), String> {
    let temporary = temporary_path(path);
    fs::write(&temporary, value).map_err(|e| format!("Could not update SSH config: {e}"))?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("Could not secure SSH config: {e}"))?;
    fs::rename(&temporary, path).map_err(|e| format!("Could not install SSH config: {e}"))
}

fn temporary_path(path: &Path) -> PathBuf {
    let mut result = path.as_os_str().to_owned();
    result.push(".keynoxis.tmp");
    PathBuf::from(result)
}

fn shell_quote(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_identity_agent_paths() {
        assert_eq!(shell_quote("/a path/socket"), "\"/a path/socket\"");
    }

    #[test]
    fn migrates_legacy_include_and_keeps_user_configuration() {
        let existing = "Include ~/.ssh/yubiagent.conf\n\nHost work\n    User deploy\n";
        assert_eq!(
            migrated_config(existing),
            "Include ~/.ssh/keynoxis.conf\n\nHost work\n    User deploy\n"
        );
    }

    #[test]
    fn migration_is_idempotent() {
        let config = "Include ~/.ssh/keynoxis.conf\n\nHost *\n    ServerAliveInterval 30\n";
        assert_eq!(migrated_config(config), config);
    }
}
