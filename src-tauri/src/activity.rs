// SPDX-License-Identifier: MPL-2.0

use crate::state::{ActivityCategory, ActivityEntry, ActivityStatus, RuntimeState};
use std::{
    collections::VecDeque,
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::{atomic::Ordering, Arc},
    time::{SystemTime, UNIX_EPOCH},
};
use tauri::{Emitter, Manager};

const MAX_ACTIVITY_ENTRIES: usize = 2_000;
const ACTIVITY_FILE: &str = "activity.json";

pub fn initialize(app: &tauri::AppHandle, runtime: &RuntimeState) -> Result<(), String> {
    let path = activity_path(app)?;
    let entries = match fs::read(&path) {
        Ok(data) => serde_json::from_slice::<VecDeque<ActivityEntry>>(&data)
            .map_err(|error| format!("Activity log is invalid: {error}"))?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => VecDeque::new(),
        Err(error) => return Err(format!("Could not read activity log: {error}")),
    };
    let next_id = entries
        .front()
        .map_or(1, |entry| entry.id.saturating_add(1));
    runtime.next_activity_id.store(next_id, Ordering::Release);
    *runtime
        .activity
        .lock()
        .map_err(|_| "Activity log lock failed")? = entries;
    Ok(())
}

pub fn record(
    app: &tauri::AppHandle,
    runtime: &Arc<RuntimeState>,
    category: ActivityCategory,
    status: ActivityStatus,
    title: impl Into<String>,
    detail: Option<String>,
) {
    let entry = ActivityEntry {
        id: runtime.next_activity_id.fetch_add(1, Ordering::Relaxed),
        timestamp_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64,
        category,
        status,
        title: title.into(),
        detail,
    };

    if let Ok(mut activity) = runtime.activity.lock() {
        activity.push_front(entry.clone());
        activity.truncate(MAX_ACTIVITY_ENTRIES);
        let _ = persist(app, &activity);
    }
    let _ = app.emit("activity-added", entry);
}

pub fn list(runtime: &RuntimeState) -> Result<Vec<ActivityEntry>, String> {
    runtime
        .activity
        .lock()
        .map(|activity| activity.iter().cloned().collect())
        .map_err(|_| "Activity log lock failed".into())
}

pub fn clear(app: &tauri::AppHandle, runtime: &RuntimeState) -> Result<(), String> {
    let mut activity = runtime
        .activity
        .lock()
        .map_err(|_| "Activity log lock failed")?;
    activity.clear();
    persist(app, &activity)
}

fn activity_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_data_dir()
        .map(|directory| directory.join(ACTIVITY_FILE))
        .map_err(|error| format!("Could not resolve activity directory: {error}"))
}

fn persist(app: &tauri::AppHandle, activity: &VecDeque<ActivityEntry>) -> Result<(), String> {
    let path = activity_path(app)?;
    let parent = path.parent().ok_or("Invalid activity log directory")?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("Could not create activity directory: {error}"))?;
    let temporary = path.with_extension("json.tmp");
    let data = serde_json::to_vec_pretty(activity)
        .map_err(|error| format!("Could not encode activity log: {error}"))?;
    fs::write(&temporary, data).map_err(|error| format!("Could not save activity log: {error}"))?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("Could not secure activity log: {error}"))?;
    fs::rename(&temporary, path).map_err(|error| format!("Could not commit activity log: {error}"))
}
