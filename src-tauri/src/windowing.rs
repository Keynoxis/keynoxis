// SPDX-License-Identifier: MPL-2.0

use crate::state::{Phase, RuntimeState};
use std::sync::Arc;
use tauri::{LogicalPosition, LogicalSize, Manager, PhysicalPosition, WebviewWindow};

pub fn show_auth(app: &tauri::AppHandle) {
    let Some(window) = app.get_webview_window("auth") else {
        return;
    };
    let phase = app
        .state::<Arc<RuntimeState>>()
        .app
        .try_lock()
        .map(|state| state.phase.clone())
        .unwrap_or(Phase::NeedsPin);
    let logical_height = match phase {
        Phase::WaitingForTouch => 270.0,
        Phase::Error => 260.0,
        Phase::WaitingForDevice => 250.0,
        _ => 350.0,
    };
    let _ = window.set_size(LogicalSize::new(380.0, logical_height));
    position_near_focused_window(&window, 380.0, logical_height);
    let _ = window.show();
    let _ = window.unminimize();
    let _ = window.set_focus();
}

fn position_near_focused_window(window: &WebviewWindow, width: f64, height: f64) {
    if let Some((x, y)) = focused_display_center() {
        let _ = window.set_position(LogicalPosition::new(x - width / 2.0, y - height / 2.0));
        return;
    }

    let cursor = window.cursor_position().ok();
    let monitors = window.available_monitors().unwrap_or_default();
    let monitor = cursor
        .as_ref()
        .and_then(|point| monitors.iter().find(|monitor| contains(monitor, point)))
        .cloned()
        .or_else(|| window.primary_monitor().ok().flatten());
    if let Some(monitor) = monitor {
        let area = monitor.work_area();
        let scale = monitor.scale_factor();
        let physical_width = width * scale;
        let physical_height = height * scale;
        let x = area.position.x as f64 + (area.size.width as f64 - physical_width) / 2.0;
        let y = area.position.y as f64 + (area.size.height as f64 - physical_height) / 2.0;
        let _ = window.set_position(PhysicalPosition::new(x.round() as i32, y.round() as i32));
    } else {
        let _ = window.center();
    }
}

#[cfg(target_os = "macos")]
fn focused_display_center() -> Option<(f64, f64)> {
    use core_graphics::display::CGDisplay;

    let (window_x, window_y) = frontmost_window_center()?;
    for id in CGDisplay::active_displays().ok()? {
        let bounds = CGDisplay::new(id).bounds();
        let min_x = bounds.origin.x;
        let min_y = bounds.origin.y;
        let max_x = min_x + bounds.size.width;
        let max_y = min_y + bounds.size.height;
        if window_x >= min_x && window_x < max_x && window_y >= min_y && window_y < max_y {
            return Some((
                min_x + bounds.size.width / 2.0,
                min_y + bounds.size.height / 2.0,
            ));
        }
    }
    None
}

#[cfg(not(target_os = "macos"))]
fn focused_display_center() -> Option<(f64, f64)> {
    None
}

fn contains(monitor: &tauri::Monitor, point: &PhysicalPosition<f64>) -> bool {
    let position = monitor.position();
    let size = monitor.size();
    point.x >= position.x as f64
        && point.x < position.x as f64 + size.width as f64
        && point.y >= position.y as f64
        && point.y < position.y as f64 + size.height as f64
}

#[cfg(target_os = "macos")]
fn frontmost_window_center() -> Option<(f64, f64)> {
    use core_foundation::{
        base::{CFType, CFTypeRef, TCFType},
        dictionary::CFDictionary,
    };
    use core_graphics::window::{
        copy_window_info, kCGNullWindowID, kCGWindowBounds, kCGWindowLayer,
        kCGWindowListExcludeDesktopElements, kCGWindowListOptionOnScreenOnly,
    };
    let windows = copy_window_info(
        kCGWindowListOptionOnScreenOnly | kCGWindowListExcludeDesktopElements,
        kCGNullWindowID,
    )?;

    for item in windows.iter() {
        let value = unsafe { CFType::wrap_under_get_rule(*item as CFTypeRef) };
        let Some(dictionary) = value.downcast::<CFDictionary>() else {
            continue;
        };
        if number_for_static_key(&dictionary, unsafe { kCGWindowLayer }).unwrap_or(0.0) != 0.0 {
            continue;
        }
        let bounds = type_for_static_key(&dictionary, unsafe { kCGWindowBounds })?
            .downcast::<CFDictionary>()?;
        let x = number_for_key(&bounds, "X")?;
        let y = number_for_key(&bounds, "Y")?;
        let width = number_for_key(&bounds, "Width")?;
        let height = number_for_key(&bounds, "Height")?;
        if width >= 100.0 && height >= 80.0 {
            return Some((x + width / 2.0, y + height / 2.0));
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn type_for_static_key(
    dictionary: &core_foundation::dictionary::CFDictionary,
    key: core_foundation::string::CFStringRef,
) -> Option<core_foundation::base::CFType> {
    use core_foundation::base::{CFTypeRef, TCFType};
    let value = dictionary.find(key as *const std::ffi::c_void)?;
    Some(unsafe { core_foundation::base::CFType::wrap_under_get_rule(*value as CFTypeRef) })
}

#[cfg(target_os = "macos")]
fn number_for_static_key(
    dictionary: &core_foundation::dictionary::CFDictionary,
    key: core_foundation::string::CFStringRef,
) -> Option<f64> {
    use core_foundation::number::CFNumber;
    type_for_static_key(dictionary, key)?
        .downcast::<CFNumber>()?
        .to_f64()
}

#[cfg(target_os = "macos")]
fn number_for_key(
    dictionary: &core_foundation::dictionary::CFDictionary,
    key: &str,
) -> Option<f64> {
    use core_foundation::{
        base::{CFType, CFTypeRef, TCFType},
        number::CFNumber,
        string::CFString,
    };
    let key = CFString::new(key);
    let value = dictionary.find(key.as_CFTypeRef() as *const std::ffi::c_void)?;
    unsafe { CFType::wrap_under_get_rule(*value as CFTypeRef) }
        .downcast::<CFNumber>()?
        .to_f64()
}

#[cfg(not(target_os = "macos"))]
fn frontmost_window_center() -> Option<(f64, f64)> {
    None
}
