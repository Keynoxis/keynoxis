// SPDX-License-Identifier: MPL-2.0

use sha2::{Digest, Sha256};
#[cfg(target_os = "macos")]
use std::os::unix::fs::PermissionsExt;
use std::{
    collections::{HashSet, VecDeque},
    env, fs,
    io::Read,
    path::{Path, PathBuf},
    process::Command,
};

fn main() {
    #[cfg(target_os = "macos")]
    {
        let vendored = bundle_macos_libfido2()
            .expect("macOS builds require the pinned native libfido2 dependency set");
        let bridge =
            build_secure_enclave_bridge(vendored.parent().expect("vendored library has a parent"))
                .expect("Secure Enclave bridge requires the Apple Swift compiler");
        stage_cargo_runtime(vendored.parent().expect("vendored library has a parent"))
            .expect("Could not stage native libraries for Cargo dev/test binaries");
        println!("cargo:rustc-link-arg={}", vendored.display());
        println!("cargo:rustc-link-arg={}", bridge.display());
        println!(
            "cargo:rustc-link-search=native={}",
            vendored
                .parent()
                .expect("vendored library has a parent")
                .display()
        );
        println!("cargo:rustc-link-arg=-Wl,-rpath,@executable_path/../Frameworks");
        tauri_build::build();
    }

    #[cfg(not(target_os = "macos"))]
    {
        pkg_config::Config::new()
            .atleast_version("1.13.0")
            .probe("libfido2")
            .expect("libfido2 is required to build Keynoxis");
        tauri_build::build();
    }
}

#[cfg(target_os = "macos")]
fn build_secure_enclave_bridge(output: &Path) -> Option<PathBuf> {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR")?);
    let source = manifest.join("native/SecureEnclaveBridge.swift");
    let destination = output.join("libKeynoxisSecureEnclave.dylib");
    let module_cache = PathBuf::from(env::var_os("OUT_DIR")?).join("swift-module-cache");
    fs::create_dir_all(&module_cache).ok()?;
    println!("cargo:rerun-if-changed={}", source.display());
    let mut command = Command::new("xcrun");
    command
        .args([
            "swiftc",
            "-parse-as-library",
            "-emit-library",
            "-O",
            "-target",
            "arm64-apple-macos26.0",
            "-module-name",
            "KeynoxisSecureEnclave",
            "-Xlinker",
            "-install_name",
            "-Xlinker",
            "@rpath/libKeynoxisSecureEnclave.dylib",
            "-module-cache-path",
        ])
        .arg(&module_cache)
        .arg("-o")
        .arg(&destination)
        .arg(&source);
    command.status().ok()?.success().then_some(())?;
    Command::new("codesign")
        .args(["--force", "--sign", "-"])
        .arg(&destination)
        .status()
        .ok()?
        .success()
        .then_some(())?;
    Some(destination)
}

#[cfg(target_os = "macos")]
fn stage_cargo_runtime(source: &Path) -> Option<()> {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR")?);
    let profile_dir = out_dir.ancestors().nth(3)?;
    let destinations = [profile_dir.to_path_buf(), profile_dir.join("deps")];
    for destination in destinations {
        fs::create_dir_all(&destination).ok()?;
        for entry in fs::read_dir(source).ok()?.flatten() {
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("dylib") {
                continue;
            }
            fs::copy(&path, destination.join(path.file_name()?)).ok()?;
        }
    }
    Some(())
}

#[cfg(target_os = "macos")]
fn bundle_macos_libfido2() -> Option<PathBuf> {
    let roots = [
        Path::new("/opt/homebrew/opt/libfido2/lib/libfido2.dylib"),
        Path::new("/usr/local/opt/libfido2/lib/libfido2.dylib"),
    ];
    let root = roots
        .iter()
        .find(|path| path.exists())?
        .canonicalize()
        .ok()?;
    let output = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR")?).join("vendor/lib");
    println!("cargo:rerun-if-changed=native/macos-dylib-sha256.txt");
    fs::create_dir_all(&output).ok()?;
    for entry in fs::read_dir(&output).ok()?.flatten() {
        if entry.path().extension().and_then(|value| value.to_str()) == Some("dylib") {
            fs::remove_file(entry.path()).ok()?;
        }
    }

    let mut queue = VecDeque::from([root.clone()]);
    let mut seen = HashSet::new();
    let mut root_copy = None;
    while let Some(source) = queue.pop_front() {
        let canonical = source.canonicalize().ok()?;
        if !seen.insert(canonical.clone()) {
            continue;
        }
        let install_name = dylib_lines(&canonical).into_iter().next()?;
        let filename = bundled_name(&install_name)?;
        verify_native_dependency(&canonical, &filename).unwrap_or_else(|error| panic!("{error}"));
        let destination = output.join(&filename);
        fs::copy(&canonical, &destination).ok()?;
        let mut permissions = fs::metadata(&destination).ok()?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&destination, permissions).ok()?;
        run_install_name_tool([
            "-id",
            &format!("@rpath/{}", filename.to_string_lossy()),
            destination.to_str()?,
        ])?;
        if canonical == root {
            root_copy = Some(destination.clone());
        }

        for dependency in dylib_lines(&canonical).into_iter().skip(1) {
            if !dependency.starts_with("/opt/homebrew/") && !dependency.starts_with("/usr/local/") {
                continue;
            }
            let dependency_path = PathBuf::from(&dependency);
            let dependency_name = bundled_name(&dependency)?.to_string_lossy().into_owned();
            run_install_name_tool([
                "-change",
                dependency.as_str(),
                &format!("@rpath/{dependency_name}"),
                destination.to_str()?,
            ])?;
            queue.push_back(dependency_path);
        }
        Command::new("codesign")
            .args(["--force", "--sign", "-", destination.to_str()?])
            .status()
            .ok()?
            .success()
            .then_some(())?;
    }
    root_copy
}

#[cfg(target_os = "macos")]
fn bundled_name(install_name: &str) -> Option<std::ffi::OsString> {
    let filename = Path::new(install_name).file_name()?.to_string_lossy();
    for prefix in ["libfido2", "libcbor", "libcrypto"] {
        if filename.starts_with(prefix) {
            return Some(format!("{prefix}.dylib").into());
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn verify_native_dependency(path: &Path, bundled_name: &std::ffi::OsStr) -> Result<(), String> {
    let manifest = include_str!("native/macos-dylib-sha256.txt");
    let name = bundled_name
        .to_str()
        .ok_or_else(|| "native dependency filename is not UTF-8".to_owned())?;
    let expected = manifest
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            let entry = fields.next()?;
            let hash = fields.next()?;
            (entry == name).then_some(hash)
        })
        .ok_or_else(|| format!("native dependency {name} is not pinned"))?;

    let mut file = fs::File::open(path)
        .map_err(|error| format!("could not hash {}: {error}", path.display()))?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("could not hash {}: {error}", path.display()))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    let actual = format!("{:x}", digest.finalize());
    if actual != expected {
        return Err(format!(
            "native dependency integrity check failed for {}: expected {}, got {}",
            path.display(),
            expected,
            actual
        ));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn dylib_lines(path: &Path) -> Vec<String> {
    let output = match Command::new("otool").arg("-L").arg(path).output() {
        Ok(output) if output.status.success() => output,
        _ => return Vec::new(),
    };
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .skip(1)
        .filter_map(|line| line.trim().split(" (").next().map(str::to_owned))
        .collect()
}

#[cfg(target_os = "macos")]
fn run_install_name_tool<const N: usize>(arguments: [&str; N]) -> Option<()> {
    Command::new("install_name_tool")
        .args(arguments)
        .status()
        .ok()?
        .success()
        .then_some(())
}
