use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, anyhow};
use serde::Deserialize;

#[derive(Deserialize)]
struct LocalState {
    profile: ProfileState,
}

#[derive(Deserialize)]
struct ProfileState {
    info_cache: BTreeMap<String, ProfileInfo>,
}

#[derive(Deserialize)]
struct ProfileInfo {
    #[serde(default)]
    user_name: String,
}

fn local_state_path() -> Result<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let home = std::env::home_dir().context("cannot determine home directory")?;
        Ok(home.join("Library/Application Support/Google/Chrome/Local State"))
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let config = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::home_dir().map(|home| home.join(".config")))
            .context("cannot determine configuration directory")?;
        Ok(config.join("google-chrome/Local State"))
    }
    #[cfg(windows)]
    {
        let local = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .context("LOCALAPPDATA is not set")?;
        Ok(local.join("Google/Chrome/User Data/Local State"))
    }
}

/// Resolves either a Chrome profile directory or a signed-in email.
pub fn resolve(specifier: &str) -> Result<String> {
    resolve_from(&local_state_path()?, specifier)
}

fn resolve_from(path: &Path, specifier: &str) -> Result<String> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading Chrome profile metadata from {}", path.display()))?;
    let state: LocalState = serde_json::from_str(&raw)
        .with_context(|| format!("parsing Chrome profile metadata from {}", path.display()))?;

    if specifier.contains('@') {
        return state
            .profile
            .info_cache
            .iter()
            .find(|(_, info)| info.user_name.eq_ignore_ascii_case(specifier))
            .map(|(directory, _)| directory.clone())
            .ok_or_else(|| anyhow!("no Chrome profile is signed in as {specifier}"));
    }

    state
        .profile
        .info_cache
        .contains_key(specifier)
        .then(|| specifier.to_owned())
        .ok_or_else(|| anyhow!("no Chrome profile directory named '{specifier}'"))
}

pub fn open_in_profile(url: &str, directory: &str) -> Result<()> {
    let flag = format!("--profile-directory={directory}");

    #[cfg(target_os = "macos")]
    let result = Command::new("open")
        .args(["-na", "Google Chrome", "--args", &flag, url])
        .spawn();

    #[cfg(all(unix, not(target_os = "macos")))]
    let result = spawn_first_available(
        &["google-chrome", "google-chrome-stable", "chromium"],
        &[&flag, url],
    );

    #[cfg(windows)]
    let result = {
        let executable = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .map(|path| path.join("Google/Chrome/Application/chrome.exe"))
            .filter(|path| path.exists())
            .unwrap_or_else(|| PathBuf::from("chrome.exe"));
        Command::new(executable).args([&flag, url]).spawn()
    };

    result
        .map(|_| ())
        .with_context(|| format!("starting Chrome profile '{directory}'"))
}

#[cfg(all(unix, not(target_os = "macos")))]
fn spawn_first_available(
    programs: &[&str],
    arguments: &[&str],
) -> std::io::Result<std::process::Child> {
    let mut not_found = None;
    for program in programs {
        match Command::new(program).args(arguments).spawn() {
            Ok(child) => return Ok(child),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => not_found = Some(error),
            Err(error) => return Err(error),
        }
    }
    Err(not_found.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no Chrome-compatible browser found",
        )
    }))
}

pub fn open_default(url: &str) {
    if let Err(error) = webbrowser::open(url) {
        eprintln!("warning: could not open a browser ({error}); open the URL above manually");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local_state() -> (tempfile::TempDir, PathBuf) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("Local State");
        std::fs::write(
            &path,
            r#"{
                "profile": {
                    "info_cache": {
                        "Default": {"user_name": "personal@example.com"},
                        "Profile 2": {"user_name": "Work@Example.com"}
                    }
                }
            }"#,
        )
        .unwrap();
        (directory, path)
    }

    #[test]
    fn resolves_email_case_insensitively() {
        let (_directory, path) = local_state();
        assert_eq!(
            resolve_from(&path, "work@example.com").unwrap(),
            "Profile 2"
        );
    }

    #[test]
    fn validates_explicit_directory_names() {
        let (_directory, path) = local_state();
        assert_eq!(resolve_from(&path, "Default").unwrap(), "Default");
        assert!(resolve_from(&path, "Profile 99").is_err());
    }

    #[test]
    fn malformed_metadata_is_reported() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("Local State");
        std::fs::write(&path, "not json").unwrap();
        let error = resolve_from(&path, "Default").unwrap_err();
        assert!(
            error
                .to_string()
                .contains("parsing Chrome profile metadata")
        );
    }
}
