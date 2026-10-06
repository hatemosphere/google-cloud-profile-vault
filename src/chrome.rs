use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, anyhow};
use serde::Deserialize;

use crate::diagnostics::debug;

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

/// Uses an explicit profile when configured, otherwise best-effort matches the
/// expected account. Failure to auto-match falls back to the system browser.
pub fn select_profile(explicit: Option<&str>, account: Option<&str>) -> Result<Option<String>> {
    select_profile_using(explicit, account, || load(&local_state_path()?))
}

fn select_profile_using(
    explicit: Option<&str>,
    account: Option<&str>,
    load: impl FnOnce() -> Result<LocalState>,
) -> Result<Option<String>> {
    if let Some(specifier) = explicit {
        let directory = match load() {
            Ok(state) => lookup(&state, specifier)?,
            // Chrome's data directory can be unreadable (macOS protects
            // browser data); a directory name needs no lookup, so trust it.
            Err(error) if !specifier.contains('@') => {
                eprintln!(
                    "warning: cannot verify Chrome profile '{specifier}' ({error:#}); passing it to Chrome unchecked"
                );
                specifier.to_owned()
            }
            Err(error) => {
                return Err(error.context(format!(
                    "cannot find the Chrome profile for {specifier}; {DIRECTORY_HINT}"
                )));
            }
        };
        debug!("using explicitly configured Chrome profile '{directory}'");
        return Ok(Some(directory));
    }
    let Some(email) = account else {
        debug!("no account or Chrome profile configured; using the system browser");
        return Ok(None);
    };
    let state = match load() {
        Ok(state) => state,
        Err(error) => {
            let chrome_absent = error
                .root_cause()
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound);
            if chrome_absent {
                debug!("no Chrome profile metadata ({error:#}); using the system browser");
            } else {
                eprintln!(
                    "warning: cannot match {email} to a Chrome profile ({error:#}); using the system browser. To fix, {DIRECTORY_HINT}"
                );
            }
            return Ok(None);
        }
    };
    match lookup(&state, email) {
        Ok(directory) => {
            debug!("matched account to Chrome profile '{directory}'");
            Ok(Some(directory))
        }
        Err(error) => {
            debug!("Chrome profile auto-match failed ({error:#}); using the system browser");
            Ok(None)
        }
    }
}

const DIRECTORY_HINT: &str = "on macOS grant your terminal Full Disk Access (System Settings > Privacy & Security), or pass --browser-profile with the directory name from chrome://version (last part of Profile Path), e.g. \"Profile 2\"";

fn load(path: &Path) -> Result<LocalState> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading Chrome profile metadata from {}", path.display()))?;
    serde_json::from_str(&raw)
        .with_context(|| format!("parsing Chrome profile metadata from {}", path.display()))
}

/// Resolves either a Chrome profile directory or a signed-in email.
fn lookup(state: &LocalState, specifier: &str) -> Result<String> {
    let profiles = &state.profile.info_cache;
    if specifier.contains('@') {
        return profiles
            .iter()
            .find(|(_, info)| info.user_name.eq_ignore_ascii_case(specifier))
            .map(|(directory, _)| directory.clone())
            .ok_or_else(|| anyhow!("no Chrome profile is signed in as {specifier}"));
    }
    profiles
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

    fn unreadable() -> Result<LocalState> {
        Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
            .context("reading Chrome profile metadata")
    }

    #[test]
    fn resolves_email_case_insensitively() {
        let (_directory, path) = local_state();
        let state = load(&path).unwrap();
        assert_eq!(lookup(&state, "work@example.com").unwrap(), "Profile 2");
    }

    #[test]
    fn validates_explicit_directory_names() {
        let (_directory, path) = local_state();
        let state = load(&path).unwrap();
        assert_eq!(lookup(&state, "Default").unwrap(), "Default");
        assert!(lookup(&state, "Profile 99").is_err());
    }

    #[test]
    fn automatically_selects_the_profile_for_the_expected_account() {
        let (_directory, path) = local_state();
        let selected =
            select_profile_using(None, Some("work@example.com"), || load(&path)).unwrap();
        assert_eq!(selected.as_deref(), Some("Profile 2"));
    }

    #[test]
    fn automatic_selection_falls_back_but_explicit_selection_fails_closed() {
        let (_directory, path) = local_state();

        assert_eq!(
            select_profile_using(None, Some("missing@example.com"), || load(&path)).unwrap(),
            None
        );
        assert!(
            select_profile_using(
                Some("missing@example.com"),
                Some("work@example.com"),
                || load(&path)
            )
            .is_err()
        );
    }

    #[test]
    fn unreadable_metadata_trusts_a_directory_name_but_cannot_resolve_an_email() {
        assert_eq!(
            select_profile_using(Some("Profile 4"), None, unreadable).unwrap(),
            Some("Profile 4".to_owned())
        );
        let error = select_profile_using(Some("work@example.com"), None, unreadable).unwrap_err();
        assert!(format!("{error:#}").contains("chrome://version"));
        assert_eq!(
            select_profile_using(None, Some("work@example.com"), unreadable).unwrap(),
            None
        );
    }

    #[test]
    fn malformed_metadata_is_reported() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("Local State");
        std::fs::write(&path, "not json").unwrap();
        let error = load(&path).err().unwrap();
        assert!(
            error
                .to_string()
                .contains("parsing Chrome profile metadata")
        );
    }
}
