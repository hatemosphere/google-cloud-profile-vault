use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Deserializer, Serialize};

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ProfileName(String);

impl ProfileName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ProfileName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for ProfileName {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        if value.is_empty() {
            return Err("profile name cannot be empty".into());
        }
        if value.len() > 64 {
            return Err("profile name cannot exceed 64 bytes".into());
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(
                "profile name may contain only ASCII letters, numbers, '.', '_' and '-'".into(),
            );
        }
        Ok(Self(value.into()))
    }
}

impl<'de> Deserialize<'de> for ProfileName {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub profiles: BTreeMap<ProfileName, Profile>,
}

impl Config {
    fn validate(&self) -> Result<()> {
        for (name, profile) in &self.profiles {
            profile
                .validate()
                .with_context(|| format!("invalid profile '{name}'"))?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    /// Stable OpenID Connect subject for the Google account.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quota_project: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub impersonate_service_account: Option<String>,
    /// API scopes replacing the defaults. Identity scopes are always added.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
    /// Chrome profile directory or its signed-in email.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser_profile: Option<String>,
}

impl Profile {
    pub fn quota_project(&self) -> Option<&str> {
        self.quota_project.as_deref().or(self.project.as_deref())
    }

    fn validate(&self) -> Result<()> {
        validate_optional("account", self.account.as_deref())?;
        validate_optional("subject", self.subject.as_deref())?;
        validate_optional("project", self.project.as_deref())?;
        validate_optional("quota_project", self.quota_project.as_deref())?;
        validate_optional("browser_profile", self.browser_profile.as_deref())?;

        for (field, value) in [
            ("subject", self.subject.as_deref()),
            ("project", self.project.as_deref()),
            ("quota_project", self.quota_project.as_deref()),
        ] {
            if value.is_some_and(|value| value.chars().any(char::is_whitespace)) {
                bail!("{field} cannot contain whitespace");
            }
        }

        if let Some(email) = self.account.as_deref()
            && (!email.contains('@') || email.chars().any(char::is_whitespace))
        {
            bail!("account must be an email address without whitespace");
        }
        if let Some(service_account) = self.impersonate_service_account.as_deref()
            && (!service_account.contains('@')
                || !service_account.ends_with(".gserviceaccount.com")
                || service_account.bytes().any(|byte| {
                    !(byte.is_ascii_alphanumeric() || matches!(byte, b'@' | b'.' | b'_' | b'-'))
                }))
        {
            bail!("impersonate_service_account must be a Google service account email");
        }
        if let Some(scopes) = &self.scopes {
            if scopes.is_empty() {
                bail!("scopes cannot be empty");
            }
            for scope in scopes {
                validate_non_empty("scope", scope)?;
                if scope.chars().any(char::is_whitespace) {
                    bail!("scope cannot contain whitespace");
                }
            }
        }
        Ok(())
    }
}

fn validate_optional(field: &str, value: Option<&str>) -> Result<()> {
    if let Some(value) = value {
        validate_non_empty(field, value)?;
    }
    Ok(())
}

fn validate_non_empty(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        bail!("{field} cannot be empty or contain control characters");
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub struct ConfigStore {
    path: PathBuf,
}

impl ConfigStore {
    pub fn discover() -> Result<Self> {
        let home = std::env::home_dir().context("cannot determine home directory")?;
        Ok(Self::new(
            home.join(".config").join("gcpv").join("config.toml"),
        ))
    }

    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn load(&self) -> Result<Config> {
        load_from(&self.path)
    }

    /// Applies and atomically persists one read-modify-write transaction.
    pub fn update<T>(&self, update: impl FnOnce(&mut Config) -> Result<T>) -> Result<T> {
        let parent = self
            .path
            .parent()
            .context("configuration path has no parent directory")?;
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;

        let lock_path = self.path.with_extension("toml.lock");
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)
            .with_context(|| format!("opening {}", lock_path.display()))?;
        lock.lock()
            .with_context(|| format!("locking {}", lock_path.display()))?;

        let mut config = load_from(&self.path)?;
        let result = update(&mut config)?;
        config.validate()?;
        save_atomic(&self.path, &config)?;
        Ok(result)
    }
}

fn load_from(path: &Path) -> Result<Config> {
    if !path.exists() {
        return Ok(Config::default());
    }
    let raw = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let config: Config =
        toml::from_str(&raw).with_context(|| format!("parsing {}", path.display()))?;
    config.validate()?;
    Ok(config)
}

fn save_atomic(path: &Path, config: &Config) -> Result<()> {
    let parent = path
        .parent()
        .context("configuration path has no parent directory")?;
    let mut temporary = tempfile::Builder::new()
        .prefix(".config.toml-")
        .tempfile_in(parent)
        .with_context(|| format!("creating a temporary file in {}", parent.display()))?;
    temporary
        .write_all(toml::to_string_pretty(config)?.as_bytes())
        .context("writing temporary configuration")?;
    temporary
        .flush()
        .context("flushing temporary configuration")?;
    temporary
        .as_file()
        .sync_all()
        .context("syncing temporary configuration")?;
    temporary
        .persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("replacing {}", path.display()))?;

    #[cfg(unix)]
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .with_context(|| format!("syncing {}", parent.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    fn name(value: &str) -> ProfileName {
        value.parse().unwrap()
    }

    #[test]
    fn profile_name_rejects_ambiguous_or_hostile_values() {
        for invalid in ["", "has space", "has/slash", "has\ttab", "é"] {
            assert!(
                invalid.parse::<ProfileName>().is_err(),
                "accepted {invalid:?}"
            );
        }
        for valid in ["work", "prod-admin", "team_one", "gcp.v2"] {
            assert!(valid.parse::<ProfileName>().is_ok(), "rejected {valid:?}");
        }
    }

    #[test]
    fn update_round_trips_and_failed_transaction_keeps_previous_file() {
        let directory = tempfile::tempdir().unwrap();
        let store = ConfigStore::new(directory.path().join("config.toml"));
        store
            .update(|config| {
                config.profiles.insert(
                    name("work"),
                    Profile {
                        project: Some("project-a".into()),
                        ..Profile::default()
                    },
                );
                Ok(())
            })
            .unwrap();

        let error = store
            .update::<()>(|config| {
                config.profiles.get_mut(&name("work")).unwrap().project = Some("not-saved".into());
                bail!("stop transaction")
            })
            .unwrap_err();
        assert!(error.to_string().contains("stop transaction"));
        assert_eq!(
            store.load().unwrap().profiles[&name("work")]
                .project
                .as_deref(),
            Some("project-a")
        );
    }

    #[test]
    fn concurrent_updates_do_not_lose_profiles() {
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(ConfigStore::new(directory.path().join("config.toml")));
        let handles: Vec<_> = (0..8)
            .map(|index| {
                let store = Arc::clone(&store);
                thread::spawn(move || {
                    store
                        .update(|config| {
                            config
                                .profiles
                                .insert(name(&format!("profile-{index}")), Profile::default());
                            Ok(())
                        })
                        .unwrap();
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
        assert_eq!(store.load().unwrap().profiles.len(), 8);
    }

    #[test]
    fn invalid_manually_edited_profile_is_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        fs::write(&path, "[profiles.work]\naccount = 'not-an-email'\n").unwrap();
        let error = ConfigStore::new(path).load().unwrap_err();
        assert!(error.to_string().contains("invalid profile 'work'"));
    }

    #[test]
    fn misspelled_configuration_fields_are_not_silently_discarded() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        fs::write(&path, "[profiles.work]\nprojet = 'typo'\n").unwrap();
        let error = ConfigStore::new(path).load().unwrap_err();
        assert!(format!("{error:#}").contains("unknown field"));
    }

    #[test]
    fn project_and_scope_values_cannot_hide_whitespace() {
        let profile = Profile {
            project: Some("project with spaces".into()),
            scopes: Some(vec!["scope one".into()]),
            ..Profile::default()
        };
        assert!(profile.validate().is_err());
    }
}
