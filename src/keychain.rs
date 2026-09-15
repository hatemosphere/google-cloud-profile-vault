use anyhow::{Context, Result};
use keyring::Entry;

use crate::config::ProfileName;
use crate::secret::SecretString;

const SERVICE: &str = "gcpv";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialState {
    Present,
    Missing,
}

fn entry(profile: &ProfileName) -> Result<Entry> {
    Entry::new(SERVICE, profile.as_str()).context("opening OS keychain")
}

pub fn store_refresh_token(profile: &ProfileName, token: &SecretString) -> Result<()> {
    entry(profile)?
        .set_password(token.expose())
        .context("storing refresh token in OS keychain")
}

/// `Ok(None)` means no entry exists; keychain access failures remain errors.
pub fn refresh_token(profile: &ProfileName) -> Result<Option<SecretString>> {
    match entry(profile)?.get_password() {
        Ok(token) => Ok(Some(SecretString::new(token))),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(error) => Err(error).context("reading refresh token from OS keychain"),
    }
}

pub fn credential_state(profile: &ProfileName) -> Result<CredentialState> {
    Ok(match refresh_token(profile)? {
        Some(_) => CredentialState::Present,
        None => CredentialState::Missing,
    })
}

pub fn delete(profile: &ProfileName) -> Result<()> {
    match entry(profile)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(error) => Err(error).context("deleting keychain credential"),
    }
}
