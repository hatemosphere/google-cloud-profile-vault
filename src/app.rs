use std::io::IsTerminal as _;

use anyhow::{Context, Result, bail};

use crate::auth::{self, Identity};
use crate::cli::{Cli, Command};
use crate::config::{ConfigStore, Profile, ProfileName};
use crate::credentials::{self, AccessToken};
use crate::keychain::{self, CredentialState};
use crate::secret::SecretString;

pub async fn run(cli: Cli) -> Result<u8> {
    let store = ConfigStore::discover()?;
    run_with_store(cli, &store).await
}

async fn run_with_store(cli: Cli, store: &ConfigStore) -> Result<u8> {
    match cli.command {
        Command::Add {
            name,
            account,
            project,
            quota_project,
            impersonate,
            scopes,
            browser_profile,
        } => {
            let profile = Profile {
                account,
                subject: None,
                project,
                quota_project,
                impersonate_service_account: impersonate,
                scopes,
                browser_profile,
            };
            store.update(|config| {
                if config.profiles.contains_key(&name) {
                    bail!(
                        "profile '{name}' already exists; use `gcpv login {name}` to re-authenticate"
                    );
                }
                config.profiles.insert(name.clone(), profile);
                Ok(())
            })?;
            eprintln!(
                "Created profile '{name}'. If authentication is interrupted, resume with `gcpv login {name}`."
            );
            login(&name, store, None).await?;
            Ok(0)
        }
        Command::Login {
            name,
            browser_profile,
        } => {
            login(&name, store, browser_profile.as_deref()).await?;
            Ok(0)
        }
        Command::List => {
            list(store)?;
            Ok(0)
        }
        Command::Remove { name } => {
            if !store.load()?.profiles.contains_key(&name) {
                bail!("no profile '{name}'");
            }
            let previous_token = keychain::refresh_token(&name)?;
            let remove_result = store.update(|config| {
                if !config.profiles.contains_key(&name) {
                    bail!("no profile '{name}'");
                }
                // Prefer a recoverable profile-without-credentials state over
                // leaving an inaccessible credential orphaned in the keychain.
                keychain::delete(&name)?;
                config.profiles.remove(&name);
                Ok(())
            });
            if let Err(remove_error) = remove_result {
                let rollback = match previous_token {
                    Some(previous) => keychain::store_refresh_token(&name, &previous),
                    None => keychain::delete(&name),
                };
                return match rollback {
                    Ok(()) => Err(remove_error.context("remove failed; restored credential")),
                    Err(rollback_error) => Err(remove_error.context(format!(
                        "remove failed and credential rollback also failed: {rollback_error:#}"
                    ))),
                };
            }
            eprintln!("Removed profile '{name}'.");
            Ok(0)
        }
        Command::Exec { name, command } => {
            let (profile, refresh_token, access_token) = credentials_for(&name, store).await?;
            let status =
                crate::process::run(&name, &profile, &command, &refresh_token, &access_token)?;
            Ok(crate::process::exit_code(status))
        }
        Command::Token { name } => {
            let (_, _, access_token) = credentials_for(&name, store).await?;
            println!("{}", access_token.expose());
            Ok(0)
        }
    }
}

async fn credentials_for(
    name: &ProfileName,
    store: &ConfigStore,
) -> Result<(Profile, SecretString, AccessToken)> {
    let interactive = std::io::stderr().is_terminal();
    let mut profile = load_profile(store, name)?;
    let mut refresh_token = match keychain::refresh_token(name)? {
        Some(token) => token,
        None if interactive => {
            eprintln!("No credentials for profile '{name}'; starting login.");
            login(name, store, None).await?;
            profile = load_profile(store, name)?;
            keychain::refresh_token(name)?.context("login did not store a refresh token")?
        }
        None => bail!("no credentials for profile '{name}'; run `gcpv login {name}`"),
    };

    match mint_access_token(name, &profile, &refresh_token).await {
        Ok(access_token) => Ok((profile, refresh_token, access_token)),
        Err(error) if error.credentials_rejected() && interactive => {
            eprintln!("Stored credentials for '{name}' were rejected ({error}); re-running login.");
            login(name, store, None).await?;
            profile = load_profile(store, name)?;
            refresh_token =
                keychain::refresh_token(name)?.context("login did not store a refresh token")?;
            let access_token = mint_access_token(name, &profile, &refresh_token).await?;
            Ok((profile, refresh_token, access_token))
        }
        Err(error) if error.credentials_rejected() => Err(anyhow::Error::new(error)).context(
            format!("credentials expired or were revoked; run `gcpv login {name}`"),
        ),
        Err(error) => Err(error.into()),
    }
}

async fn mint_access_token(
    name: &ProfileName,
    profile: &Profile,
    refresh_token: &SecretString,
) -> std::result::Result<AccessToken, credentials::MintError> {
    let kind = if profile.impersonate_service_account.is_some() {
        "impersonated service-account"
    } else {
        "user-account"
    };
    crate::diagnostics::debug(format_args!(
        "profile '{name}': minting {kind} access token"
    ));
    let result = credentials::mint(profile, refresh_token).await;
    if let Err(error) = &result {
        crate::diagnostics::debug(format_args!(
            "profile '{name}': access-token mint failed: {error}"
        ));
    }
    result
}

async fn login(
    name: &ProfileName,
    store: &ConfigStore,
    browser_override: Option<&str>,
) -> Result<()> {
    let before = load_profile(store, name)?;
    let scopes = auth::effective_scopes(before.scopes.as_deref());
    let chrome_profile = crate::chrome::select_profile(
        browser_override.or(before.browser_profile.as_deref()),
        before.account.as_deref(),
    )?;
    let result = auth::login(
        before.account.as_deref(),
        &scopes,
        chrome_profile.as_deref(),
    )
    .await?;
    verify_identity(name, &before, &result.identity)?;

    let previous_token = keychain::refresh_token(name)?;
    keychain::store_refresh_token(name, &result.refresh_token)?;
    let save_result = store.update(|config| {
        let current = config
            .profiles
            .get_mut(name)
            .with_context(|| format!("profile '{name}' was removed during login"))?;
        if current.account != before.account || current.subject != before.subject {
            bail!("profile '{name}' identity changed during login; retry the command");
        }
        current.account = Some(result.identity.email.clone());
        current.subject = Some(result.identity.subject.clone());
        if let Some(browser_profile) = browser_override {
            current.browser_profile = Some(browser_profile.to_owned());
        }
        Ok(())
    });
    if let Err(save_error) = save_result {
        let rollback = match previous_token {
            Some(previous) => keychain::store_refresh_token(name, &previous),
            None => keychain::delete(name),
        };
        return match rollback {
            Ok(()) => {
                Err(save_error.context("profile update failed; restored previous credential"))
            }
            Err(rollback_error) => Err(save_error.context(format!(
                "profile update failed and credential rollback also failed: {rollback_error:#}"
            ))),
        };
    }

    eprintln!(
        "Profile '{name}' logged in as {}; refresh token stored in OS keychain.",
        result.identity.email
    );
    Ok(())
}

fn verify_identity(name: &ProfileName, profile: &Profile, actual: &Identity) -> Result<()> {
    if let Some(expected_subject) = profile.subject.as_deref()
        && expected_subject != actual.subject
    {
        bail!(
            "logged in with a different Google identity for profile '{name}'; nothing was stored"
        );
    }
    if let Some(expected_email) = profile.account.as_deref()
        && !expected_email.eq_ignore_ascii_case(&actual.email)
    {
        bail!(
            "logged in as {}, but profile '{name}' expects {expected_email}; nothing was stored",
            actual.email
        );
    }
    Ok(())
}

fn load_profile(store: &ConfigStore, name: &ProfileName) -> Result<Profile> {
    store
        .load()?
        .profiles
        .get(name)
        .cloned()
        .with_context(|| format!("no profile '{name}'; create it with `gcpv add {name}`"))
}

fn list(store: &ConfigStore) -> Result<()> {
    let config = store.load()?;
    if config.profiles.is_empty() {
        eprintln!("No profiles. Create one with `gcpv add <name> --project <project>`.");
        return Ok(());
    }

    println!(
        "{:<16} {:<32} {:<24} {:<10} IMPERSONATE",
        "PROFILE", "ACCOUNT", "PROJECT", "CREDS"
    );
    for (name, profile) in &config.profiles {
        let credentials = match keychain::credential_state(name)? {
            CredentialState::Present => "keychain",
            CredentialState::Missing => "none",
        };
        println!(
            "{:<16} {:<32} {:<24} {:<10} {}",
            name,
            profile.account.as_deref().unwrap_or("-"),
            profile.project.as_deref().unwrap_or("-"),
            credentials,
            profile
                .impersonate_service_account
                .as_deref()
                .unwrap_or("-"),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name() -> ProfileName {
        "work".parse().unwrap()
    }

    #[test]
    fn expected_email_must_match() {
        let profile = Profile {
            account: Some("expected@example.com".into()),
            ..Profile::default()
        };
        let identity = Identity {
            subject: "subject-1".into(),
            email: "other@example.com".into(),
        };
        let error = verify_identity(&name(), &profile, &identity).unwrap_err();
        assert!(error.to_string().contains("expects expected@example.com"));
    }

    #[test]
    fn stable_subject_prevents_account_substitution_even_if_email_matches() {
        let profile = Profile {
            account: Some("work@example.com".into()),
            subject: Some("subject-1".into()),
            ..Profile::default()
        };
        let identity = Identity {
            subject: "subject-2".into(),
            email: "work@example.com".into(),
        };
        let error = verify_identity(&name(), &profile, &identity).unwrap_err();
        assert!(error.to_string().contains("different Google identity"));
    }

    #[test]
    fn email_comparison_is_case_insensitive() {
        let profile = Profile {
            account: Some("Work@Example.com".into()),
            ..Profile::default()
        };
        let identity = Identity {
            subject: "subject-1".into(),
            email: "work@example.com".into(),
        };
        verify_identity(&name(), &profile, &identity).unwrap();
    }
}
