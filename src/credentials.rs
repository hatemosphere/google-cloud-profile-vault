use std::fmt;

use google_cloud_auth::credentials::{impersonated, user_account};
use serde::Serialize;

use crate::auth;
use crate::config::Profile;
use crate::secret::SecretString;

#[derive(Serialize)]
pub(crate) struct AuthorizedUserAdc<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    client_id: &'static str,
    client_secret: &'static str,
    refresh_token: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    quota_project_id: Option<&'a str>,
}

#[derive(Serialize)]
pub(crate) struct ImpersonatedAdc<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    service_account_impersonation_url: String,
    source_credentials: AuthorizedUserAdc<'a>,
    delegates: &'static [&'static str],
    #[serde(skip_serializing_if = "Option::is_none")]
    quota_project_id: Option<&'a str>,
}

#[derive(Serialize)]
#[serde(untagged)]
pub(crate) enum Adc<'a> {
    AuthorizedUser(AuthorizedUserAdc<'a>),
    Impersonated(ImpersonatedAdc<'a>),
}

pub(crate) fn adc<'a>(profile: &'a Profile, refresh_token: &'a SecretString) -> Adc<'a> {
    let source = AuthorizedUserAdc {
        kind: "authorized_user",
        client_id: auth::CLIENT_ID,
        client_secret: auth::CLIENT_SECRET,
        refresh_token: refresh_token.expose(),
        quota_project_id: profile
            .impersonate_service_account
            .is_none()
            .then(|| profile.quota_project())
            .flatten(),
    };

    match &profile.impersonate_service_account {
        Some(service_account) => Adc::Impersonated(ImpersonatedAdc {
            kind: "impersonated_service_account",
            service_account_impersonation_url: format!(
                "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{service_account}:generateAccessToken"
            ),
            source_credentials: source,
            delegates: &[],
            quota_project_id: profile.quota_project(),
        }),
        None => Adc::AuthorizedUser(source),
    }
}

pub struct AccessToken(SecretString);

impl AccessToken {
    pub(crate) fn new(value: impl Into<String>) -> Self {
        Self(SecretString::new(value))
    }

    pub fn expose(&self) -> &str {
        self.0.expose()
    }
}

impl fmt::Debug for AccessToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AccessToken([REDACTED])")
    }
}

#[derive(Debug)]
pub struct MintError {
    message: String,
    rejected: bool,
}

impl MintError {
    pub fn credentials_rejected(&self) -> bool {
        self.rejected
    }

    fn new(context: &str, error: &(dyn std::error::Error + 'static)) -> Self {
        let mut details = error.to_string();
        let mut source = error.source();
        while let Some(error) = source {
            details.push_str(": ");
            details.push_str(&error.to_string());
            source = error.source();
        }
        let normalized = details.to_ascii_lowercase();
        Self {
            message: format!("{context}: {details}"),
            rejected: normalized.contains("invalid_grant") || normalized.contains("invalid_rapt"),
        }
    }
}

impl fmt::Display for MintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for MintError {}

/// Mints an access token and classifies credential rejection separately from
/// transient or configuration failures.
pub async fn mint(
    profile: &Profile,
    refresh_token: &SecretString,
) -> Result<AccessToken, MintError> {
    let value = serde_json::to_value(adc(profile, refresh_token))
        .map_err(|error| MintError::new("serializing credentials", &error))?;
    let credentials = if profile.impersonate_service_account.is_some() {
        impersonated::Builder::new(value).build_access_token_credentials()
    } else {
        user_account::Builder::new(value).build_access_token_credentials()
    }
    .map_err(|error| MintError::new("building credentials", &error))?;
    let token = credentials
        .access_token()
        .await
        .map_err(|error| MintError::new("minting access token", &error))?;
    Ok(AccessToken::new(token.token))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> Profile {
        Profile {
            account: Some("test@example.com".into()),
            project: Some("project-a".into()),
            ..Profile::default()
        }
    }

    #[test]
    fn authorized_user_adc_uses_project_as_quota_fallback() {
        let refresh = SecretString::new("refresh-token");
        let value = serde_json::to_value(adc(&profile(), &refresh)).unwrap();
        assert_eq!(value["type"], "authorized_user");
        assert_eq!(value["refresh_token"], "refresh-token");
        assert_eq!(value["client_id"], auth::CLIENT_ID);
        assert_eq!(value["quota_project_id"], "project-a");
    }

    #[test]
    fn impersonated_adc_wraps_source_and_keeps_quota_on_the_outer_credential() {
        let mut profile = profile();
        profile.impersonate_service_account =
            Some("deploy@project-a.iam.gserviceaccount.com".into());
        profile.quota_project = Some("billing-project".into());
        let refresh = SecretString::new("refresh-token");
        let value = serde_json::to_value(adc(&profile, &refresh)).unwrap();

        assert_eq!(value["type"], "impersonated_service_account");
        assert_eq!(value["source_credentials"]["type"], "authorized_user");
        assert_eq!(
            value["source_credentials"]["refresh_token"],
            "refresh-token"
        );
        assert!(
            value["source_credentials"]
                .get("quota_project_id")
                .is_none()
        );
        assert_eq!(value["quota_project_id"], "billing-project");
        assert_eq!(
            value["service_account_impersonation_url"],
            "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/deploy@project-a.iam.gserviceaccount.com:generateAccessToken"
        );
    }

    #[derive(Debug)]
    struct ErrorMessage(&'static str);

    impl fmt::Display for ErrorMessage {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.0)
        }
    }

    impl std::error::Error for ErrorMessage {}

    #[test]
    fn only_known_oauth_rejections_trigger_interactive_reauthentication() {
        let rejected = MintError::new("mint", &ErrorMessage("invalid_grant"));
        let transient = MintError::new("mint", &ErrorMessage("connection reset"));
        assert!(rejected.credentials_rejected());
        assert!(!transient.credentials_rejected());
    }

    #[test]
    fn access_token_debug_output_is_redacted() {
        let token = AccessToken::new("access-token");
        assert!(!format!("{token:?}").contains("access-token"));
    }
}
