# gcpv — Google Cloud Profile Vault

**Named Google Cloud credentials without global auth-state roulette.**

`gcpv` is a small, `aws-vault`-style wrapper for running commands with an
isolated Google account, project, scopes, and optional service-account
impersonation.

## Why gcpv?

- **Keychain-backed at rest.** `gcloud auth application-default login` creates a
  well-known JSON file containing a reusable refresh token. gcpv keeps that
  token in macOS Keychain, Windows Credential Manager, or Secret Service and
  materializes a restricted temporary ADC file for the child command.
- **No global account or ADC switching.** The gcloud CLI credential store and
  local ADC are separate, and changing a gcloud configuration does not switch
  ADC. A gcpv profile supplies both to one process tree without activating a
  global gcloud configuration or overwriting the well-known ADC file.
- **The right browser and the right identity.** gcpv can match an account to its
  signed-in Chrome profile, accepts an explicit profile override, and verifies
  both the returned email and stable Google subject before storing credentials.
- **Useful for real development workflows.** Child processes receive a fresh
  gcloud access token plus renewable ADC for Terraform and Google client
  libraries. Competing credential variables are scrubbed first.

Google documents both the [refresh token stored in local ADC][local-adc] and
the fact that [gcloud configurations do not switch local ADC][adc-search].

[local-adc]: https://cloud.google.com/docs/authentication/set-up-adc-local-dev-environment#user-credentials
[adc-search]: https://cloud.google.com/docs/authentication/application-default-credentials

```console
gcpv add work --account you@corp.com --project my-project
gcpv exec work -- terraform plan
gcpv exec work -- kubectl get pods -A
gcpv exec work                         # start $SHELL
gcpv token work                        # print a fresh access token
gcpv list
```

## Install

Requires Rust 1.97 or newer.

```console
cargo install --git https://github.com/hatemosphere/google-cloud-profile-vault --locked
```

## Make gcpv the only local auth source

This cleanup is optional: gcpv already isolates wrapped commands from native
gcloud credentials. Use it on a local workstation if you also want unwrapped
`gcloud` commands to fail instead of silently using a previously active
account.

Native gcloud CLI credentials and local Application Default Credentials (ADC)
are separate stores, so remove both before logging back into gcpv:

```console
# Delete and revoke ADC created by `gcloud auth application-default login`.
gcloud auth application-default revoke

# Remove every account stored by the gcloud CLI and revoke user tokens.
gcloud auth revoke --all

# Recreate gcpv credentials last.
gcpv login work
```

Run the native revocations first. gcpv uses Google's public gcloud OAuth client,
so revoking an older gcloud authorization can also invalidate an existing gcpv
refresh token for that Google account.

Verify from a fresh, ordinary shell—not from inside `gcpv exec`:

```console
# Prints no active account.
gcloud auth list --filter=status:ACTIVE --format='value(account)'

# Fails without authentication.
gcloud organizations list

# Still works through the selected profile.
gcpv exec work -- gcloud organizations list
```

This does not delete service-account key files or revoke credentials owned by
an external identity provider. Explicit token flags, `CLOUDSDK_AUTH_*`
environment variables, or Google Cloud metadata credentials can also keep bare
gcloud commands authenticated; remove those separately if present. The
[`gcloud auth revoke`][gcloud-auth-revoke] and
[`gcloud auth application-default revoke`][adc-revoke] references describe the
exact behavior.

[gcloud-auth-revoke]: https://cloud.google.com/sdk/gcloud/reference/auth/revoke
[adc-revoke]: https://cloud.google.com/sdk/gcloud/reference/auth/application-default/revoke

## Commands

| Command | Purpose |
|---|---|
| `gcpv add NAME [OPTIONS]` | Create and authenticate a profile |
| `gcpv login NAME [--browser-profile DIR_OR_EMAIL]` | Re-authenticate a profile |
| `gcpv exec NAME [-- COMMAND...]` | Run a command, or start `$SHELL` |
| `gcpv token NAME` | Print a fresh access token |
| `gcpv list` / `gcpv ls` | List profiles and credential status |
| `gcpv remove NAME` / `gcpv rm NAME` | Delete the profile and keychain entry |

The `--` before a child command is optional, but recommended when the child has
flags of its own.

`add` accepts:

- `--account EMAIL`: expected Google account. Authentication fails closed if
  Google cannot verify this email or returns another identity.
- `--project PROJECT`: default project for gcloud, ADC clients, and Terraform.
- `--quota-project PROJECT`: quota/billing project; defaults to `--project`.
- `--impersonate SA_EMAIL`: service account to impersonate.
- `--scopes SCOPE,...`: API scopes replacing the default `cloud-platform` and
  `sqlservice.login` scopes. The `openid` and `userinfo.email` scopes are always
  added so gcpv can verify the Google identity.
- `--browser-profile DIR_OR_EMAIL`: explicit Google Chrome profile directory or
  its signed-in email.

Profile names are deliberately portable: ASCII letters, numbers, `.`, `_`, and
`-`, up to 64 bytes.

If browser authentication is interrupted during `add`, the non-secret profile
remains configured; continue with `gcpv login NAME`.

## Environment used by `exec`

| Variable | Value |
|---|---|
| `GOOGLE_APPLICATION_CREDENTIALS` | Temporary authorized-user or impersonated ADC file |
| `CLOUDSDK_AUTH_ACCESS_TOKEN` | Fresh token for the gcloud CLI |
| `CLOUDSDK_CORE_ACCOUNT` | Authenticated user email |
| `CLOUDSDK_CORE_PROJECT` | Profile project |
| `GOOGLE_CLOUD_PROJECT`, `GOOGLE_PROJECT`, `GCLOUD_PROJECT` | Profile project |
| `GOOGLE_CLOUD_QUOTA_PROJECT` | Quota project |
| `GCPV_PROFILE` | Profile name |

Competing Google credential, access-token, project, and impersonation variables
are removed before this environment is applied. `CLOUDSDK_CONFIG` is preserved,
so `gcloud config set` still writes to the user's normal gcloud configuration.

`GOOGLE_OAUTH_ACCESS_TOKEN` is intentionally removed instead of populated.
Terraform gives that static token precedence over ADC and cannot renew it;
using the ADC file lets Terraform and other compatible clients refresh their
credentials during long operations.

The gcloud-specific access token is static and normally lasts about one hour.
For a shell that remains open longer than that, start a new `gcpv exec` before
running more gcloud commands.

## Service account impersonation

```console
gcpv add production \
  --project production-project \
  --impersonate deploy@production-project.iam.gserviceaccount.com
```

The authenticated user must have `iam.serviceAccounts.getAccessToken`, usually
through `roles/iam.serviceAccountTokenCreator`, on the target service account.
The Service Account Credentials API must also be enabled.

The generated ADC uses the `impersonated_service_account` format. Support for
this credential type varies between Google authentication libraries. The
injected gcloud access token already belongs to the service account.

## Chrome profiles

`--browser-profile` can be either a known Chrome profile directory, such as
`Profile 2`, or an email found in Chrome's `Local State` file. Explicit unknown
directories and emails are rejected before Chrome is started.

```console
gcpv add work --account you@corp.com --browser-profile 'Profile 2'
gcpv login work --browser-profile you@corp.com
```

To find the directory name, open `chrome://version` in the intended Chrome
profile and use the final component of **Profile Path** (`Default`, `Profile 2`,
and so on). A `login` override is saved only after authentication succeeds and
the returned Google identity is verified.

Without this option, gcpv tries to match `--account` to a signed-in Chrome
profile. If no match is available, it opens the system browser and supplies
Google's `login_hint`. If the browser cannot be started, the authorization URL
remains available for manual opening.

## Configuration

Non-secret configuration is stored in `~/.config/gcpv/config.toml`:

```toml
[profiles.work]
account = "you@corp.com"
subject = "google-openid-subject" # set automatically after login
project = "my-project"

[profiles.production]
account = "you@corp.com"
subject = "google-openid-subject"
project = "production-project"
quota_project = "billing-project"
impersonate_service_account = "deploy@production-project.iam.gserviceaccount.com"

[profiles.data]
account = "you@corp.com"
scopes = ["https://www.googleapis.com/auth/bigquery.readonly"]
browser_profile = "Profile 2"
```

Configuration updates use an advisory lock and an atomic file replacement, so
concurrent `add`, `login`, and `remove` operations do not overwrite one another.
Unknown or invalid profile values are reported when the file is loaded.

Refresh tokens use keychain service `gcpv`, with the profile name as the entry
name. `list` distinguishes a missing entry from a keychain access failure.

## Troubleshooting

Set `GCPV_LOG=debug` to show credential flow and browser-profile selection on
stderr:

```console
GCPV_LOG=debug gcpv exec work -- gcloud projects list
```

Debug messages do not include access or refresh token values. Credential
rejections include Google's response even when debug logging is disabled.
`Rejected` means Google's token endpoint returned `invalid_grant` or
`invalid_rapt`; it is not inferred from credential age. Google documents
[revocation, token limits, and Workspace session controls][refresh-expiration]
as possible causes.

[refresh-expiration]: https://developers.google.com/identity/protocols/oauth2#expiration

## Security model

- Outside an active `exec` (and the crash case below), the refresh token is
  stored only in macOS Keychain, Windows Credential Manager, or Secret Service,
  depending on the platform.
- Login uses authorization code flow with PKCE, a CSRF state value, a loopback
  callback bound to `127.0.0.1`, verified Google identity data, connection
  limits, and an overall callback deadline.
- During `exec`, an ADC file with restrictive permissions (`0600` on Unix)
  contains the refresh token so ADC clients can renew access tokens. The child
  process can read and copy that long-lived token; only run trusted commands.
- The ADC file is deleted after normal child termination and after handled
  `SIGINT`, `SIGTERM`, or `SIGHUP`. No process can clean up after `SIGKILL`, a
  machine crash, or abrupt power loss, so a stale file can remain in the system
  temporary directory in those cases.
- On macOS, rebuilding an unsigned binary can cause Keychain authorization
  prompts. Ad-hoc signing the release binary can reduce repeated prompts:

  ```console
  codesign -s - target/release/gcpv
  ```

This differs from AWS Vault's usual short-lived-only child environment: generic
Google ADC refresh requires the child to receive a renewable credential.

## Development

```console
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-targets --locked
```

Tests cover CLI parsing, profile validation, concurrent and transactional
configuration updates, OAuth callback behavior, identity binding, ADC formats,
credential error classification, environment isolation, file permissions,
cleanup, and child exit propagation. Network OAuth and real keychain behavior
remain platform/integration concerns and are not exercised by unit tests.
