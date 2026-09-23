use std::io::Write as _;
use std::path::Path;
use std::process::{Child, Command, ExitStatus};
#[cfg(windows)]
use std::sync::OnceLock;

use anyhow::{Context, Result, anyhow};

use crate::config::{Profile, ProfileName};
use crate::credentials::{self, AccessToken};
use crate::secret::SecretString;

const CLEAN_ENVIRONMENT: &[&str] = &[
    "BOTO_CONFIG",
    "BOTO_PATH",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "GOOGLE_BACKEND_CREDENTIALS",
    "GOOGLE_CREDENTIALS",
    "GOOGLE_CLOUD_KEYFILE_JSON",
    "GCLOUD_KEYFILE_JSON",
    "GOOGLE_OAUTH_ACCESS_TOKEN",
    "GOOGLE_IMPERSONATE_SERVICE_ACCOUNT",
    "CLOUDSDK_AUTH_ACCESS_TOKEN",
    "CLOUDSDK_AUTH_ACCESS_TOKEN_FILE",
    "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE",
    "CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT",
    "CLOUDSDK_CORE_ACCOUNT",
    "CLOUDSDK_CORE_PROJECT",
    "GOOGLE_CLOUD_PROJECT",
    "GOOGLE_PROJECT",
    "GCLOUD_PROJECT",
    "GOOGLE_CLOUD_QUOTA_PROJECT",
    "GCPV_PROFILE",
];

pub fn run(
    name: &ProfileName,
    profile: &Profile,
    command: &[String],
    refresh_token: &SecretString,
    access_token: &AccessToken,
) -> Result<ExitStatus> {
    let adc_file = temporary_adc(profile, refresh_token)?;
    let boto_file = temporary_boto(profile, refresh_token)?;

    let (program, arguments) = match command {
        [] => (default_shell(), &[] as &[String]),
        [program, arguments @ ..] => (program.clone(), arguments),
    };
    let mut child = child_command(
        &program,
        arguments,
        name,
        profile,
        adc_file.path(),
        boto_file.path(),
        access_token,
    )
    .spawn()
    .with_context(|| format!("running {program}"))?;
    wait_for_child(&mut child)
}

/// Owner-only (0600 on Unix) file deleted when dropped.
fn private_temporary_file(prefix: &str, suffix: &str) -> Result<tempfile::NamedTempFile> {
    tempfile::Builder::new()
        .prefix(prefix)
        .suffix(suffix)
        .tempfile()
        .with_context(|| format!("creating temporary {prefix}{suffix} file"))
}

fn temporary_adc(
    profile: &Profile,
    refresh_token: &SecretString,
) -> Result<tempfile::NamedTempFile> {
    let mut file = private_temporary_file("gcpv-adc-", ".json")?;
    serde_json::to_writer_pretty(&mut file, &credentials::adc(profile, refresh_token))
        .context("writing temporary ADC file")?;
    file.flush().context("flushing temporary ADC file")?;
    Ok(file)
}

fn temporary_boto(
    profile: &Profile,
    refresh_token: &SecretString,
) -> Result<tempfile::NamedTempFile> {
    let mut file = private_temporary_file("gcpv-boto-", ".cfg")?;
    file.write_all(
        credentials::boto(profile, refresh_token)
            .expose()
            .as_bytes(),
    )
    .context("writing temporary boto file")?;
    file.flush().context("flushing temporary boto file")?;
    Ok(file)
}

/// Keeps gcpv alive through terminal signals so the ADC file is always
/// deleted, and relays signals addressed only to gcpv.
///
/// Terminal-generated SIGINT/SIGQUIT already reach the child through the
/// foreground process group; forwarding them would deliver a second interrupt,
/// which tools like Terraform treat as "exit immediately".
#[cfg(unix)]
fn wait_for_child(child: &mut Child) -> Result<ExitStatus> {
    use rustix::process::{Pid, Signal, WaitId, WaitIdOptions, kill_process, waitid};
    use signal_hook::consts::{SIGHUP, SIGINT, SIGQUIT, SIGTERM};

    let pid = Pid::from_raw(child.id().cast_signed())
        .context("child process ID was outside the supported range")?;
    let mut signals = signal_hook::iterator::Signals::new([SIGINT, SIGQUIT, SIGTERM, SIGHUP])
        .context("installing signal handlers")?;
    let handle = signals.handle();
    let forwarder = std::thread::spawn(move || {
        for signal in signals.forever() {
            let relayed = match signal {
                SIGTERM => Signal::TERM,
                SIGHUP => Signal::HUP,
                _ => continue,
            };
            let _ = kill_process(pid, relayed);
        }
    });

    // Wait without reaping so the pid cannot be reused while the forwarder
    // may still signal it.
    loop {
        match waitid(
            WaitId::Pid(pid),
            WaitIdOptions::EXITED | WaitIdOptions::NOWAIT,
        ) {
            Ok(_) => break,
            Err(rustix::io::Errno::INTR) => {}
            Err(error) => return Err(error).context("waiting for child process"),
        }
    }
    handle.close();
    forwarder
        .join()
        .map_err(|_| anyhow!("signal forwarding thread panicked"))?;
    child.wait().context("waiting for child process")
}

#[cfg(windows)]
fn wait_for_child(child: &mut Child) -> Result<ExitStatus> {
    // The console delivers Ctrl-C to the child directly; gcpv only has to
    // survive it long enough to delete the ADC file.
    static HANDLER: OnceLock<std::result::Result<(), String>> = OnceLock::new();
    HANDLER
        .get_or_init(|| ctrlc::set_handler(|| {}).map_err(|error| error.to_string()))
        .clone()
        .map_err(|error| anyhow!("installing Ctrl-C handler: {error}"))?;
    child.wait().context("waiting for child process")
}

#[cfg(not(any(unix, windows)))]
fn wait_for_child(child: &mut Child) -> Result<ExitStatus> {
    child.wait().context("waiting for child process")
}

fn child_command(
    program: &str,
    arguments: &[String],
    name: &ProfileName,
    profile: &Profile,
    adc_path: &Path,
    boto_path: &Path,
    access_token: &AccessToken,
) -> Command {
    let mut command = Command::new(program);
    command.args(arguments);
    for variable in CLEAN_ENVIRONMENT {
        command.env_remove(variable);
    }
    command
        .env("GCPV_PROFILE", name.as_str())
        .env("GOOGLE_APPLICATION_CREDENTIALS", adc_path)
        .env("BOTO_CONFIG", boto_path)
        .env("CLOUDSDK_AUTH_ACCESS_TOKEN", access_token.expose());

    if let Some(account) = &profile.account {
        command.env("CLOUDSDK_CORE_ACCOUNT", account);
    }
    if let Some(project) = &profile.project {
        command
            .env("CLOUDSDK_CORE_PROJECT", project)
            .env("GOOGLE_CLOUD_PROJECT", project)
            .env("GOOGLE_PROJECT", project)
            .env("GCLOUD_PROJECT", project);
    }
    if let Some(quota_project) = profile.quota_project() {
        command.env("GOOGLE_CLOUD_QUOTA_PROJECT", quota_project);
    }
    command
}

pub fn exit_code(status: ExitStatus) -> u8 {
    if let Some(code) = status.code() {
        return u8::try_from(code).unwrap_or(1);
    }

    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt as _;
        status
            .signal()
            .and_then(|signal| u8::try_from(128 + signal).ok())
            .unwrap_or(1)
    }

    #[cfg(not(unix))]
    1
}

fn default_shell() -> String {
    #[cfg(windows)]
    return std::env::var("COMSPEC").unwrap_or_else(|_| "cmd.exe".into());

    #[cfg(not(windows))]
    std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::ffi::{OsStr, OsString};

    fn name() -> ProfileName {
        "test-profile".parse().unwrap()
    }

    fn profile() -> Profile {
        Profile {
            account: Some("test@example.com".into()),
            project: Some("project-a".into()),
            ..Profile::default()
        }
    }

    #[cfg(unix)]
    fn refresh_token() -> SecretString {
        SecretString::new("refresh-token")
    }

    fn access_token() -> AccessToken {
        AccessToken::new("access-token")
    }

    #[cfg(unix)]
    fn shell(script: String) -> Vec<String> {
        vec!["sh".into(), "-c".into(), script]
    }

    /// Signals sent to the test process are relayed by every concurrent
    /// `run`, so tests that spawn children must not overlap.
    #[cfg(unix)]
    fn run_serialized(command: &[String], profile: &Profile) -> Result<ExitStatus> {
        static RUN_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = RUN_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        run(&name(), profile, command, &refresh_token(), &access_token())
    }

    fn configured_environment(command: &Command) -> BTreeMap<OsString, Option<OsString>> {
        command
            .get_envs()
            .map(|(key, value)| (key.to_owned(), value.map(OsStr::to_owned)))
            .collect()
    }

    #[test]
    fn child_environment_removes_competing_credentials_and_static_terraform_token() {
        let mut profile = profile();
        profile.account = None;
        profile.project = None;
        profile.quota_project = None;
        let access = access_token();
        let command = child_command(
            "program",
            &[],
            &name(),
            &profile,
            Path::new("/tmp/adc.json"),
            Path::new("/tmp/boto.cfg"),
            &access,
        );
        let environment = configured_environment(&command);

        for variable in [
            "BOTO_PATH",
            "GOOGLE_CREDENTIALS",
            "GOOGLE_BACKEND_CREDENTIALS",
            "GOOGLE_CLOUD_KEYFILE_JSON",
            "GOOGLE_OAUTH_ACCESS_TOKEN",
            "GOOGLE_IMPERSONATE_SERVICE_ACCOUNT",
            "CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT",
            "CLOUDSDK_CORE_ACCOUNT",
            "CLOUDSDK_CORE_PROJECT",
            "GOOGLE_CLOUD_PROJECT",
            "GOOGLE_CLOUD_QUOTA_PROJECT",
        ] {
            assert_eq!(
                environment.get(OsStr::new(variable)),
                Some(&None),
                "{variable} was not explicitly removed"
            );
        }
        assert_eq!(
            environment[OsStr::new("CLOUDSDK_AUTH_ACCESS_TOKEN")].as_deref(),
            Some(OsStr::new("access-token"))
        );
    }

    #[test]
    #[cfg(unix)]
    fn run_injects_env_writes_private_credential_files_and_deletes_them_afterward() {
        let output_directory = tempfile::tempdir().unwrap();
        let output = output_directory.path().join("environment.txt");
        let script = format!(
            "echo \"$GOOGLE_APPLICATION_CREDENTIALS\" > {out}; \
             echo \"$BOTO_CONFIG\" >> {out}; \
             echo \"$CLOUDSDK_AUTH_ACCESS_TOKEN|${{GOOGLE_OAUTH_ACCESS_TOKEN-unset}}|$GCPV_PROFILE|$CLOUDSDK_CORE_PROJECT|$GOOGLE_CLOUD_QUOTA_PROJECT|$CLOUDSDK_CORE_ACCOUNT\" >> {out}; \
             cat \"$GOOGLE_APPLICATION_CREDENTIALS\" \"$BOTO_CONFIG\" >> {out}",
            out = output.display()
        );
        let status = run_serialized(&shell(script), &profile()).unwrap();
        assert!(status.success());

        let data = std::fs::read_to_string(&output).unwrap();
        let mut lines = data.lines();
        let adc_path = lines.next().unwrap();
        assert!(adc_path.contains("gcpv-adc-"));
        assert!(!Path::new(adc_path).exists());
        let boto_path = lines.next().unwrap();
        assert!(boto_path.contains("gcpv-boto-"));
        assert!(!Path::new(boto_path).exists());
        assert_eq!(
            lines.next().unwrap(),
            "access-token|unset|test-profile|project-a|project-a|test@example.com"
        );
        assert!(data.contains("\"refresh_token\": \"refresh-token\""));
        assert!(data.contains("gs_oauth2_refresh_token = refresh-token"));
    }

    #[test]
    #[cfg(unix)]
    fn temporary_credential_files_have_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt as _;

        let refresh = refresh_token();
        for file in [
            temporary_adc(&profile(), &refresh).unwrap(),
            temporary_boto(&profile(), &refresh).unwrap(),
        ] {
            let mode = file.as_file().metadata().unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    #[cfg(unix)]
    fn run_returns_the_child_exit_status() {
        let status = run_serialized(&shell("exit 42".into()), &profile()).unwrap();
        assert_eq!(exit_code(status), 42);
    }

    #[cfg(unix)]
    #[test]
    fn relays_term_but_not_int_addressed_to_gcpv() {
        let output_directory = tempfile::tempdir().unwrap();
        let output = output_directory.path().join("signals");
        let script = format!(
            "int=0; term=0; trap 'int=$((int+1))' INT; trap 'term=$((term+1))' TERM; \
             kill -INT $PPID; kill -TERM $PPID; sleep 0.3; sleep 0.3; \
             echo \"$int $term\" > {}",
            output.display()
        );
        let status = run_serialized(&shell(script), &profile()).unwrap();
        assert!(status.success());
        assert_eq!(std::fs::read_to_string(&output).unwrap().trim(), "0 1");
    }

    #[cfg(unix)]
    #[test]
    fn run_cleans_up_when_the_child_dies_from_a_signal() {
        let output_directory = tempfile::tempdir().unwrap();
        let output = output_directory.path().join("adc-path");
        let script = format!(
            "echo \"$GOOGLE_APPLICATION_CREDENTIALS\" > {}; kill -TERM $$",
            output.display()
        );
        let status = run_serialized(&shell(script), &profile()).unwrap();
        assert_eq!(exit_code(status), 128 + 15);
        let adc_path = std::fs::read_to_string(&output).unwrap();
        assert!(!Path::new(adc_path.trim()).exists());
    }
}
