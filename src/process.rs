use std::io::Write as _;
use std::path::Path;
use std::process::{Command, ExitStatus};
use std::sync::OnceLock;
#[cfg(unix)]
use std::time::Duration;

use anyhow::{Context, Result, anyhow};

use crate::config::{Profile, ProfileName};
use crate::credentials::{self, AccessToken};
use crate::secret::SecretString;

const CLEAN_ENVIRONMENT: &[&str] = &[
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
    let signals = install_signal_handlers()?;

    let mut adc_file = tempfile::Builder::new()
        .prefix("gcpv-adc-")
        .suffix(".json")
        .tempfile()
        .context("creating temporary ADC file")?;
    serde_json::to_writer_pretty(&mut adc_file, &credentials::adc(profile, refresh_token))
        .context("writing temporary ADC file")?;
    adc_file.flush().context("flushing temporary ADC file")?;

    let (program, arguments) = match command {
        [] => (default_shell(), &[] as &[String]),
        [program, arguments @ ..] => (program.clone(), arguments),
    };
    let mut command = child_command(
        &program,
        arguments,
        name,
        profile,
        adc_file.path(),
        access_token,
    );
    let mut child = command
        .spawn()
        .with_context(|| format!("running {program}"))?;
    let status = wait_for_child(&mut child, &signals)?;
    drop(adc_file);
    Ok(status)
}

#[cfg(unix)]
#[derive(Clone)]
struct SignalState {
    interrupt: std::sync::Arc<std::sync::atomic::AtomicBool>,
    terminate: std::sync::Arc<std::sync::atomic::AtomicBool>,
    hangup: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

#[cfg(unix)]
impl SignalState {
    fn clear(&self) {
        use std::sync::atomic::Ordering;
        self.interrupt.store(false, Ordering::Relaxed);
        self.terminate.store(false, Ordering::Relaxed);
        self.hangup.store(false, Ordering::Relaxed);
    }

    fn take(&self) -> Option<rustix::process::Signal> {
        use std::sync::atomic::Ordering;
        if self.interrupt.swap(false, Ordering::Relaxed) {
            return Some(rustix::process::Signal::INT);
        }
        if self.terminate.swap(false, Ordering::Relaxed) {
            return Some(rustix::process::Signal::TERM);
        }
        if self.hangup.swap(false, Ordering::Relaxed) {
            return Some(rustix::process::Signal::HUP);
        }
        None
    }
}

#[cfg(windows)]
type SignalState = ();

#[cfg(not(any(unix, windows)))]
type SignalState = ();

#[cfg(unix)]
fn wait_for_child(child: &mut std::process::Child, signals: &SignalState) -> Result<ExitStatus> {
    let pid = rustix::process::Pid::from_raw(child.id() as i32)
        .context("child process ID was outside the supported range")?;
    loop {
        if let Some(status) = child.try_wait().context("waiting for child process")? {
            return Ok(status);
        }
        while let Some(signal) = signals.take() {
            // Terminal-generated signals already reach the child process. This
            // also covers signals sent only to the gcpv parent.
            let _ = rustix::process::kill_process(pid, signal);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(not(unix))]
fn wait_for_child(child: &mut std::process::Child, _signals: &SignalState) -> Result<ExitStatus> {
    child.wait().context("waiting for child process")
}

fn child_command(
    program: &str,
    arguments: &[String],
    name: &ProfileName,
    profile: &Profile,
    adc_path: &Path,
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

#[cfg(unix)]
fn install_signal_handlers() -> Result<SignalState> {
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    static INSTALLATION: OnceLock<std::result::Result<SignalState, String>> = OnceLock::new();
    let already_installed = INSTALLATION.get().is_some();
    let state = INSTALLATION
        .get_or_init(|| {
            let state = SignalState {
                interrupt: Arc::new(AtomicBool::new(false)),
                terminate: Arc::new(AtomicBool::new(false)),
                hangup: Arc::new(AtomicBool::new(false)),
            };
            signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&state.interrupt))
                .map_err(|error| error.to_string())?;
            signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&state.terminate))
                .map_err(|error| error.to_string())?;
            signal_hook::flag::register(signal_hook::consts::SIGHUP, Arc::clone(&state.hangup))
                .map_err(|error| error.to_string())?;
            Ok(state)
        })
        .clone()
        .map_err(|error| anyhow!("installing signal handlers: {error}"))?;
    if already_installed {
        state.clear();
    }
    Ok(state)
}

#[cfg(windows)]
fn install_signal_handlers() -> Result<SignalState> {
    static INSTALLATION: OnceLock<std::result::Result<(), String>> = OnceLock::new();
    INSTALLATION
        .get_or_init(|| ctrlc::set_handler(|| {}).map_err(|error| error.to_string()))
        .clone()
        .map_err(|error| anyhow!("installing Ctrl-C handler: {error}"))?;
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn install_signal_handlers() -> Result<SignalState> {
    Ok(())
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
            &access,
        );
        let environment = configured_environment(&command);

        for variable in [
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
    fn run_injects_env_writes_private_adc_and_deletes_it_afterward() {
        let output_directory = tempfile::tempdir().unwrap();
        let output = output_directory.path().join("environment.txt");
        let script = format!(
            "echo \"$GOOGLE_APPLICATION_CREDENTIALS\" > {out}; \
             stat -f %Lp \"$GOOGLE_APPLICATION_CREDENTIALS\" >> {out} 2>/dev/null \
               || stat -c %a \"$GOOGLE_APPLICATION_CREDENTIALS\" >> {out}; \
             echo \"$CLOUDSDK_AUTH_ACCESS_TOKEN|${{GOOGLE_OAUTH_ACCESS_TOKEN-unset}}|$GCPV_PROFILE|$CLOUDSDK_CORE_PROJECT|$GOOGLE_CLOUD_QUOTA_PROJECT|$CLOUDSDK_CORE_ACCOUNT\" >> {out}; \
             cat \"$GOOGLE_APPLICATION_CREDENTIALS\" >> {out}",
            out = output.display()
        );
        let refresh = refresh_token();
        let access = access_token();
        let status = run(&name(), &profile(), &shell(script), &refresh, &access).unwrap();
        assert!(status.success());

        let data = std::fs::read_to_string(&output).unwrap();
        let mut lines = data.lines();
        let adc_path = lines.next().unwrap();
        assert!(adc_path.contains("gcpv-adc-"));
        assert!(!Path::new(adc_path).exists());
        assert_eq!(lines.next().unwrap(), "600");
        assert_eq!(
            lines.next().unwrap(),
            "access-token|unset|test-profile|project-a|project-a|test@example.com"
        );
        assert!(data.contains("\"refresh_token\": \"refresh-token\""));
    }

    #[test]
    #[cfg(unix)]
    fn run_returns_the_child_exit_status() {
        let refresh = refresh_token();
        let access = access_token();
        let status = run(
            &name(),
            &profile(),
            &shell("exit 42".into()),
            &refresh,
            &access,
        )
        .unwrap();
        assert_eq!(exit_code(status), 42);
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
        let refresh = refresh_token();
        let access = access_token();
        let status = run(&name(), &profile(), &shell(script), &refresh, &access).unwrap();
        assert_eq!(exit_code(status), 128 + 15);
        let adc_path = std::fs::read_to_string(&output).unwrap();
        assert!(!Path::new(adc_path.trim()).exists());
    }
}
