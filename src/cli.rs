use clap::{Parser, Subcommand};

use crate::config::ProfileName;

#[derive(Debug, Parser)]
#[command(
    name = "gcpv",
    version,
    about = "Run commands with named Google Cloud credentials from the OS keychain",
    arg_required_else_help = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create a profile and authenticate it
    Add {
        name: ProfileName,
        /// Expected Google account email
        #[arg(long)]
        account: Option<String>,
        /// Default Google Cloud project
        #[arg(long)]
        project: Option<String>,
        /// Quota/billing project (defaults to --project)
        #[arg(long)]
        quota_project: Option<String>,
        /// Service account to impersonate
        #[arg(long, value_name = "SA_EMAIL")]
        impersonate: Option<String>,
        /// Comma-separated API scopes replacing the defaults; identity scopes are always added
        #[arg(long, value_delimiter = ',', value_name = "SCOPES")]
        scopes: Option<Vec<String>>,
        /// Chrome profile directory or signed-in email to use for authentication
        #[arg(long, value_name = "DIR_OR_EMAIL")]
        browser_profile: Option<String>,
    },
    /// Re-authenticate a profile
    Login { name: ProfileName },
    /// List profiles
    #[command(visible_alias = "ls")]
    List,
    /// Delete a profile and its keychain credential
    #[command(visible_alias = "rm")]
    Remove { name: ProfileName },
    /// Run a command with the profile environment (no command starts $SHELL)
    Exec {
        name: ProfileName,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Print a fresh access token
    Token { name: ProfileName },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::error::ErrorKind;

    #[test]
    fn exec_preserves_child_arguments_after_separator() {
        let cli = Cli::try_parse_from([
            "gcpv",
            "exec",
            "work",
            "--",
            "terraform",
            "plan",
            "-out=plan.bin",
        ])
        .unwrap();

        let Command::Exec { name, command } = cli.command else {
            panic!("expected exec command");
        };
        assert_eq!(name.as_str(), "work");
        assert_eq!(command, ["terraform", "plan", "-out=plan.bin"]);
    }

    #[test]
    fn aliases_are_accepted() {
        assert!(matches!(
            Cli::try_parse_from(["gcpv", "ls"]).unwrap().command,
            Command::List
        ));
        assert!(matches!(
            Cli::try_parse_from(["gcpv", "rm", "work"]).unwrap().command,
            Command::Remove { .. }
        ));
    }

    #[test]
    fn profile_is_required_for_profile_commands() {
        let error = Cli::try_parse_from(["gcpv", "exec"]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn invalid_profile_name_is_rejected_during_parsing() {
        let error = Cli::try_parse_from(["gcpv", "login", "bad/name"]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::ValueValidation);
    }
}
