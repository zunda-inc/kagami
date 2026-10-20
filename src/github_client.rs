use log::{debug, warn};
use octocrab::Octocrab;
use std::env;
use std::error::Error;
use tokio::process::Command;

const ENV_GH_TOKEN: &str = "GH_TOKEN";
const ENV_GITHUB_TOKEN: &str = "GITHUB_TOKEN";
const COMMAND_GH: &str = "gh";
const COMMAND_GH_AUTH_TOKEN_ARGS: [&str; 2] = ["auth", "token"];

async fn get_github_pat() -> Result<Option<String>, Box<dyn Error>> {
    // Check if it has environment variables
    let env_gh_token = env::var(ENV_GH_TOKEN);
    let env_github_token = env::var(ENV_GITHUB_TOKEN);
    if let Ok(env_token) = env_gh_token.or(env_github_token) {
        debug!("Found GH_TOKEN or GITHUB_TOKEN.");
        return Ok(Some(env_token));
    }

    // Check if it has gh command and has valid token from it
    debug!("Fall backing to `gh auth token` command.");
    let command_result = Command::new(COMMAND_GH)
        .args(COMMAND_GH_AUTH_TOKEN_ARGS)
        .output()
        .await;
    if let Ok(command_output) = command_result {
        if !command_output.status.success() {
            warn!(
                "Failed to run `gh auth token` command. Command's status code returned non zero value."
            );
            ()
        }
        return Ok(Some(
            String::from_utf8(command_output.stdout)?.trim().to_string(),
        ));
    }

    if let Err(e) = command_result {
        warn!("Failed to run `gh auth token` command.");
        warn!("{}", e.to_string());
    }

    // Could not get token, will fall back to None
    warn!(
        "Failed to retrieve GitHub PAT from your environment. It will call the API anonymously. Be careful for the API rate limiting!"
    );
    Ok(None)
}

pub async fn init_octocrab() -> Result<Octocrab, Box<dyn Error>> {
    let mut builder = Octocrab::builder();

    let pat_result = get_github_pat().await?;
    if let Some(pat) = pat_result {
        builder = builder.personal_token(pat);
    }

    Ok(builder.build()?)
}
