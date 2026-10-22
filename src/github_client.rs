use log::{debug, info, warn};
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
        info!("Found GH_TOKEN or GITHUB_TOKEN.");
        return Ok(Some(env_token));
    }

    // Check if it has gh command and has valid token from it
    debug!("Falling back to the `gh auth token` command.");
    let command_result = Command::new(COMMAND_GH)
        .args(COMMAND_GH_AUTH_TOKEN_ARGS)
        .output()
        .await;

    match command_result {
        Ok(command_output) if command_output.status.success() => {
            info!("Retrieved a token from the `gh auth token` command.");
            return Ok(Some(
                String::from_utf8(command_output.stdout)?.trim().to_string(),
            ));
        }
        Ok(command_output) => {
            debug!(
                "The `gh auth token` command failed with {}.",
                command_output.status
            );
        }
        Err(e) => {
            debug!("Could not run the `gh` command: {}.", e);
        }
    }

    // Could not get token, will fall back to None
    warn!(
        "Failed to retrieve GitHub PAT from your environment. It will call the API anonymously. Be careful of the API rate limit! Set `GH_TOKEN` or `GITHUB_TOKEN`, or log in with `gh auth login`."
    );
    Ok(None)
}

pub async fn init_octocrab() -> Result<Octocrab, Box<dyn Error>> {
    let mut builder = Octocrab::builder();

    let pat_result = get_github_pat().await?;
    if let Some(pat) = pat_result {
        debug!("Initializing the GitHub client with a personal access token.");
        builder = builder.personal_token(pat);
    }

    Ok(builder.build()?)
}
