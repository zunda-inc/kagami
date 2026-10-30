use crate::error::KagamiError;
use log::error;
use std::error::Error;
use std::path::Path;

pub fn resolve_config_file_path(
    config_file_path: Option<impl Into<String>>,
) -> Result<String, Box<dyn Error>> {
    let config_path = match config_file_path {
        Some(s) => Ok(s.into()),
        None => {
            if Path::new("kagami.yaml").exists() {
                Ok("kagami.yaml".to_string())
            } else if Path::new("kagami.yml").exists() {
                Ok("kagami.yml".to_string())
            } else {
                error!(
                    "The config file path was not provided, and no default config file was found in the current directory. Have you placed either 'kagami.yml' or 'kagami.yaml'?"
                );
                Err(Box::new(KagamiError::FailedToResolveConfigFilePath()))
            }
        }
    }?;

    Ok(config_path)
}
