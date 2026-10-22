use crate::Config;
use log::{debug, trace};
use std::error::Error;
use std::fs;

pub fn parse_config_file(file_path: impl Into<String>) -> Result<Config, Box<dyn Error>> {
    let file_path = file_path.into();
    debug!("Reading the config file `{}`.", file_path);

    let config_content = fs::read_to_string(&file_path)?;
    trace!("Read {} bytes from `{}`.", config_content.len(), file_path);

    let parsed_config: Config = yaml_serde::from_str(config_content.as_str())?;
    debug!(
        "Parsed the config file, {} targets are defined.",
        parsed_config.targets.len()
    );
    trace!("Parsed config: {:?}.", parsed_config);

    Ok(parsed_config)
}
