use std::error::Error;
use std::fs;
use crate::Config;

pub fn parse_config_file(file_path: impl Into<String>) -> Result<Config, Box<dyn Error>> {
    let config_content = fs::read_to_string(file_path.into())?;
    let parsed_config: Config = yaml_serde::from_str(config_content.as_str())?;
    Ok(parsed_config)
}
