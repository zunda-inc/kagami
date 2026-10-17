use crate::libkagami::Config;
use std::error::Error;
use std::fs;

fn parse_config_file(file_path: &str) -> Result<Config, Box<dyn Error>> {
    let config_content = fs::read_to_string(file_path)?;
    let parsed_config: Config = yaml_serde::from_str(config_content.as_str())?;
    Ok(parsed_config)
}
