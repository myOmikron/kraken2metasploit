use std::fs::read_to_string;

use serde::Deserialize;
use url::Url;

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DBConfig {
    pub host: String,
    pub port: u16,
    pub name: String,
    pub user: String,
    pub password: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct KrakenConfig {
    pub url: Url,
    pub user: String,
    pub password: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Config {
    pub database: DBConfig,
    pub kraken: KrakenConfig,
}

impl Config {
    pub fn from_path(path: &str) -> Result<Self, String> {
        let data =
            read_to_string(path).map_err(|e| format!("File could not be read: {path}: {e}"))?;

        let config =
            toml::from_str(&data).map_err(|e| format!("Config could not be parsed: {e}"))?;

        Ok(config)
    }
}
