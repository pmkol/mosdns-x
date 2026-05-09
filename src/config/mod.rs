use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default, rename = "data_providers")]
    pub data_providers: Vec<DataProviderConfig>,
    #[serde(default)]
    pub plugins: Vec<PluginConfig>,
    #[serde(default)]
    pub servers: Vec<ServerConfig>,
    #[serde(default)]
    pub api: ApiConfig,
    #[serde(default)]
    pub security: SecurityConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct LogConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default)]
    pub file: Option<String>,
    #[serde(default)]
    pub production: bool,
    #[serde(default)]
    pub omit_time: bool,
}

fn default_log_level() -> String {
    "info".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DataProviderConfig {
    pub tag: String,
    #[serde(flatten)]
    pub args: HashMap<String, serde_yaml::Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PluginConfig {
    pub tag: String,
    #[serde(rename = "type")]
    pub plugin_type: String,
    #[serde(default)]
    pub args: Option<serde_yaml::Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    #[serde(default)]
    pub exec: String,
    #[serde(default)]
    pub timeout: Option<u64>,
    #[serde(default)]
    pub listeners: Vec<ServerListenerConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerListenerConfig {
    #[serde(default)]
    pub protocol: String,
    pub addr: String,
    #[serde(default, rename = "uds")]
    pub unix_domain_socket: bool,
    #[serde(default)]
    pub cert: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default, rename = "kernel_tx")]
    pub kernel_tx: bool,
    #[serde(default, rename = "kernel_rx")]
    pub kernel_rx: bool,
    #[serde(default, rename = "url_path")]
    pub url_path: Option<String>,
    #[serde(default, rename = "get_user_ip_from_header")]
    pub get_user_ip_from_header: Option<String>,
    #[serde(default, rename = "proxy_protocol")]
    pub proxy_protocol: bool,
    #[serde(default, rename = "idle_timeout")]
    pub idle_timeout: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct ApiConfig {
    #[serde(default)]
    pub http: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct SecurityConfig {
    #[serde(default, rename = "bad_ip_observer")]
    pub bad_ip_observer: BadIpObserverConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct BadIpObserverConfig {
    #[serde(default)]
    pub threshold: i32,
    #[serde(default = "default_interval")]
    pub interval: u64,
    #[serde(default = "default_ttl")]
    pub ttl: u64,
    #[serde(default, rename = "on_update_callback")]
    pub on_update_callback: String,
    #[serde(default = "default_ipv4_mask")]
    pub ipv4_mask: u8,
    #[serde(default = "default_ipv6_mask")]
    pub ipv6_mask: u8,
}

fn default_interval() -> u64 { 10 }
fn default_ttl() -> u64 { 600 }
fn default_ipv4_mask() -> u8 { 32 }
fn default_ipv6_mask() -> u8 { 48 }

impl Config {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path.as_ref())
            .with_context(|| format!("Failed to read config file: {:?}", path.as_ref()))?;
        let mut cfg: Config = serde_yaml::from_str(&content)
            .with_context(|| "Failed to parse config file")?;
        
        // Process includes
        cfg.merge_includes(0, &[])?;
        
        Ok(cfg)
    }

    fn merge_includes(&mut self, depth: usize, _paths: &[String]) -> Result<()> {
        if depth > 8 {
            anyhow::bail!("maximum include depth reached");
        }

        let mut included = Config {
            log: LogConfig::default(),
            include: vec![],
            data_providers: vec![],
            plugins: vec![],
            servers: vec![],
            api: ApiConfig::default(),
            security: SecurityConfig::default(),
        };

        for sub_cfg_file in &self.include {
            let sub_cfg = Config::load(sub_cfg_file)?;
            included.data_providers.extend(sub_cfg.data_providers);
            included.plugins.extend(sub_cfg.plugins);
            included.servers.extend(sub_cfg.servers);
        }

        self.data_providers.splice(0..0, included.data_providers);
        self.plugins.splice(0..0, included.plugins);
        self.servers.splice(0..0, included.servers);
        
        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            log: LogConfig::default(),
            include: vec![],
            data_providers: vec![],
            plugins: vec![],
            servers: vec![],
            api: ApiConfig::default(),
            security: SecurityConfig::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let cfg = Config::default();
        assert!(cfg.plugins.is_empty());
        assert!(cfg.servers.is_empty());
        // Default log level is empty string from Default impl, "info" only from deserialization
        assert_eq!(cfg.log.level, "");
    }

    #[test]
    fn test_config_parse() {
        let yaml = r#"
log:
  level: debug
servers:
  - exec: main_sequence
    listeners:
      - protocol: udp
        addr: 127.0.0.1:53
plugins:
  - tag: main_sequence
    type: sequence
"#;
        let cfg: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.log.level, "debug");
        assert_eq!(cfg.servers.len(), 1);
        assert_eq!(cfg.servers[0].exec, "main_sequence");
        assert_eq!(cfg.servers[0].listeners.len(), 1);
        assert_eq!(cfg.servers[0].listeners[0].addr, "127.0.0.1:53");
        assert_eq!(cfg.plugins.len(), 1);
        assert_eq!(cfg.plugins[0].tag, "main_sequence");
        assert_eq!(cfg.plugins[0].plugin_type, "sequence");
    }
}
