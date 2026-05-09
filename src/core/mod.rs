use crate::config::{Config, ServerConfig};
use crate::plugin::PluginRegistry;
use crate::server::{handler::EntryHandler, Server, ServerOpts};
use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

/// Core mosdns structure
pub struct Mosdns {
    plugin_registry: Arc<RwLock<PluginRegistry>>,
}

impl Mosdns {
    pub fn new() -> Self {
        Self {
            plugin_registry: Arc::new(RwLock::new(PluginRegistry::new())),
        }
    }

    pub async fn run(cfg: Config) -> Result<()> {
        let mosdns = Arc::new(Self::new());
        
        // Initialize plugins
        mosdns.init_plugins(&cfg).await?;

        // Start servers
        let mut handles = vec![];
        for server_config in &cfg.servers {
            let handle = mosdns.start_server(server_config).await?;
            handles.push(handle);
        }

        // Wait for all servers (they run indefinitely)
        for handle in handles {
            if let Err(e) = handle.await {
                error!("Server error: {}", e);
            }
        }

        Ok(())
    }

    async fn init_plugins(&self, cfg: &Config) -> Result<()> {
        let _registry = self.plugin_registry.write().await;
        
        // Register built-in plugins from config
        for plugin_config in &cfg.plugins {
            info!("Loading plugin: {} (type: {})", plugin_config.tag, plugin_config.plugin_type);
            
            // TODO: Implement plugin factory based on type
            match plugin_config.plugin_type.as_str() {
                "sequence" => {
                    // Parse sequence args and create plugin
                }
                "forward" => {
                    // Create forward plugin
                }
                _ => {
                    warn!("Unknown plugin type: {}", plugin_config.plugin_type);
                }
            }
        }

        Ok(())
    }

    async fn start_server(&self, cfg: &ServerConfig) -> Result<tokio::task::JoinHandle<Result<()>>> {
        if cfg.listeners.is_empty() {
            anyhow::bail!("no server listener is configured");
        }
        if cfg.exec.is_empty() {
            anyhow::bail!("empty entry");
        }

        let registry = self.plugin_registry.read().await;
        let entry = registry.get_executable(&cfg.exec)
            .context(format!("cannot find entry {}", cfg.exec))?;
        drop(registry);

        let query_timeout = cfg.timeout.map(Duration::from_secs).unwrap_or(Duration::from_secs(5));
        let handler = Arc::new(EntryHandler::new(entry, query_timeout, true));

        let server = Arc::new(Server::new(ServerOpts {
            dns_handler: handler,
            idle_timeout: Duration::from_secs(10),
        }));

        let mut listeners = vec![];
        for listener_cfg in &cfg.listeners {
            let addr = listener_cfg.addr.parse::<SocketAddr>()
                .context(format!("invalid address: {}", listener_cfg.addr))?;
            listeners.push((listener_cfg.protocol.clone(), addr));
        }

        let handle = tokio::spawn(async move {
            let mut handles = vec![];
            
            for (protocol, addr) in listeners {
                let server_clone = server.clone();
                let handle = match protocol.as_str() {
                    "" | "udp" => {
                        tokio::spawn(async move {
                            server_clone.serve_udp(addr).await
                        })
                    }
                    "tcp" => {
                        tokio::spawn(async move {
                            server_clone.serve_tcp(addr).await
                        })
                    }
                    _ => {
                        warn!("Unsupported protocol: {}", protocol);
                        continue;
                    }
                };
                handles.push(handle);
            }

            for handle in handles {
                if let Err(e) = handle.await {
                    error!("Listener error: {}", e);
                }
            }

            Ok(())
        });

        Ok(handle)
    }
}

impl Default for Mosdns {
    fn default() -> Self {
        Self::new()
    }
}
