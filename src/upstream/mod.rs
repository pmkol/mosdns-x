use anyhow::Result;
use std::sync::Arc;
use trust_dns_proto::op::Message;

pub mod transport;

/// Upstream trait - represents a DNS upstream server
#[async_trait::async_trait]
pub trait Upstream: Send + Sync {
    /// Exchange a DNS query message with the upstream server
    async fn exchange(&self, query: &Message) -> Result<Message>;
}

/// Upstream configuration
#[derive(Debug, Clone)]
pub struct UpstreamConfig {
    pub addr: String,
    pub dial_addr: Option<String>,
    pub socks5: Option<String>,
    pub insecure: bool,
    pub idle_timeout: Option<u64>,
    pub max_conns: Option<usize>,
    pub bootstrap: Option<String>,
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        Self {
            addr: String::new(),
            dial_addr: None,
            socks5: None,
            insecure: false,
            idle_timeout: None,
            max_conns: None,
            bootstrap: None,
        }
    }
}

/// Create an upstream based on the address scheme
pub async fn create_upstream(config: UpstreamConfig) -> Result<Arc<dyn Upstream>> {
    let addr = if config.addr.contains("://") {
        config.addr.clone()
    } else {
        format!("udp://{}", config.addr)
    };

    let scheme = addr.split("://").next().unwrap_or("udp");
    
    match scheme {
        "udp" | "" => {
            let transport = transport::UdpTransport::new(&addr).await?;
            Ok(Arc::new(transport))
        }
        "tcp" => {
            let transport = transport::TcpTransport::new(&addr).await?;
            Ok(Arc::new(transport))
        }
        _ => anyhow::bail!("unsupported upstream scheme: {}", scheme),
    }
}
