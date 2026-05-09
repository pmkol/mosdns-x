use super::Upstream;
use anyhow::{Context, Result};
use std::net::SocketAddr;
use tokio::net::{TcpStream, UdpSocket};
use trust_dns_proto::op::Message;
use trust_dns_proto::serialize::binary::BinDecodable;

/// UDP transport for DNS queries
pub struct UdpTransport {
    socket: UdpSocket,
    server_addr: SocketAddr,
}

impl UdpTransport {
    pub async fn new(addr: &str) -> Result<Self> {
        let server_addr = parse_addr(addr)?;
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(server_addr).await?;
        Ok(Self { socket, server_addr })
    }
}

#[async_trait::async_trait]
impl Upstream for UdpTransport {
    async fn exchange(&self, query: &Message) -> Result<Message> {
        let query_bytes = query.to_vec()?;
        
        // Send query
        self.socket.send(&query_bytes).await?;
        
        // Receive response
        let mut buf = vec![0u8; 4096];
        let len = self.socket.recv(&mut buf).await?;
        buf.truncate(len);
        
        let response = Message::from_bytes(&buf)?;
        Ok(response)
    }
}

/// TCP transport for DNS queries
pub struct TcpTransport {
    server_addr: SocketAddr,
}

impl TcpTransport {
    pub async fn new(addr: &str) -> Result<Self> {
        let server_addr = parse_addr(addr)?;
        Ok(Self { server_addr })
    }
}

#[async_trait::async_trait]
impl Upstream for TcpTransport {
    async fn exchange(&self, query: &Message) -> Result<Message> {
        let mut stream = TcpStream::connect(self.server_addr).await?;
        
        let query_bytes = query.to_vec()?;
        
        // Write length-prefixed message
        let len = query_bytes.len() as u16;
        stream.write_all(&len.to_be_bytes()).await?;
        stream.write_all(&query_bytes).await?;
        
        // Read length-prefixed response
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await?;
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        
        let mut resp_buf = vec![0u8; resp_len];
        stream.read_exact(&mut resp_buf).await?;
        
        let response = Message::from_bytes(&resp_buf)?;
        Ok(response)
    }
}

use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn parse_addr(addr: &str) -> Result<SocketAddr> {
    let addr = addr.strip_prefix("udp://")
        .or_else(|| addr.strip_prefix("tcp://"))
        .unwrap_or(addr);
    
    addr.parse::<SocketAddr>()
        .or_else(|_| {
            // Try with default port 53
            format!("{}:53", addr).parse::<SocketAddr>()
        })
        .with_context(|| format!("invalid address: {}", addr))
}
