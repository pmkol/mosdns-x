use crate::query_context::{QueryContext, RequestMeta};
use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, UdpSocket};
use tracing::{info, warn};
use trust_dns_proto::op::Message;
use trust_dns_proto::serialize::binary::BinDecodable;

pub mod handler;

use handler::DnsHandler;

/// Server options
#[derive(Clone)]
pub struct ServerOpts {
    pub dns_handler: Arc<dyn DnsHandler>,
    pub idle_timeout: std::time::Duration,
}

/// DNS Server supporting multiple protocols
pub struct Server {
    opts: ServerOpts,
}

impl Server {
    pub fn new(opts: ServerOpts) -> Self {
        Self { opts }
    }

    /// Serve UDP DNS requests
    pub async fn serve_udp(&self, bind_addr: SocketAddr) -> Result<()> {
        let socket = Arc::new(UdpSocket::bind(bind_addr).await?);
        info!("UDP server listening on {}", bind_addr);

        let mut buf = vec![0u8; 4096];
        loop {
            let (len, peer) = socket.recv_from(&mut buf).await?;
            let data = buf[..len].to_vec();
            
            let handler = self.opts.dns_handler.clone();
            let socket_clone = socket.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_udp_query(handler, data, peer, socket_clone).await {
                    warn!("UDP query error from {}: {}", peer, e);
                }
            });
        }
    }

    /// Serve TCP DNS requests
    pub async fn serve_tcp(&self, bind_addr: SocketAddr) -> Result<()> {
        let listener = TcpListener::bind(bind_addr).await?;
        info!("TCP server listening on {}", bind_addr);

        loop {
            let (stream, peer) = listener.accept().await?;
            let handler = self.opts.dns_handler.clone();
            
            tokio::spawn(async move {
                if let Err(e) = handle_tcp_connection(handler, stream, peer).await {
                    warn!("TCP connection error from {}: {}", peer, e);
                }
            });
        }
    }
}

async fn handle_udp_query(
    handler: Arc<dyn DnsHandler>,
    data: Vec<u8>,
    peer: SocketAddr,
    socket: Arc<UdpSocket>,
) -> Result<()> {
    let query = Message::from_bytes(&data)?;
    let meta = RequestMeta::new(peer.ip()).with_protocol(crate::query_context::PROTOCOL_UDP);
    let mut ctx = QueryContext::new(query, meta);

    handler.handle(&mut ctx).await?;

    if let Some(response) = ctx.take_response() {
        let resp_bytes = response.to_vec()?;
        socket.send_to(&resp_bytes, peer).await?;
    }

    Ok(())
}

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

async fn handle_tcp_connection(
    handler: Arc<dyn DnsHandler>,
    mut stream: TcpStream,
    peer: SocketAddr,
) -> Result<()> {
    let meta = RequestMeta::new(peer.ip()).with_protocol(crate::query_context::PROTOCOL_TCP);

    loop {
        // Read length-prefixed message
        let mut len_buf = [0u8; 2];
        match stream.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }

        let len = u16::from_be_bytes(len_buf) as usize;
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await?;

        let query = Message::from_bytes(&buf)?;
        let mut ctx = QueryContext::new(query, meta.clone());

        match handler.handle(&mut ctx).await {
            Ok(()) => {
                if let Some(response) = ctx.take_response() {
                    let resp_bytes = response.to_vec()?;
                    let resp_len = resp_bytes.len() as u16;
                    stream.write_all(&resp_len.to_be_bytes()).await?;
                    stream.write_all(&resp_bytes).await?;
                }
            }
            Err(e) => {
                warn!("TCP query error from {}: {}", peer, e);
            }
        }
    }

    Ok(())
}
