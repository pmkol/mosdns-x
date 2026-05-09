use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Instant;
use trust_dns_proto::op::Message;

pub const PROTOCOL_UDP: &str = "udp";
pub const PROTOCOL_TCP: &str = "tcp";
pub const PROTOCOL_TLS: &str = "tls";
pub const PROTOCOL_QUIC: &str = "quic";
pub const PROTOCOL_HTTP: &str = "http";
pub const PROTOCOL_HTTPS: &str = "https";
pub const PROTOCOL_H2: &str = "h2";
pub const PROTOCOL_H3: &str = "h3";

#[derive(Debug, Clone)]
pub struct RequestMeta {
    client_addr: Option<IpAddr>,
    #[allow(dead_code)]
    server_name: Option<String>,
    protocol: String,
}

impl RequestMeta {
    pub fn new(addr: IpAddr) -> Self {
        Self {
            client_addr: Some(addr),
            server_name: None,
            protocol: PROTOCOL_UDP.to_string(),
        }
    }

    pub fn with_protocol(mut self, protocol: &str) -> Self {
        self.protocol = protocol.to_string();
        self
    }

    #[allow(dead_code)]
    pub fn set_server_name(&mut self, name: String) {
        self.server_name = Some(name);
    }

    pub fn client_addr(&self) -> Option<IpAddr> {
        self.client_addr
    }

    #[allow(dead_code)]
    pub fn protocol(&self) -> &str {
        &self.protocol
    }

    #[allow(dead_code)]
    pub fn server_name(&self) -> Option<&str> {
        self.server_name.as_deref()
    }
}

static CONTEXT_ID: AtomicU32 = AtomicU32::new(0);

#[derive(Debug)]
pub struct QueryContext {
    #[allow(dead_code)]
    id: u32,
    #[allow(dead_code)]
    start_time: Instant,
    query: Message,
    #[allow(dead_code)]
    original_query: Message,
    #[allow(dead_code)]
    request_meta: RequestMeta,
    response: Option<Message>,
    #[allow(dead_code)]
    marks: Vec<u32>,
}

impl QueryContext {
    pub fn new(query: Message, meta: RequestMeta) -> Self {
        let id = CONTEXT_ID.fetch_add(1, Ordering::SeqCst);
        Self {
            id,
            start_time: Instant::now(),
            original_query: query.clone(),
            query,
            request_meta: meta,
            response: None,
            marks: Vec::new(),
        }
    }

    #[allow(dead_code)]
    pub fn id(&self) -> u32 {
        self.id
    }

    pub fn query(&self) -> &Message {
        &self.query
    }

    #[allow(dead_code)]
    pub fn original_query(&self) -> &Message {
        &self.original_query
    }

    #[allow(dead_code)]
    pub fn request_meta(&self) -> &RequestMeta {
        &self.request_meta
    }

    pub fn response(&self) -> Option<&Message> {
        self.response.as_ref()
    }

    pub fn set_response(&mut self, response: Message) {
        self.response = Some(response);
    }

    pub fn take_response(&mut self) -> Option<Message> {
        self.response.take()
    }

    #[allow(dead_code)]
    pub fn start_time(&self) -> Instant {
        self.start_time
    }

    #[allow(dead_code)]
    pub fn add_mark(&mut self, mark: u32) {
        if !self.marks.contains(&mark) {
            self.marks.push(mark);
        }
    }

    #[allow(dead_code)]
    pub fn has_mark(&self, mark: u32) -> bool {
        self.marks.contains(&mark)
    }
}

impl std::fmt::Display for QueryContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let question = self.query.queries().first()
            .map(|q| format!("{} {:?} {:?}", q.name(), q.query_class(), q.query_type()))
            .unwrap_or_else(|| "empty question".to_string());
        let client = self.request_meta.client_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|| "unknown client".to_string());
        write!(f, "{} {} {} {}", question, self.query.id(), self.id, client)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use trust_dns_proto::op::Message;
    use trust_dns_proto::rr::{Name, RecordType};
    use trust_dns_proto::rr::rdata::A;

    #[test]
    fn test_request_meta() {
        let addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let meta = RequestMeta::new(addr).with_protocol(PROTOCOL_TCP);
        
        assert_eq!(meta.client_addr(), Some(addr));
        assert_eq!(meta.protocol(), PROTOCOL_TCP);
        assert!(meta.server_name().is_none());
    }

    #[test]
    fn test_query_context() {
        let query = Message::new();
        let addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let meta = RequestMeta::new(addr);
        let mut ctx = QueryContext::new(query, meta);
        
        assert!(ctx.response().is_none());
        
        let response = Message::new();
        ctx.set_response(response);
        assert!(ctx.response().is_some());
        
        let taken = ctx.take_response();
        assert!(taken.is_some());
        assert!(ctx.response().is_none());
    }

    #[test]
    fn test_query_context_marks() {
        let query = Message::new();
        let addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let meta = RequestMeta::new(addr);
        let mut ctx = QueryContext::new(query, meta);
        
        assert!(!ctx.has_mark(1));
        ctx.add_mark(1);
        assert!(ctx.has_mark(1));
        
        // Duplicate marks should not be added
        ctx.add_mark(1);
        assert!(ctx.has_mark(1));
    }
}
