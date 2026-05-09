use std::net::{IpAddr, SocketAddr};

/// Extract IP address from a socket address string
pub fn extract_ip(addr: &str) -> Option<IpAddr> {
    addr.parse::<SocketAddr>()
        .ok()
        .map(|sa| sa.ip())
        .or_else(|| addr.parse::<IpAddr>().ok())
}

/// Format duration in human-readable form
pub fn format_duration(d: std::time::Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m{}s", secs / 60, secs % 60)
    } else {
        format!("{}h{}m{}s", secs / 3600, (secs % 3600) / 60, secs % 60)
    }
}

/// Generate a cache key from a DNS query
pub fn query_cache_key(msg: &trust_dns_proto::op::Message) -> String {
    let query = msg.queries().first();
    match query {
        Some(q) => format!("{}#{}#{}#{}", 
            q.name(),
            q.query_type(),
            q.query_class(),
            msg.op_code()
        ),
        None => format!("empty#{}#{}", msg.id(), msg.op_code()),
    }
}
