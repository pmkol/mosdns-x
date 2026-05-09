use anyhow::Result;
use regex::Regex;
use std::net::IpAddr;

/// Domain matcher using suffix matching
pub struct DomainMatcher {
    patterns: Vec<String>,
}

impl DomainMatcher {
    pub fn new(patterns: Vec<String>) -> Self {
        Self { patterns }
    }

    pub fn matches(&self, domain: &str) -> bool {
        let domain = domain.to_lowercase();
        for pattern in &self.patterns {
            if domain.ends_with(pattern) || domain == *pattern {
                return true;
            }
        }
        false
    }
}

/// IP network matcher
pub struct IpMatcher {
    networks: Vec<ipnet::IpNet>,
}

impl IpMatcher {
    pub fn new(networks: Vec<ipnet::IpNet>) -> Self {
        Self { networks }
    }

    pub fn matches(&self, addr: IpAddr) -> bool {
        for network in &self.networks {
            if network.contains(&addr) {
                return true;
            }
        }
        false
    }
}

/// Regex matcher
pub struct RegexMatcher {
    regex: Regex,
}

impl RegexMatcher {
    pub fn new(pattern: &str) -> Result<Self> {
        let regex = Regex::new(pattern)?;
        Ok(Self { regex })
    }

    pub fn matches(&self, text: &str) -> bool {
        self.regex.is_match(text)
    }
}

/// Query type matcher
pub struct QueryTypeMatcher {
    types: Vec<trust_dns_proto::rr::RecordType>,
}

impl QueryTypeMatcher {
    pub fn new(types: Vec<trust_dns_proto::rr::RecordType>) -> Self {
        Self { types }
    }

    pub fn matches(&self, query_type: trust_dns_proto::rr::RecordType) -> bool {
        self.types.contains(&query_type)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_matcher() {
        let matcher = DomainMatcher::new(vec![
            "example.com".to_string(),
            "test.org".to_string(),
        ]);

        assert!(matcher.matches("www.example.com"));
        assert!(matcher.matches("example.com"));
        assert!(matcher.matches("sub.test.org"));
        assert!(!matcher.matches("other.com"));
    }

    #[test]
    fn test_ip_matcher() {
        let networks = vec![
            "192.168.0.0/16".parse().unwrap(),
            "10.0.0.0/8".parse().unwrap(),
        ];
        let matcher = IpMatcher::new(networks);

        assert!(matcher.matches("192.168.1.1".parse().unwrap()));
        assert!(matcher.matches("10.0.0.1".parse().unwrap()));
        assert!(!matcher.matches("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn test_regex_matcher() {
        let matcher = RegexMatcher::new(r"^.*\.example\.com$").unwrap();

        assert!(matcher.matches("www.example.com"));
        assert!(matcher.matches("test.example.com"));
        assert!(!matcher.matches("example.org"));
    }
}
