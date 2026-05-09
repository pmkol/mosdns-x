use dashmap::DashMap;
use std::time::{Duration, Instant};
use trust_dns_proto::op::Message;

/// Cache entry
#[derive(Clone)]
pub struct CacheEntry {
    pub response: Message,
    pub expires_at: Instant,
}

impl CacheEntry {
    pub fn is_expired(&self) -> bool {
        Instant::now() > self.expires_at
    }
}

/// Simple in-memory DNS cache
pub struct DnsCache {
    inner: DashMap<String, CacheEntry>,
    default_ttl: Duration,
}

impl DnsCache {
    pub fn new(default_ttl: Duration) -> Self {
        Self {
            inner: DashMap::new(),
            default_ttl,
        }
    }

    pub fn get(&self, key: &str) -> Option<Message> {
        let entry = self.inner.get(key)?;
        if entry.is_expired() {
            drop(entry);
            self.inner.remove(key);
            None
        } else {
            Some(entry.response.clone())
        }
    }

    pub fn insert(&self, key: String, response: Message, ttl: Option<Duration>) {
        let ttl = ttl.unwrap_or(self.default_ttl);
        let entry = CacheEntry {
            response,
            expires_at: Instant::now() + ttl,
        };
        self.inner.insert(key, entry);
    }

    pub fn remove(&self, key: &str) {
        self.inner.remove(key);
    }

    pub fn clear(&self) {
        self.inner.clear();
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new(Duration::from_secs(300))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_insert_and_get() {
        let cache = DnsCache::new(Duration::from_secs(60));
        let msg = Message::new();
        
        cache.insert("test".to_string(), msg.clone(), None);
        assert_eq!(cache.len(), 1);
        
        let result = cache.get("test");
        assert!(result.is_some());
    }

    #[test]
    fn test_cache_expiration() {
        let cache = DnsCache::new(Duration::from_millis(10));
        let msg = Message::new();
        
        cache.insert("test".to_string(), msg, None);
        assert!(cache.get("test").is_some());
        
        // Wait for expiration
        std::thread::sleep(Duration::from_millis(50));
        assert!(cache.get("test").is_none());
    }

    #[test]
    fn test_cache_remove() {
        let cache = DnsCache::new(Duration::from_secs(60));
        let msg = Message::new();
        
        cache.insert("test".to_string(), msg, None);
        assert_eq!(cache.len(), 1);
        
        cache.remove("test");
        assert_eq!(cache.len(), 0);
        assert!(cache.get("test").is_none());
    }

    #[test]
    fn test_cache_clear() {
        let cache = DnsCache::new(Duration::from_secs(60));
        let msg = Message::new();
        
        cache.insert("test1".to_string(), msg.clone(), None);
        cache.insert("test2".to_string(), msg, None);
        assert_eq!(cache.len(), 2);
        
        cache.clear();
        assert!(cache.is_empty());
    }
}
