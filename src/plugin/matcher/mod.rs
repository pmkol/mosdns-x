use crate::plugin::Matcher;
use crate::query_context::QueryContext;
use anyhow::Result;

/// Domain matcher - matches queries by domain name patterns
pub struct DomainMatcher {
    patterns: Vec<String>,
}

impl DomainMatcher {
    pub fn new(patterns: Vec<String>) -> Self {
        Self { patterns }
    }
}

#[async_trait::async_trait]
impl Matcher for DomainMatcher {
    async fn match_query(&self, ctx: &QueryContext) -> Result<bool> {
        let query_name = ctx.query().queries().first()
            .map(|q| q.name().to_string().to_lowercase())
            .unwrap_or_default();
        
        for pattern in &self.patterns {
            if query_name.ends_with(pattern) || query_name == *pattern {
                return Ok(true);
            }
        }
        Ok(false)
    }
}
