use crate::query_context::QueryContext;
use anyhow::Result;
use std::sync::Arc;
use trust_dns_proto::op::{Message, ResponseCode};

/// DNS Handler trait - processes DNS queries
#[async_trait::async_trait]
pub trait DnsHandler: Send + Sync {
    /// Handle a DNS query
    /// Should set the response in the context if successful
    async fn handle(&self, ctx: &mut QueryContext) -> Result<()>;
}

/// Entry handler - the main entry point for DNS queries
pub struct EntryHandler {
    entry: Arc<dyn crate::plugin::Executable>,
    query_timeout: std::time::Duration,
    recursion_available: bool,
}

impl EntryHandler {
    pub fn new(
        entry: Arc<dyn crate::plugin::Executable>,
        query_timeout: std::time::Duration,
        recursion_available: bool,
    ) -> Self {
        Self {
            entry,
            query_timeout,
            recursion_available,
        }
    }
}

#[async_trait::async_trait]
impl DnsHandler for EntryHandler {
    async fn handle(&self, ctx: &mut QueryContext) -> Result<()> {
        let original_id = ctx.query().id();

        // Apply timeout
        let timeout_result = tokio::time::timeout(
            self.query_timeout,
            self.entry.exec(ctx)
        ).await;

        match timeout_result {
            Ok(Ok(())) => {
                // Check if response is set
                if ctx.response().is_none() {
                    // Return REFUSED if no response
                    let mut resp = Message::new();
                    resp.set_response_code(ResponseCode::Refused);
                    ctx.set_response(resp);
                }
            }
            Ok(Err(e)) => {
                // Entry returned an error - return SERVFAIL
                let mut resp = Message::new();
                resp.set_response_code(ResponseCode::ServFail);
                ctx.set_response(resp);
                return Err(e);
            }
            Err(_) => {
                // Timeout - return SERVFAIL
                let mut resp = Message::new();
                resp.set_response_code(ResponseCode::ServFail);
                ctx.set_response(resp);
                return Err(anyhow::anyhow!("query timeout"));
            }
        }

        // Preserve original query ID
        if let Some(response) = ctx.response() {
            let mut new_resp = response.clone();
            new_resp.set_id(original_id);
            ctx.set_response(new_resp);
        }

        Ok(())
    }
}
