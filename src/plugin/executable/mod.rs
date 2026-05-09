use crate::plugin::Executable;
use crate::query_context::QueryContext;
use anyhow::Result;
use std::sync::Arc;

/// Sequence plugin - executes a chain of plugins
pub struct Sequence {
    plugins: Vec<Arc<dyn Executable>>,
}

impl Sequence {
    pub fn new(plugins: Vec<Arc<dyn Executable>>) -> Self {
        Self { plugins }
    }
}

#[async_trait::async_trait]
impl Executable for Sequence {
    async fn exec(&self, ctx: &mut QueryContext) -> Result<()> {
        for plugin in &self.plugins {
            plugin.exec(ctx).await?;
        }
        Ok(())
    }
}

/// Fallback plugin - tries plugins in order until one succeeds
pub struct Fallback {
    primary: Arc<dyn Executable>,
    secondary: Arc<dyn Executable>,
}

impl Fallback {
    pub fn new(primary: Arc<dyn Executable>, secondary: Arc<dyn Executable>) -> Self {
        Self { primary, secondary }
    }
}

#[async_trait::async_trait]
impl Executable for Fallback {
    async fn exec(&self, ctx: &mut QueryContext) -> Result<()> {
        match self.primary.exec(ctx).await {
            Ok(()) => Ok(()),
            Err(_) => self.secondary.exec(ctx).await,
        }
    }
}
