use crate::query_context::QueryContext;
use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;

pub mod executable;
pub mod matcher;

/// Trait for plugins that can execute DNS query processing
#[async_trait::async_trait]
pub trait Executable: Send + Sync {
    async fn exec(&self, ctx: &mut QueryContext) -> Result<()>;
}

/// Trait for plugins that can match DNS queries
#[async_trait::async_trait]
pub trait Matcher: Send + Sync {
    async fn match_query(&self, ctx: &QueryContext) -> Result<bool>;
}

/// Plugin trait - base trait for all plugins
pub trait Plugin: Send + Sync {
    fn tag(&self) -> &str;
    fn plugin_type(&self) -> &str;
}

/// Plugin registry for managing plugin types
pub struct PluginRegistry {
    executables: HashMap<String, Arc<dyn Executable>>,
    matchers: HashMap<String, Arc<dyn Matcher>>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self {
            executables: HashMap::new(),
            matchers: HashMap::new(),
        }
    }

    pub fn register_executable(&mut self, tag: String, exec: Arc<dyn Executable>) {
        self.executables.insert(tag, exec);
    }

    pub fn register_matcher(&mut self, tag: String, matcher: Arc<dyn Matcher>) {
        self.matchers.insert(tag, matcher);
    }

    pub fn get_executable(&self, tag: &str) -> Option<Arc<dyn Executable>> {
        self.executables.get(tag).cloned()
    }

    pub fn get_matcher(&self, tag: &str) -> Option<Arc<dyn Matcher>> {
        self.matchers.get(tag).cloned()
    }
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}
