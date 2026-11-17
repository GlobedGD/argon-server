use std::{
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};

use crate::{
    config::AuthResourceConfig,
    node_manager::{node::ArgonNode, performance_tracker::PerformanceTracker},
};
use parking_lot::Mutex;
use shared::resource::{ResourceKey, ResourceType};

pub struct AuthResource {
    pub r#type: ResourceType,
    pub id: i32,
    pub remaining_uses: AtomicU32,
    pub nodes: Mutex<Vec<Arc<ArgonNode>>>,
    pub perf_tracker: Mutex<PerformanceTracker>,
}

impl AuthResource {
    pub fn new(config: &AuthResourceConfig) -> Self {
        let remaining_uses = AtomicU32::new(if config.reusable { u32::MAX } else { 1 });

        Self {
            r#type: config.r#type,
            id: config.id,
            remaining_uses,
            nodes: Mutex::new(Vec::new()),
            perf_tracker: Mutex::new(PerformanceTracker::new()),
        }
    }

    pub fn try_claim(&self, node: &Arc<ArgonNode>) -> bool {
        let mut current = self.remaining_uses.load(Ordering::Acquire);

        while current > 0 {
            match self.remaining_uses.compare_exchange(
                current,
                current - 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    self.nodes.lock().push(node.clone());
                    return true;
                }
                Err(new_current) => current = new_current,
            }
        }

        false
    }

    pub fn release(&self, node: &Arc<ArgonNode>) {
        let mut nodes = self.nodes.lock();
        if let Some(pos) = nodes.iter().position(|n| Arc::ptr_eq(n, node)) {
            nodes.remove(pos);
            self.remaining_uses.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn key(&self) -> ResourceKey {
        ResourceKey {
            r#type: self.r#type,
            id: self.id,
        }
    }

    pub fn nodes(&self) -> Vec<Arc<ArgonNode>> {
        self.nodes.lock().clone()
    }

    pub fn success_rate(&self, window: Duration) -> f64 {
        self.perf_tracker.lock().success_rate(window)
    }

    pub fn performing_well(&self) -> bool {
        self.success_rate(Duration::from_secs(60)) >= 0.75
    }
}
