use std::sync::atomic::{AtomicUsize, Ordering};

use serde::Serialize;

#[derive(Serialize)]
pub struct ServerStatusResponse {
    pub active: bool,
    pub total_nodes: usize,
    pub active_nodes: usize,
    pub ident: String,
}

pub struct ServerHealthState {
    nodes: AtomicUsize,
    active: AtomicUsize,
    pub ident: String,
}

impl ServerHealthState {
    pub fn new(ident: String) -> Self {
        Self {
            nodes: AtomicUsize::new(0),
            active: AtomicUsize::new(0),
            ident,
        }
    }

    pub fn node_count(&self) -> usize {
        self.nodes.load(Ordering::SeqCst)
    }

    pub fn active_node_count(&self) -> usize {
        self.active.load(Ordering::SeqCst)
    }

    pub fn is_active(&self) -> bool {
        self.active_node_count() > 0
    }

    pub fn set_node_count(&self, n: usize) {
        self.nodes.store(n, Ordering::SeqCst);
    }

    pub fn set_active_node_count(&self, n: usize) {
        self.active.store(n, Ordering::SeqCst);
    }

    pub fn status(&self) -> ServerStatusResponse {
        ServerStatusResponse {
            active: self.is_active(),
            total_nodes: self.node_count(),
            active_nodes: self.active_node_count(),
            ident: self.ident.clone(),
        }
    }
}
