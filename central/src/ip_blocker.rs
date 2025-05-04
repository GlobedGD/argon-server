use std::{
    net::IpAddr,
    sync::atomic::{AtomicBool, Ordering},
};

use crate::ip_allowlist::IpAllowlist;

pub struct IpBlocker {
    allowlist: IpAllowlist,
    enabled: AtomicBool,
}

impl IpBlocker {
    pub fn new(enabled: bool) -> Self {
        Self {
            allowlist: IpAllowlist::new(),
            enabled: AtomicBool::new(enabled),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::SeqCst)
    }

    pub fn set_enabled(&self, value: bool) {
        self.enabled.store(value, Ordering::SeqCst);
    }

    pub fn is_allowed(&self, ip: &IpAddr) -> bool {
        !self.is_enabled() || self.allowlist.is_allowed(ip)
    }
}
