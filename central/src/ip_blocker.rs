use std::{net::IpAddr, sync::OnceLock};

use argon_shared::logger::*;
use ipnet::{Ipv4Net, Ipv6Net};
use iprange::IpRange;

pub struct IpBlocker {
    range_v4: IpRange<Ipv4Net>,
    range_v6: IpRange<Ipv6Net>,
}

impl IpBlocker {
    pub fn instance() -> &'static Self {
        static INSTANCE: OnceLock<IpBlocker> = OnceLock::new();
        INSTANCE.get_or_init(|| {
            let contents = include_str!("allowed_ranges.txt");
            let mut v4 = Vec::new();
            let mut v6 = Vec::new();

            for line in contents.lines() {
                let line = line.trim().to_lowercase();
                if line.is_empty() || line.starts_with('#') || !line.contains(' ') {
                    continue;
                }

                let (proto, range) = line.split_once(' ').unwrap();

                if proto == "v4" {
                    v4.push(range.to_string());
                } else if proto == "v6" {
                    v6.push(range.to_string());
                } else {
                    warn!("ignoring invalid IP address entry: {line}");
                }
            }

            for ip in std::env::var("ARGON_EXTRA_ALLOW_IPS")
                .unwrap_or_default()
                .split(';')
            {
                if !ip.is_empty() {
                    debug!("Adding extra allowed IP: {ip}");
                    v4.push(ip.to_owned());
                }
            }

            for ip in std::env::var("ARGON_EXTRA_ALLOW_IPS_V6")
                .unwrap_or_default()
                .split(';')
            {
                if !ip.is_empty() {
                    debug!("Adding extra allowed IP: {ip}");
                    v6.push(ip.to_owned());
                }
            }

            Self::new(&v4, &v6)
        })
    }

    pub fn new(v4: &[String], v6: &[String]) -> Self {
        let range_v4 = v4.iter().map(|s| s.parse()).try_collect();
        let range_v6 = v6.iter().map(|s| s.parse()).try_collect();

        if let Err(err) = range_v4 {
            error!(
                "Error parsing some IPv4 addresses in either allowed_ranges.txt or the ARGON_EXTRA_ALLOW_IPS environment variable: {err}"
            );
            error!("Fix the issue and restart the server.");
            std::process::exit(1);
        }

        if let Err(err) = range_v4 {
            error!(
                "Error parsing some IPv6 addresses in either allowed_ranges.txt or the ARGON_EXTRA_ALLOW_IPS_V6 environment variable: {err}"
            );
            error!("Fix the issue and restart the server.");
            std::process::exit(1);
        }

        Self {
            range_v4: range_v4.unwrap(),
            range_v6: range_v6.unwrap(),
        }
    }

    pub fn is_allowed(&self, address: &IpAddr) -> bool {
        match address {
            IpAddr::V4(addr) => self.range_v4.contains(addr),
            IpAddr::V6(addr) => self.range_v6.contains(addr),
        }
    }
}
