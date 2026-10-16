//! Czyste funkcje: wyjście CLI netbird, adresy, czas sesji.

use std::path::Path;

use regex::Regex;

pub const EXIT_PREFIXES: [&str; 2] = ["0.0.0.0/0", "::/0"];

/// Sieć albo trasa z `netbird networks list`.
#[derive(Clone, Debug, PartialEq)]
pub struct Net {
    pub id: String,
    pub network: String,
    pub domains: String,
    pub selected: bool,
}

impl Net {
    /// Exit node = trasa domyślna. NetBird 0.80 podaje oba prefiksy w jednym polu: "0.0.0.0/0, ::/0".
    pub fn is_exit(&self) -> bool {
        self.network.split(',').any(|p| EXIT_PREFIXES.contains(&p.trim()))
    }
}

/// CLI netbird loguje ostrzeżenia gRPC na stderr przy każdym wywołaniu - do komunikatów tylko reszta.
pub fn clean(text: &str) -> String {
    let noise = Regex::new(r"(?m)^\S+ (INFO|WARN|DEBG) .*$|^.*caller_not_available.*$").unwrap();
    noise.replace_all(text, "").trim().to_string()
}

pub fn daemon_addr(unit: &str) -> String {
    if let Some(iface) = unit.strip_prefix("netbird@").and_then(|r| r.strip_suffix(".service")) {
        return format!("unix:///var/run/netbird/{iface}.sock");
    }
    if let Some(env) = std::env::var("NB_DAEMON_ADDR").ok().filter(|e| !e.is_empty()) {
        return env;
    }
    if Path::new("/var/run/netbird.sock").exists() {
        return "unix:///var/run/netbird.sock".into();
    }
    let mut socks: Vec<String> = std::fs::read_dir("/var/run/netbird")
        .map(|d| {
            d.flatten()
                .map(|e| e.path().to_string_lossy().into_owned())
                .filter(|p| p.ends_with(".sock"))
                .collect()
        })
        .unwrap_or_default();
    socks.sort();
    socks.first().map(|p| format!("unix://{p}")).unwrap_or_else(|| "unix:///var/run/netbird.sock".into())
}

pub fn short_name(fqdn: &str) -> String {
    let name = fqdn.split('.').next().unwrap_or("");
    if name.is_empty() { "?".into() } else { name.into() }
}

pub fn strip_prefix(ip: &str) -> String {
    let ip = ip.split('/').next().unwrap_or("");
    if ip.is_empty() { "-".into() } else { ip.into() }
}

/// Host z adresu URL (bez portu).
pub fn host_of(url: &str) -> Option<String> {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let hostport = rest.split(['/', '?', '#']).next()?;
    let host = match hostport.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => h,
        _ => hostport,
    };
    (!host.is_empty()).then(|| host.to_lowercase())
}

/// Dashboard pod adresem serwera zarządzającego: https://host[:port], bez :443.
pub fn admin_url(mgmt: &str) -> String {
    let Some(host) = host_of(mgmt) else { return String::new() };
    let rest = mgmt.split_once("://").map(|(_, r)| r).unwrap_or(mgmt);
    let hostport = rest.split(['/', '?', '#']).next().unwrap_or("");
    let port = match hostport.rsplit_once(':') {
        Some((_, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) && p != "443" => format!(":{p}"),
        _ => String::new(),
    };
    format!("https://{host}{port}")
}

/// '2026-10-08T17:06:52.05Z' -> 'in 23h 59m' / 'expired' ("" przy błędnej dacie).
pub fn until_text(iso: &str) -> String {
    let Ok(when) = chrono::DateTime::parse_from_rfc3339(iso) else { return String::new() };
    let secs = (when.with_timezone(&chrono::Utc) - chrono::Utc::now()).num_seconds();
    if secs <= 0 {
        return "expired".into();
    }
    let (days, rest) = (secs / 86400, secs % 86400);
    let (hours, mins) = (rest / 3600, rest % 3600 / 60);
    if days > 0 { format!("in {days}d {hours}h") } else { format!("in {hours}h {mins}m") }
}

/// Wyjście `netbird networks list` (brak trybu JSON) -> lista sieci.
pub fn parse_networks(text: &str) -> Vec<Net> {
    let mut nets: Vec<Net> = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if let Some(id) = line.strip_prefix("- ID:") {
            nets.push(Net { id: id.trim().into(), network: String::new(), domains: String::new(), selected: false });
        } else if let (Some(cur), Some((key, val))) = (nets.last_mut(), line.split_once(':')) {
            let val = val.trim();
            match key.trim() {
                "Network" => cur.network = val.into(),
                "Domains" => cur.domains = val.into(),
                "Status" => cur.selected = val.eq_ignore_ascii_case("selected"),
                _ => {}
            }
        }
    }
    nets
}

/// `netbird profile list` -> (nazwy, aktywny).
pub fn parse_profiles(text: &str) -> (Vec<String>, String) {
    let (mut names, mut active) = (Vec::new(), String::new());
    for line in text.lines().skip(1) {
        // pierwsza linia to nagłówek NAME ACTIVE
        let parts: Vec<&str> = line.split_whitespace().collect();
        let Some(name) = parts.first() else { continue };
        names.push(name.to_string());
        if parts.len() > 1 && parts.last() == Some(&"✓") {
            active = name.to_string();
        }
    }
    (names, active)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn networks() {
        let text = "Available Networks:\n\n  - ID: home-lan\n    Network: 10.20.0.0/16\n    Status: Selected\n\n\
                    \x20 - ID: exit-vps\n    Network: 0.0.0.0/0\n    Status: Not Selected\n\
                    \x20 - ID: docs\n    Domains: *.example.com\n    Status: Selected\n";
        let nets = parse_networks(text);
        assert_eq!(nets.len(), 3);
        assert_eq!(nets[0], Net { id: "home-lan".into(), network: "10.20.0.0/16".into(), domains: "".into(), selected: true });
        assert!(!nets[1].selected);
        assert_eq!(nets[2].domains, "*.example.com");
        assert!(!nets[0].is_exit());
        assert!(nets[1].is_exit());
    }

    #[test]
    fn exit_dual_stack() {
        let nets = parse_networks("Available Networks:\n\n  - ID: Exit Node Dom\n    Network: 0.0.0.0/0, ::/0\n    Status: Selected\n");
        assert_eq!(nets[0].network, "0.0.0.0/0, ::/0");
        assert!(nets[0].is_exit());
        assert!(Net { id: "v6".into(), network: "::/0".into(), domains: "".into(), selected: false }.is_exit());
    }

    #[test]
    fn profiles() {
        let (names, active) = parse_profiles("NAME   ACTIVE\ndom    ✓\nfirma  \n");
        assert_eq!(names, ["dom", "firma"]);
        assert_eq!(active, "dom");
    }

    #[test]
    fn units_and_urls() {
        assert_eq!(daemon_addr("netbird@wt1.service"), "unix:///var/run/netbird/wt1.sock");
        assert_eq!(admin_url("https://netbird.example.com:443"), "https://netbird.example.com");
        assert_eq!(admin_url("https://vpn.example.com:33073/x"), "https://vpn.example.com:33073");
        assert_eq!(admin_url(""), "");
        assert_eq!(host_of("https://Vpn.Example.com"), Some("vpn.example.com".into()));
        assert_eq!(strip_prefix("100.64.0.5/16"), "100.64.0.5");
        assert_eq!(short_name("x16.netbird.cloud"), "x16");
    }

    #[test]
    fn times() {
        assert_eq!(until_text("2000-01-01T00:00:00.123456789Z"), "expired");
        assert_eq!(until_text("bad"), "");
        let later = (chrono::Utc::now() + chrono::Duration::seconds(90_000 + 30)).to_rfc3339();
        assert_eq!(until_text(&later), "in 1d 1h");
    }

    #[test]
    fn noise() {
        assert_eq!(clean("2026-10-08T10:00:00Z WARN grpc blah\nreal error\n"), "real error");
    }
}
