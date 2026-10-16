//! Udziały NFS za VPN-em. Gdy VPN, przez który idzie ruch do serwera NFS, znika, zamontowany udział
//! przestaje odpowiadać, a procesy, które go dotkną (np. kded6 - a z nim cały zasobnik Plasmy),
//! wiszą w jądrze w oczekiwaniu na RPC (2026-10-16). Dlatego przed rozłączeniem tray odmontowuje
//! takie udziały, póki serwer jeszcze odpowiada; automount (x-systemd.automount) podmontuje je
//! przy następnym otwarciu.

use std::net::IpAddr;

use crate::common::run;

pub const HELPER: &str = "/usr/local/lib/vpn-tray/vpn-helper";

/// Zamontowany udział NFS: punkt montowania i serwer.
#[derive(Clone, Debug, PartialEq)]
pub struct Mount {
    pub target: String,
    pub server: String,
}

/// /proc/mounts: spacje i inne znaki w ścieżkach są zapisane ósemkowo (\040).
fn unescape(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() && bytes[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c)) {
            let code = (bytes[i + 1] - b'0') * 64 + (bytes[i + 2] - b'0') * 8 + (bytes[i + 3] - b'0');
            out.push(code);
            i += 4;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// "10.20.0.2:/mnt/user/x" → "10.20.0.2", "[fd00::1]:/x" → "fd00::1".
fn server_of(source: &str) -> Option<String> {
    let host = if let Some(rest) = source.strip_prefix('[') { rest.split_once(']')?.0 } else { source.split_once(':')?.0 };
    (!host.is_empty()).then(|| host.to_string())
}

pub fn parse_mounts(text: &str) -> Vec<Mount> {
    text.lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 3 || !f[2].starts_with("nfs") {
                return None;
            }
            Some(Mount { target: unescape(f[1]), server: server_of(f[0])? })
        })
        .collect()
}

/// Interfejs z `ip -o route get <adres>` ("... dev wt0 src ...").
fn route_dev(output: &str) -> Option<String> {
    let mut words = output.split_whitespace();
    while let Some(w) = words.next() {
        if w == "dev" {
            return words.next().map(String::from);
        }
    }
    None
}

fn resolve(host: &str) -> Option<String> {
    if host.parse::<IpAddr>().is_ok() {
        return Some(host.into());
    }
    run(&["getent", "ahosts", host], 3).stdout.split_whitespace().next().map(String::from)
}

/// Udziały, do których ruch idzie przez któryś z podanych interfejsów.
pub fn behind(ifaces: &[String]) -> Vec<Mount> {
    if ifaces.is_empty() {
        return Vec::new();
    }
    let mounts = parse_mounts(&std::fs::read_to_string("/proc/mounts").unwrap_or_default());
    mounts
        .into_iter()
        .filter(|m| {
            let Some(ip) = resolve(&m.server) else { return false };
            route_dev(&run(&["ip", "-o", "route", "get", &ip], 3).stdout).is_some_and(|dev| ifaces.contains(&dev))
        })
        .collect()
}

/// Odmontowanie (przez pomocnika roota); zwraca komunikaty o błędach.
pub fn unmount(mounts: &[Mount]) -> Vec<String> {
    let mut errors = Vec::new();
    for m in mounts {
        let out = run(&["pkexec", HELPER, "unmount-nfs", &m.target], 60);
        if !out.ok_or_cancelled() {
            errors.push(format!("Could not unmount {}:\n{}", m.target, out.text()));
        }
    }
    errors
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mounts() {
        let text = "proc /proc proc rw 0 0\n\
                    10.20.0.2:/mnt/user/6TB\\040Filmy /mnt/unraid/6TB_Filmy nfs4 rw,soft 0 0\n\
                    [fd00::2]:/srv /mnt/v6 nfs rw 0 0\n\
                    systemd-1 /mnt/unraid/6TB_Seriale autofs rw 0 0\n";
        let m = parse_mounts(text);
        assert_eq!(m, [
            Mount { target: "/mnt/unraid/6TB_Filmy".into(), server: "10.20.0.2".into() },
            Mount { target: "/mnt/v6".into(), server: "fd00::2".into() },
        ]);
        assert_eq!(unescape("/a\\040b"), "/a b");
    }

    #[test]
    fn route() {
        assert_eq!(route_dev("10.20.0.2 dev wt0 table 7120 src 100.66.58.215 uid 1000 \\    cache"), Some("wt0".into()));
        assert_eq!(route_dev("garbage"), None);
    }
}
