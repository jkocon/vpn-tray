//! Czyste funkcje: wyjście nmcli, adresy IPv4 i podsieci, liczby do menu.

use std::net::Ipv4Addr;

/// Połączenie WireGuard zapisane w NetworkManagerze.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Conn {
    pub name: String,
    pub uuid: String,
    pub autoconnect: bool,
    /// Interfejs, gdy połączenie jest aktywne (zwykle = nazwa pliku .conf przy imporcie).
    pub device: String,
    /// "activated", "activating", "deactivating" albo "" (nieaktywne).
    pub state: String,
}

impl Conn {
    pub fn active(&self) -> bool {
        self.state == "activated"
    }

    pub fn busy(&self) -> bool {
        self.state == "activating" || self.state == "deactivating"
    }
}

/// Peer z `wireguard.peers` (klucz publiczny i atrybuty key=value).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Peer {
    pub public_key: String,
    pub endpoint: String,
    pub allowed_ips: Vec<String>,
    pub keepalive: u32,
}

/// Szczegóły połączenia z `nmcli connection show <uuid>`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Details {
    pub addresses: Vec<String>,
    pub dns: Vec<String>,
    pub peers: Vec<Peer>,
}

impl Details {
    /// Wszystkie podsieci kierowane do tunelu.
    pub fn routes(&self) -> Vec<String> {
        self.peers.iter().flat_map(|p| p.allowed_ips.iter().cloned()).collect()
    }

    pub fn endpoint(&self) -> String {
        self.peers.iter().map(|p| p.endpoint.as_str()).find(|e| !e.is_empty()).unwrap_or("").to_string()
    }

    pub fn full_tunnel(&self) -> bool {
        self.routes().iter().any(|r| r == "0.0.0.0/0" || r == "::/0")
    }
}

/// Pola linii `nmcli -t`: ':' oddziela pola, w wartościach jest escapowany jako "\:", a '\' jako "\\".
pub fn split_terse(line: &str) -> Vec<String> {
    let mut fields = vec![String::new()];
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                if let Some(next) = chars.next() {
                    fields.last_mut().unwrap().push(next);
                }
            }
            ':' => fields.push(String::new()),
            _ => fields.last_mut().unwrap().push(c),
        }
    }
    fields
}

/// `nmcli -t -f NAME,UUID,TYPE,AUTOCONNECT,DEVICE,STATE,FILENAME connection show` → tylko WireGuard
/// zapisany w NetworkManagerze. Interfejsy tworzone przez inne programy (np. wt0 NetBirda) NetworkManager
/// pokazuje jako połączenia "connected (externally)" trzymane tylko w pamięci, w /run/NetworkManager -
/// to nie są sieci do wyboru.
pub fn parse_connections(out: &str) -> Vec<Conn> {
    out.lines()
        .filter_map(|line| {
            let f = split_terse(line);
            if f.len() < 6 || f[2] != "wireguard" || f.get(6).is_some_and(|file| file.starts_with("/run/")) {
                return None;
            }
            Some(Conn {
                name: f[0].clone(),
                uuid: f[1].clone(),
                autoconnect: f[3] == "yes",
                device: f[4].clone(),
                state: f[5].clone(),
            })
        })
        .collect()
}

/// `wireguard.peers` w formacie nmcli 1.4x+: "<klucz> allowed-ips=a;b endpoint=host:port persistent-keepalive=25",
/// kolejne peery po przecinku.
pub fn parse_peers(value: &str) -> Vec<Peer> {
    value
        .split(',')
        .filter_map(|chunk| {
            let mut words = chunk.split_whitespace();
            let mut peer = Peer { public_key: words.next()?.to_string(), ..Default::default() };
            for word in words {
                let Some((key, val)) = word.split_once('=') else { continue };
                match key {
                    "endpoint" => peer.endpoint = val.to_string(),
                    "allowed-ips" => {
                        peer.allowed_ips = val.split(';').map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect()
                    }
                    "persistent-keepalive" => peer.keepalive = val.parse().unwrap_or(0),
                    _ => {}
                }
            }
            Some(peer)
        })
        .collect()
}

/// `nmcli -t -f wireguard.peers,ipv4.addresses,ipv4.dns connection show <uuid>`. W trybie jednego
/// połączenia nmcli nie escapuje wartości ("endpoint=host:51820"), więc dzielimy na pierwszym ':'.
pub fn parse_details(out: &str) -> Details {
    let mut d = Details::default();
    let list = |v: &str| v.split(',').map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect::<Vec<_>>();
    for line in out.lines() {
        let Some((key, value)) = line.split_once(':') else { continue };
        let value = value.replace("\\:", ":").replace("\\\\", "\\");
        match key {
            "wireguard.peers" => d.peers = parse_peers(&value),
            "ipv4.addresses" => d.addresses = list(&value),
            "ipv4.dns" => d.dns = list(&value),
            _ => {}
        }
    }
    d
}

/// "10.11.0.0/24" → (adres, długość prefiksu); tylko IPv4.
pub fn parse_cidr(cidr: &str) -> Option<(Ipv4Addr, u8)> {
    let (addr, len) = cidr.split_once('/').unwrap_or((cidr, "32"));
    let len: u8 = len.parse().ok().filter(|l| *l <= 32)?;
    Some((addr.parse().ok()?, len))
}

pub fn cidr_contains(cidr: &str, ip: Ipv4Addr) -> bool {
    let Some((net, len)) = parse_cidr(cidr) else { return false };
    let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
    u32::from(net) & mask == u32::from(ip) & mask
}

/// Lokalny adres (z innych interfejsów niż tunel), który leży w jednej z tras tunelu - czyli jesteśmy
/// już w tej sieci (np. w Kurancie na miejscu). Trasy domyślne się nie liczą, one obejmują wszystko.
pub fn overlap(routes: &[String], local: &[(String, Ipv4Addr)]) -> Option<(String, Ipv4Addr, String)> {
    for route in routes {
        if parse_cidr(route).is_none_or(|(_, len)| len == 0) {
            continue;
        }
        if let Some((iface, ip)) = local.iter().find(|(_, ip)| cidr_contains(route, *ip)) {
            return Some((iface.clone(), *ip, route.clone()));
        }
    }
    None
}

/// Nazwa interfejsu z nazwy pliku: NetworkManager bierze ją z nazwy pliku .conf (max 15 znaków).
pub fn iface_name(stem: &str) -> String {
    let name: String = stem
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '-' })
        .take(15)
        .collect();
    let name = name.trim_matches('-').to_string();
    if name.is_empty() { "wg0".into() } else { name }
}

pub fn valid_iface(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

pub fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut unit = 0;
    while v >= 1024.0 && unit < UNITS.len() - 1 {
        v /= 1024.0;
        unit += 1;
    }
    if unit == 0 { format!("{n} B") } else { format!("{v:.1} {}", UNITS[unit]) }
}

pub fn ago(secs: u64) -> String {
    match secs {
        0..=4 => "just now".into(),
        5..=119 => format!("{secs} s ago"),
        120..=7199 => format!("{} min ago", secs / 60),
        _ => format!("{} h ago", secs / 3600),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terse_escapes() {
        assert_eq!(split_terse(r"a\:b:c\\d::e"), ["a:b", r"c\d", "", "e"]);
    }

    #[test]
    fn connections_only_wireguard() {
        let out = "Kurantowka-Priv:cea2:802-11-wireless:yes:wlan0:activated:/etc/NetworkManager/system-connections/k.nmconnection\n\
                   kurant:c46c:wireguard:no:kurant:activated:/etc/NetworkManager/system-connections/kurant.nmconnection\n\
                   wt0:d00d:wireguard:no:wt0:activated:/run/NetworkManager/system-connections/wt0.nmconnection\n\
                   biuro\\:2:aaaa:wireguard:yes:::\n";
        let c = parse_connections(out);
        assert_eq!(c.len(), 2);
        assert!(c[0].active() && !c[0].autoconnect);
        assert_eq!(c[1].name, "biuro:2");
        assert!(c[1].autoconnect && !c[1].active() && c[1].device.is_empty());
    }

    #[test]
    fn details_from_nmcli() {
        let out = "wireguard.peers:+6CL= allowed-ips=10.11.0.0/24;10.0.0.1/32 endpoint=kurant.example.com:51820 persistent-keepalive=25\n\
                   ipv4.addresses:10.0.0.2/32\nipv4.dns:\n";
        let d = parse_details(out);
        assert_eq!(d.addresses, ["10.0.0.2/32"]);
        assert!(d.dns.is_empty());
        assert_eq!(d.endpoint(), "kurant.example.com:51820");
        assert_eq!(d.routes(), ["10.11.0.0/24", "10.0.0.1/32"]);
        assert_eq!(d.peers[0].keepalive, 25);
        assert!(!d.full_tunnel());
    }

    #[test]
    fn two_peers() {
        let p = parse_peers("AAA= allowed-ips=10.0.0.0/8, BBB= allowed-ips=0.0.0.0/0;::/0 endpoint=[2001:db8::1]:51820");
        assert_eq!(p.len(), 2);
        assert_eq!(p[1].endpoint, "[2001:db8::1]:51820");
        assert_eq!(p[1].allowed_ips, ["0.0.0.0/0", "::/0"]);
    }

    #[test]
    fn subnets() {
        let ip = |s: &str| s.parse::<Ipv4Addr>().unwrap();
        assert!(cidr_contains("10.11.30.0/23", ip("10.11.31.7")));
        assert!(!cidr_contains("10.11.30.0/23", ip("10.11.32.1")));
        assert!(cidr_contains("10.0.0.1/32", ip("10.0.0.1")));
        let local = vec![("wlan0".to_string(), ip("10.11.20.15"))];
        let routes: Vec<String> = ["0.0.0.0/0", "10.11.0.0/24", "10.11.20.0/24"].map(String::from).into();
        assert_eq!(overlap(&routes, &local), Some(("wlan0".into(), ip("10.11.20.15"), "10.11.20.0/24".into())));
        assert_eq!(overlap(&routes[..2], &local), None);
    }

    #[test]
    fn iface_names() {
        assert_eq!(iface_name("kurant-jan"), "kurant-jan");
        assert_eq!(iface_name("my vpn (office) 2026"), "my-vpn--office");
        assert_eq!(iface_name("..."), "wg0");
        assert!(valid_iface("kurant-jan") && !valid_iface("a b") && !valid_iface("abcdefghijklmnop"));
    }

    #[test]
    fn numbers() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1536), "1.5 KiB");
        assert_eq!(ago(30), "30 s ago");
        assert_eq!(ago(600), "10 min ago");
    }
}
