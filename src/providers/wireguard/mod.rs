//! WireGuard (dawny wireguard-tray): połączenia WireGuard zapisane w NetworkManagerze - każde to
//! osobna pozycja na liście wyboru VPN. Podmenu: szczegóły aktywnego tunelu, zarządzanie
//! połączeniami (autoconnect, zmiana nazwy, usuwanie) i import plików .conf (wg-quick).
//!
//! Wszystko idzie przez `nmcli`: up/down to network-control (aktywna sesja - bez hasła), a import,
//! zmiany i usuwanie to settings.modify.system (grupa wheel - bez hasła dzięki regule z pakietu
//! NetworkManager, inaczej pyta agent polkit). NetworkManager nie podaje czasu ostatniego handshake'u
//! (`wg show` wymaga roota), więc "żyje" = przychodzą bajty na interfejsie (/sys/class/net).

mod parse;

use std::collections::HashMap;
use std::fs;
use std::net::Ipv4Addr;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::Path;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use serde_json::Value;
use crate::common::cmd::which;
use crate::common::json::{arr, s};
use crate::common::menu::{button, check, sep, submenu, text, Menu};
use crate::common::{bg, icon_path, run, runtime_dir, Out, Poller};
use crate::providers::{Choice, Confirm, Job, Kind, Level, Summary};
use crate::{update, Tray, APP};

use parse::{ago, human_bytes, iface_name, overlap, parse_connections, parse_details, valid_iface, Conn, Details};

const POLL: Duration = Duration::from_secs(3);
/// Bez odpowiedzi serwera dłużej niż to = ostrzeżenie. Przy persistent-keepalive klient co 2 min
/// robi nowy handshake (odpowiedź serwera to ruch przychodzący), więc 190 s nie powinno migać.
const STALE_SECS: u64 = 190;
/// Po tylu sekundach od połączenia brak jakiegokolwiek ruchu przychodzącego = serwer nie odpowiada.
const NO_REPLY_SECS: u64 = 15;

static POLLER: OnceLock<Poller> = OnceLock::new();

pub fn refresh_now() {
    if let Some(p) = POLLER.get() {
        p.poke();
    }
}

fn nmcli(args: &[&str], timeout: u64) -> Out {
    let mut cmd = vec!["nmcli"];
    cmd.extend_from_slice(args);
    run(&cmd, timeout)
}

fn report(out: &Out, what: &str) {
    if !out.ok_or_cancelled() {
        APP.error(&format!("{what}:\n{}", out.text()));
    }
}

/// Ruch na interfejsie tunelu, liczony w wątku odpytywania.
#[derive(Clone, Copy, Debug, Default)]
struct Traffic {
    rx: u64,
    tx: u64,
    /// Sekundy od pojawienia się interfejsu (od połączenia albo od startu traya).
    up_secs: u64,
    /// Sekundy od ostatniego przyrostu rx.
    rx_idle_secs: u64,
}

enum Health {
    Ok,
    /// Brak handshake'u: od połączenia nic nie przyszło.
    NoReply,
    /// Serwer przestał odpowiadać (sekundy bez ruchu przychodzącego).
    Stale(u64),
    /// Bez persistent-keepalive i bez ruchu - nie da się ocenić.
    Unknown,
}

struct Icons {
    on: String,
    off: String,
    connecting: String,
    warn: String,
}

pub struct WireGuard {
    conns: Vec<Conn>,
    details: HashMap<String, Details>,
    traffic: HashMap<String, Traffic>,
    error: String,
    icons: Icons,
}

impl WireGuard {
    pub fn detect() -> Option<WireGuard> {
        if !which("nmcli") {
            return None;
        }
        let icon = |name: &str| icon_path(APP.id, name);
        Some(WireGuard {
            conns: Vec::new(),
            details: HashMap::new(),
            traffic: HashMap::new(),
            error: String::new(),
            icons: Icons {
                on: icon("wireguard-tray-on"),
                off: icon("wireguard-tray-disconnected"),
                connecting: icon("wireguard-tray-connecting"),
                warn: icon("wireguard-tray-warning"),
            },
        })
    }

    pub fn gather_now(&mut self) {
        let g = gather();
        let traffic = measure(&g.conns, &mut HashMap::new());
        apply_gathered(self, g, traffic);
    }

    fn active_conns(&self) -> Vec<&Conn> {
        self.conns.iter().filter(|c| c.active()).collect()
    }

    pub fn active(&self) -> bool {
        self.conns.iter().any(|c| c.active() || c.busy())
    }

    fn details(&self, c: &Conn) -> Details {
        self.details.get(&c.uuid).cloned().unwrap_or_default()
    }

    fn health(&self, c: &Conn) -> Health {
        let Some(t) = self.traffic.get(&c.device) else { return Health::Unknown };
        let keepalive = self.details(c).peers.iter().any(|p| p.keepalive > 0);
        if t.rx == 0 {
            if keepalive && t.up_secs >= NO_REPLY_SECS { Health::NoReply } else { Health::Unknown }
        } else if keepalive && t.rx_idle_secs >= STALE_SECS {
            Health::Stale(t.rx_idle_secs)
        } else {
            Health::Ok
        }
    }

    pub fn summary(&self) -> Summary {
        let active = self.active_conns();
        let names = active.iter().map(|c| c.name.as_str()).collect::<Vec<_>>().join(", ");
        let (level, text, icon) = if let Some(c) = self.conns.iter().find(|c| c.busy()) {
            (Level::Connecting, format!("{} {}…", c.state, c.name), &self.icons.connecting)
        } else if active.iter().any(|c| matches!(self.health(c), Health::NoReply | Health::Stale(_))) {
            (Level::Attention, format!("{names} - server not responding"), &self.icons.warn)
        } else if !active.is_empty() {
            (Level::On, format!("connected to {names}"), &self.icons.on)
        } else if !self.error.is_empty() {
            (Level::Off, self.error.clone(), &self.icons.off)
        } else {
            (Level::Off, "disconnected".into(), &self.icons.off)
        };
        Summary { level, text, icon: icon.clone() }
    }

    /// Jedna pozycja na połączenie WireGuard (z hostem serwera, gdy to cały ruch - z dopiskiem).
    pub fn choices(&self) -> Vec<Choice> {
        let mut conns: Vec<&Conn> = self.conns.iter().collect();
        conns.sort_by_key(|c| c.name.to_lowercase());
        conns
            .into_iter()
            .map(|c| {
                let d = self.details(c);
                let mut detail = c.name.clone();
                if let Some((host, _)) = d.endpoint().rsplit_once(':') {
                    detail.push_str(&format!("  ({})", host.trim_matches(['[', ']'])));
                }
                if d.full_tunnel() {
                    detail.push_str("  [all traffic]");
                }
                Choice { kind: Kind::WireGuard, id: c.uuid.clone(), detail, active: c.active() || c.busy() }
            })
            .collect()
    }

    /// Pytanie przed połączeniem, gdy komputer ma już adres w podsieciach tunelu (jesteś w tej
    /// sieci lokalnie, np. w Kurancie na miejscu) - trasy tunelu przykryłyby LAN.
    pub fn confirm(&self, uuid: &str) -> Option<Confirm> {
        let target = self.conns.iter().find(|c| c.uuid == uuid)?.clone();
        let routes = self.details(&target).routes();
        let wg_devices: Vec<String> = self.conns.iter().map(|c| c.device.clone()).filter(|d| !d.is_empty()).collect();
        Some(Box::new(move || {
            let Some((iface, ip, route)) = overlap(&routes, &local_addresses(&wg_devices)) else { return true };
            APP.yesno(&format!(
                "This computer is already in {route} ({ip} on {iface}) - it looks like you are on the {} network right now.\n\n\
                 Connecting would send that subnet through the tunnel and may cut off local access.\n\nConnect anyway?",
                target.name
            ))
        }))
    }

    /// Połączenie: rozłączenie innych tuneli WireGuard i `nmcli connection up`.
    pub fn connect_job(&self, uuid: &str) -> Job {
        let uuid = if uuid.is_empty() { self.conns.first().map(|c| c.uuid.clone()).unwrap_or_default() } else { uuid.to_string() };
        let others: Vec<String> = self.conns.iter().filter(|c| c.uuid != uuid && (c.active() || c.busy())).map(|c| c.uuid.clone()).collect();
        Box::new(move || {
            if uuid.is_empty() {
                return Err("No WireGuard connection - import a .conf file first.".into());
            }
            for other in &others {
                nmcli(&["connection", "down", "uuid", other], 30);
            }
            let out = nmcli(&["connection", "up", "uuid", &uuid], 60);
            if out.ok() { Ok(()) } else { Err(out.text()) }
        })
    }

    pub fn disconnect_job(&self) -> Job {
        let uuids: Vec<String> = self.conns.iter().filter(|c| c.active() || c.busy()).map(|c| c.uuid.clone()).collect();
        Box::new(move || {
            let mut errors = Vec::new();
            for uuid in &uuids {
                let out = nmcli(&["connection", "down", "uuid", uuid], 30);
                if !out.ok() {
                    errors.push(out.text());
                }
            }
            if errors.is_empty() { Ok(()) } else { Err(errors.join("\n")) }
        })
    }

    // ---------- menu ----------

    fn status_items(&self) -> Menu<Tray> {
        let mut m = Vec::new();
        if !self.error.is_empty() {
            m.push(text(&self.error));
            return m;
        }
        let active = self.active_conns();
        if active.is_empty() {
            let connecting = self.conns.iter().find(|c| c.busy());
            m.push(text(&connecting.map(|c| format!("{} {}…", c.state, c.name)).unwrap_or("Disconnected - pick a network above".into())));
        }
        for c in active {
            m.push(check(&format!("Connected: {}", c.name), true, true, |t: &mut Tray, _| t.disconnect_all()));
            let server = self.details(c).endpoint();
            match self.health(c) {
                Health::NoReply => m.push(text(&format!("⚠ No response from {server} (check the key and endpoint)"))),
                Health::Stale(secs) => m.push(text(&format!("⚠ Nothing received from the server for {}", ago(secs).replace(" ago", "")))),
                _ => {}
            }
        }
        m
    }

    fn details_items(&self) -> Menu<Tray> {
        let mut m = Vec::new();
        for c in self.active_conns() {
            let d = self.details(c);
            for addr in &d.addresses {
                let ip = addr.split('/').next().unwrap_or(addr).to_string();
                m.push(button(&format!("This device: {ip}  [{}]", c.device), true, move |_| copy(&ip)));
            }
            let endpoint = d.endpoint();
            if !endpoint.is_empty() {
                m.push(button(&format!("Server: {endpoint}"), true, move |_| copy(&endpoint)));
            }
            let routes = d.routes();
            let mut sub: Menu<Tray> = routes
                .iter()
                .map(|r| {
                    let r = r.clone();
                    button(&r.clone(), true, move |_| copy(&r))
                })
                .collect();
            if !d.dns.is_empty() {
                sub.push(sep());
                sub.push(text(&format!("DNS: {}", d.dns.join(", "))));
            }
            sub.push(sep());
            sub.push(text("Click a subnet to copy it"));
            m.push(submenu(&format!("Routed through the tunnel ({})", routes.len()), true, sub));
            if let Some(t) = self.traffic.get(&c.device) {
                let last = if t.rx == 0 { "nothing received yet".into() } else { format!("last received {}", ago(t.rx_idle_secs)) };
                m.push(text(&format!("↓ {}  ↑ {}  ·  {last}", human_bytes(t.rx), human_bytes(t.tx))));
            }
        }
        m
    }

    fn manage_menu(&self, idle: bool) -> ksni::MenuItem<Tray> {
        let mut conns: Vec<&Conn> = self.conns.iter().collect();
        conns.sort_by_key(|c| c.name.to_lowercase());
        let mut sub: Menu<Tray> = Vec::new();
        for c in conns {
            let (uuid, name) = (c.uuid.clone(), c.name.clone());
            let endpoint = self.details(c).endpoint();
            let (u1, u2, u3, n2, n3) = (uuid.clone(), uuid.clone(), uuid, name.clone(), name.clone());
            let items = vec![
                check("Connect automatically", c.autoconnect, idle, move |_, v| {
                    let uuid = u1.clone();
                    bg(move || set_autoconnect(&uuid, v));
                }),
                button("Copy server address", !endpoint.is_empty(), move |_| copy(&endpoint)),
                sep(),
                button("Rename…", idle, move |_| {
                    let (uuid, name) = (u2.clone(), n2.clone());
                    bg(move || rename(&uuid, &name));
                }),
                button("Remove…", idle, move |_| {
                    let (uuid, name) = (u3.clone(), n3.clone());
                    bg(move || remove(&uuid, &name));
                }),
            ];
            let label = if c.autoconnect { format!("{name}  (auto)") } else { name };
            sub.push(submenu(&label, true, items));
        }
        if !sub.is_empty() {
            sub.push(sep());
        }
        sub.push(button("Import a .conf file…", idle, |_| bg(import)));
        sub.push(button("Network settings…", true, |_| open_settings()));
        submenu("Manage connections", true, sub)
    }

    pub fn menu(&self) -> Menu<Tray> {
        let mut m = self.status_items();
        if self.error.is_empty() {
            let details = self.details_items();
            if !details.is_empty() {
                m.push(sep());
                m.extend(details);
            }
            m.extend([sep(), self.manage_menu(true)]);
        }
        m
    }
}

// ---------- akcje w tle ----------

fn copy(text: &str) {
    let text = text.to_string();
    bg(move || APP.copy_to_clipboard(&text));
}

/// Adresy IPv4 innych interfejsów niż loopback i tunele WireGuard (z `ip -j`).
fn local_addresses(skip: &[String]) -> Vec<(String, Ipv4Addr)> {
    let json: Value = serde_json::from_str(&run(&["ip", "-j", "-4", "addr"], 10).stdout).unwrap_or(Value::Null);
    let mut out = Vec::new();
    for iface in json.as_array().map(Vec::as_slice).unwrap_or(&[]) {
        let name = s(iface, "ifname");
        if name == "lo" || skip.iter().any(|d| d == name) {
            continue;
        }
        for addr in arr(iface, "addr_info") {
            if let Ok(ip) = s(addr, "local").parse::<Ipv4Addr>() {
                out.push((name.to_string(), ip));
            }
        }
    }
    out
}

fn set_autoconnect(uuid: &str, enabled: bool) {
    let out = nmcli(&["connection", "modify", "uuid", uuid, "connection.autoconnect", if enabled { "yes" } else { "no" }], 30);
    report(&out, "Could not change the connection");
    refresh_now();
}

fn rename(uuid: &str, name: &str) {
    let Some(new) = APP.inputbox(&format!("New name for {name}:"), name) else { return };
    if new.is_empty() || new == name {
        return;
    }
    report(&nmcli(&["connection", "modify", "uuid", uuid, "connection.id", &new], 30), "Could not rename the connection");
    refresh_now();
}

fn remove(uuid: &str, name: &str) {
    if !APP.yesno(&format!(
        "Remove the WireGuard connection {name}?\n\nIts private key is deleted from NetworkManager - keep the .conf file if you want to import it again."
    )) {
        return;
    }
    report(&nmcli(&["connection", "delete", "uuid", uuid], 30), &format!("Could not remove {name}"));
    refresh_now();
}

fn open_settings() {
    if which("systemsettings") {
        crate::common::cmd::spawn(&["systemsettings", "kcm_networkmanagement"]);
    } else if which("nm-connection-editor") {
        crate::common::cmd::spawn(&["nm-connection-editor"]);
    } else {
        APP.error("Neither KDE System Settings nor nm-connection-editor is installed.");
    }
}

/// Import pliku wg-quick (.conf) do NetworkManagera. Nazwa połączenia i interfejsu = nazwa pliku,
/// więc plik idzie przez kopię o wybranej nazwie w prywatnym katalogu. Nowe połączenie dostaje
/// autoconnect=no - tunel ma się włączać tylko z menu.
fn import() {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/".into());
    let pick = run(&["kdialog", "--title", "Import WireGuard configuration", "--getopenfilename", &home, "*.conf|WireGuard configuration (*.conf)"], 600);
    let path = pick.stdout.trim().to_string();
    if !pick.ok() || path.is_empty() {
        return;
    }
    let content = match fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => return APP.error(&format!("Cannot read {path}:\n{e}")),
    };
    if !content.contains("[Interface]") || !content.contains("PrivateKey") || !content.contains("[Peer]") {
        return APP.error(&format!(
            "{path} does not look like a WireGuard configuration\n(it needs [Interface] with PrivateKey and a [Peer] section)."
        ));
    }
    let stem = Path::new(&path).file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    let Some(name) = APP.inputbox(
        "Name of the connection (also the network interface name):\nmax 15 characters - letters, digits, '-' and '_'",
        &iface_name(&stem),
    ) else {
        return;
    };
    if !valid_iface(&name) {
        return APP.error("Use 1-15 characters: letters, digits, '-' and '_'.");
    }
    let existing = parse_connections(&nmcli(&["-t", "-f", "NAME,UUID,TYPE,AUTOCONNECT,DEVICE,STATE,FILENAME", "connection", "show"], 15).stdout);
    if existing.iter().any(|c| c.name == name || c.device == name) {
        return APP.error(&format!("A WireGuard connection named {name} already exists - pick another name or remove it first."));
    }

    let result = (|| -> std::io::Result<Out> {
        let dir = runtime_dir(APP.id)?.join(format!("import-{}", std::process::id()));
        fs::DirBuilder::new().recursive(true).mode(0o700).create(&dir)?;
        let file = dir.join(format!("{name}.conf"));
        fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&file).and_then(|mut f| {
            use std::io::Write;
            f.write_all(content.as_bytes())
        })?;
        let out = nmcli(&["connection", "import", "type", "wireguard", "file", &file.to_string_lossy()], 30);
        let _ = fs::remove_dir_all(&dir); // kopia z kluczem prywatnym nie zostaje na dysku
        Ok(out)
    })();
    let out = match result {
        Ok(out) => out,
        Err(e) => return APP.error(&format!("Cannot prepare the import:\n{e}")),
    };
    if !out.ok() {
        return report(&out, &format!("Could not import {path}"));
    }
    let uuid = nmcli(&["-g", "connection.uuid", "connection", "show", "id", &name], 15).stdout.lines().next().unwrap_or("").trim().to_string();
    if uuid.is_empty() {
        refresh_now();
        return APP.notify("WireGuard: imported", &name);
    }
    // nmcli import zapisuje autoconnect=yes i od razu łączy - zostawiamy wybór użytkownikowi.
    nmcli(&["connection", "modify", "uuid", &uuid, "connection.autoconnect", "no"], 30);
    nmcli(&["connection", "down", "uuid", &uuid], 30);
    refresh_now();
    if APP.yesno(&format!("Imported {name}.\n\nConnect to it now?")) {
        // Najpierw odświeżenie, żeby nowe połączenie (z trasami do pytania o LAN) było w stanie traya.
        let g = gather();
        update(move |t| {
            if let Some(wg) = t.wg.as_mut() {
                (wg.conns, wg.details) = (g.conns, g.details);
            }
            t.switch_to(Kind::WireGuard, uuid);
        });
    }
}

struct Gathered {
    conns: Vec<Conn>,
    details: HashMap<String, Details>,
    error: String,
}

/// Odpytanie nmcli (każde wywołanie to osobny proces).
fn gather() -> Gathered {
    let mut g = Gathered { conns: Vec::new(), details: HashMap::new(), error: String::new() };
    let out = nmcli(&["-t", "-f", "NAME,UUID,TYPE,AUTOCONNECT,DEVICE,STATE,FILENAME", "connection", "show"], 8);
    if !out.ok() {
        g.error = "NetworkManager is not running".into();
        return g;
    }
    g.conns = parse_connections(&out.stdout);
    for c in &g.conns {
        let out = nmcli(&["-t", "-f", "wireguard.peers,ipv4.addresses,ipv4.dns", "connection", "show", "uuid", &c.uuid], 8);
        g.details.insert(c.uuid.clone(), parse_details(&out.stdout));
    }
    g
}

/// Liczniki z /sys/class/net; `seen` = (ostatnie rx, kiedy wzrosło, kiedy pojawił się interfejs).
fn measure(conns: &[Conn], seen: &mut HashMap<String, (u64, Instant, Instant)>) -> HashMap<String, Traffic> {
    let read = |dev: &str, what: &str| -> Option<u64> {
        fs::read_to_string(format!("/sys/class/net/{dev}/statistics/{what}")).ok()?.trim().parse().ok()
    };
    let now = Instant::now();
    let mut out = HashMap::new();
    let devices: Vec<&str> = conns.iter().filter(|c| c.active() && !c.device.is_empty()).map(|c| c.device.as_str()).collect();
    seen.retain(|dev, _| devices.contains(&dev.as_str()));
    for dev in devices {
        let (Some(rx), Some(tx)) = (read(dev, "rx_bytes"), read(dev, "tx_bytes")) else { continue };
        let entry = seen.entry(dev.to_string()).or_insert((rx, now, now));
        if rx != entry.0 {
            entry.0 = rx;
            entry.1 = now;
        }
        out.insert(
            dev.to_string(),
            Traffic { rx, tx, up_secs: now.duration_since(entry.2).as_secs(), rx_idle_secs: now.duration_since(entry.1).as_secs() },
        );
    }
    out
}

fn apply_gathered(t: &mut WireGuard, g: Gathered, traffic: HashMap<String, Traffic>) {
    (t.conns, t.details, t.error, t.traffic) = (g.conns, g.details, g.error, traffic);
}

pub fn start() {
    let mut seen = HashMap::new();
    let _ = POLLER.set(Poller::start(POLL, move || {
        let g = gather();
        let traffic = measure(&g.conns, &mut seen);
        update(move |t| {
            if let Some(wg) = t.wg.as_mut() {
                apply_gathered(wg, g, traffic);
            }
        });
    }));
}
