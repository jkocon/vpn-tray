//! NetBird (dawny netbird-tray): status, profil (przełączanie, dodawanie, panel admina, ważność
//! sesji), to urządzenie, urządzenia w sieci, sieci (Networks / trasy), exit node, ustawienia.
//!
//! Rozmawia z demonem przez CLI `netbird` (status --json, networks, profile, up/down) - socket demona
//! ma prawa 0666, więc nie trzeba roota. Systemctl (autostart, restart usługi) idzie przez pkexec;
//! install.sh dodaje regułę polkit, żeby start/stop/restart nie pytały o hasło. Każdy profil NetBird
//! (np. "dom" i "firma") to osobna pozycja na liście wyboru VPN.

mod parse;

use std::sync::OnceLock;
use std::time::Duration;

use regex::Regex;
use serde_json::Value;
use crate::common::cmd::stream_lines;
use crate::common::json::{arr, b, get, n, s};
use crate::common::menu::{button, check, radio, sep, submenu, text, Menu};
use crate::common::{bg, icon_path, open_url, run, unit_active, unit_enabled, Out, Poller};
use crate::providers::{Choice, Job, Kind, Level, Summary};
use crate::{update, Tray, APP};

use parse::{admin_url, clean, daemon_addr, host_of, parse_networks, parse_profiles, short_name, strip_prefix, until_text, Net};

const POLL: Duration = Duration::from_secs(3);
const NEEDS_LOGIN: [&str; 3] = ["NeedsLogin", "SessionExpired", "LoginFailed"];

static POLLER: OnceLock<Poller> = OnceLock::new();

pub fn refresh_now() {
    if let Some(p) = POLLER.get() {
        p.poke();
    }
}

fn netbird(args: &[&str], timeout: u64) -> Out {
    let mut cmd = vec!["netbird"];
    cmd.extend_from_slice(args);
    run(&cmd, timeout)
}

/// Komunikat CLI bez szumu z logów gRPC.
fn output(out: &Out) -> String {
    clean(&format!("{}{}", out.stderr, out.stdout))
}

fn report(out: &Out, what: &str) {
    if !out.ok_or_cancelled() {
        APP.error(&format!("{what}:\n{}", output(out)));
    }
}

fn needs_login_text(text: &str) -> bool {
    let text = text.to_lowercase();
    text.contains("login") || text.contains("sso")
}

// ---------- usługa ----------

fn list_units() -> Vec<(String, String)> {
    let out = run(&["systemctl", "list-units", "--all", "--plain", "--no-legend", "netbird.service", "netbird@*.service"], 30);
    out.stdout
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            Some((f.first()?.to_string(), f.get(2).unwrap_or(&"").to_string()))
        })
        .collect()
}

fn list_unit_files() -> Vec<(String, String)> {
    let out = run(&["systemctl", "list-unit-files", "--plain", "--no-legend", "netbird.service", "netbird@*.service"], 30);
    out.stdout
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            Some((f.first()?.to_string(), f.get(1)?.to_string()))
        })
        .collect()
}

/// Jednostka systemd demona. Pakiet AUR netbird-bin ma szablon netbird@.service (instancja = nazwa
/// interfejsu, np. netbird@wt0), a `netbird service install` tworzy zwykłe netbird.service.
/// Jeden demon na komputer - sieci przełącza się profilami.
fn service_unit() -> String {
    let units = list_units();
    if let Some((unit, _)) = units.iter().find(|(u, _)| unit_active(u)) {
        return unit.clone(); // najpierw działająca
    }
    if let Some((name, _)) = list_unit_files().into_iter().find(|(n, st)| st == "enabled" && !n.ends_with("@.service")) {
        return name;
    }
    units.first().map(|(u, _)| u.clone()).unwrap_or_else(|| "netbird@wt0.service".into())
}

struct Icons {
    on: String,
    off: String,
    exit: String,
    auth: String,
    relay: String,
}

pub struct NetBird {
    unit: String,
    status: Option<Value>,
    networks: Vec<Net>,
    profiles: Vec<String>,
    profile: String,
    error: String,
    autostart: bool,
    busy: String,
    login_running: bool,
    icons: Icons,
}

impl NetBird {
    pub fn detect() -> Option<NetBird> {
        if !crate::common::cmd::which("netbird") {
            return None;
        }
        let unit = service_unit();
        // Instancja szablonu ma własny socket; ustawione przed startem wątków.
        std::env::set_var("NB_DAEMON_ADDR", daemon_addr(&unit));
        let icon = |name: &str| icon_path(APP.id, name);
        Some(NetBird {
            autostart: unit_enabled(&unit),
            unit,
            status: None,
            networks: Vec::new(),
            profiles: Vec::new(),
            profile: String::new(),
            error: String::new(),
            busy: String::new(),
            login_running: false,
            icons: Icons {
                on: icon("netbird-tray-on"),
                off: icon("netbird-tray-disconnected"),
                exit: icon("netbird-tray-exit"),
                auth: icon("netbird-tray-auth"),
                relay: icon("netbird-tray-connecting"),
            },
        })
    }

    pub fn gather_now(&mut self) {
        apply_gathered(self, gather(&self.unit));
    }

    fn st(&self) -> &Value {
        static NULL: Value = Value::Null;
        self.status.as_ref().unwrap_or(&NULL)
    }

    fn state(&self) -> &str {
        s(self.st(), "daemonStatus")
    }

    fn connected(&self) -> bool {
        self.state() == "Connected"
    }

    fn needs_login(&self) -> bool {
        NEEDS_LOGIN.contains(&self.state())
    }

    /// Połączony albo łączy się (też w trakcie logowania z traya).
    pub fn active(&self) -> bool {
        matches!(self.state(), "Connected" | "Connecting") || self.login_running
    }

    fn exit_node(&self) -> Option<&Net> {
        self.networks.iter().find(|n| n.is_exit() && n.selected)
    }

    fn peers(&self) -> &[Value] {
        arr(get(self.st(), "peers"), "details")
    }

    fn admin_url(&self) -> String {
        admin_url(s(get(self.st(), "management"), "url"))
    }

    pub fn summary(&self) -> Summary {
        let mgmt_ok = b(get(self.st(), "management"), "connected");
        let (level, text, icon) = if self.error == "service-down" {
            (Level::Off, "service not running".to_string(), &self.icons.off)
        } else if !self.error.is_empty() {
            (Level::Off, "not responding".into(), &self.icons.off)
        } else if self.login_running {
            (Level::Attention, "waiting for login in the browser".into(), &self.icons.auth)
        } else if self.connected() && !mgmt_ok {
            (Level::Attention, "connected, management server unreachable".into(), &self.icons.relay)
        } else if self.connected() && self.exit_node().is_some() {
            (Level::On, "connected (exit node)".into(), &self.icons.exit)
        } else if self.connected() {
            (Level::On, "connected".into(), &self.icons.on)
        } else if self.state() == "Connecting" {
            (Level::Connecting, "connecting…".into(), &self.icons.relay)
        } else if self.needs_login() {
            (Level::Off, if self.state() == "SessionExpired" { "session expired" } else { "logged out" }.into(), &self.icons.off)
        } else {
            (Level::Off, "disconnected".into(), &self.icons.off)
        };
        let text = if self.profile.is_empty() || self.profiles.len() <= 1 { text } else { format!("{}: {text}", self.profile) };
        Summary { level, text, icon: icon.clone() }
    }

    /// Jedna pozycja na profil NetBird.
    pub fn choices(&self) -> Vec<Choice> {
        let active = self.active();
        if self.profiles.len() <= 1 {
            return vec![Choice { kind: Kind::NetBird, id: String::new(), detail: String::new(), active }];
        }
        let mut names = self.profiles.clone();
        names.sort_by_key(|n| n.to_lowercase());
        names
            .into_iter()
            .map(|n| Choice { kind: Kind::NetBird, active: active && n == self.profile, detail: n.clone(), id: n })
            .collect()
    }

    /// Połączenie z profilem: down (przy innym profilu), profile select, up; gdy profil wymaga
    /// logowania - logowanie SSO w przeglądarce (czeka na nie).
    pub fn connect_job(&self, id: &str) -> Job {
        let switch = (!id.is_empty() && id != self.profile).then(|| id.to_string());
        let (connected, needs_login) = (self.connected() || self.state() == "Connecting", self.needs_login());
        Box::new(move || {
            if let Some(name) = &switch {
                if connected {
                    netbird(&["down"], 30);
                }
                let out = netbird(&["profile", "select", name], 30);
                if !out.ok() {
                    return Err(output(&out));
                }
            }
            if needs_login && switch.is_none() {
                login(up_cmd(&[]));
                return Ok(());
            }
            let up = netbird(&["up", "--no-browser"], 90);
            if !up.ok() && needs_login_text(&output(&up)) {
                login(up_cmd(&[]));
                return Ok(());
            }
            if up.ok() { Ok(()) } else { Err(output(&up)) }
        })
    }

    pub fn disconnect_job(&self) -> Job {
        Box::new(|| {
            let out = netbird(&["down"], 60);
            if out.ok() { Ok(()) } else { Err(output(&out)) }
        })
    }

    // ---------- menu ----------

    fn status_items(&self) -> Menu<Tray> {
        let mut m = Vec::new();
        let state = self.state();
        let current = self.profile.clone();
        let connect = move |t: &mut Tray| t.switch_to(Kind::NetBird, current.clone());
        m.push(if !self.busy.is_empty() {
            text(&self.busy)
        } else if self.login_running {
            text("Waiting for login in the browser…")
        } else if self.error == "service-down" {
            button("NetBird service is not running - click to start", true, |t: &mut Tray| t.nb().start_service())
        } else if !self.error.is_empty() {
            text(&format!("NetBird: {}", self.error.chars().take(80).collect::<String>()))
        } else if state == "Connected" {
            check("Connected", true, true, |t: &mut Tray, _| t.nb().disconnect())
        } else if self.needs_login() {
            let what = if state == "SessionExpired" { "Session expired" } else { "Logged out" };
            button(&format!("{what} - click to log in…"), true, connect)
        } else if state == "Connecting" {
            text("Connecting…")
        } else {
            check("Disconnected - click to connect", false, true, move |t: &mut Tray, _| connect(t))
        });
        if self.connected() {
            let problems: Vec<&str> =
                ["management", "signal"].into_iter().filter(|name| !b(get(self.st(), name), "connected")).collect();
            if !problems.is_empty() {
                let mut what = problems.join(" and ");
                what[..1].make_ascii_uppercase();
                m.push(text(&format!("⚠ {what} server unreachable")));
            }
        }
        m
    }

    fn profiles_menu(&self) -> ksni::MenuItem<Tray> {
        let mut names = self.profiles.clone();
        names.sort_by_key(|n| n.to_lowercase());
        let idle = self.busy.is_empty() && !self.login_running;
        let mut sub: Menu<Tray> = Vec::new();
        if !names.is_empty() {
            let selected = names.iter().position(|n| *n == self.profile).unwrap_or(usize::MAX);
            let options = names.iter().map(|n| (n.clone(), idle)).collect();
            sub.push(radio(options, selected, move |t: &mut Tray, i| t.nb().switch_profile(names[i].clone())));
            sub.push(sep());
        }
        let expires = s(self.st(), "sessionExpiresAt");
        if !expires.is_empty() && self.connected() {
            sub.push(text(&format!("Session expires {}", until_text(expires))));
        }
        let ready = self.status.is_some() && idle;
        sub.push(button("Log in again (extend session)…", ready && self.connected(), |t: &mut Tray| {
            // `up` przy aktywnym połączeniu kończy się "Already connected" bez logowania; `login --extend`
            // przedłuża sesję SSO bez zrywania tunelu (nowy termin wg ustawienia w panelu).
            t.nb().login(cmd(&["netbird", "login", "--extend", "--no-browser"]));
        }));
        sub.push(button("Add another profile…", ready, |t: &mut Tray| {
            let (mgmt, connected) = (s(get(t.nb().st(), "management"), "url").to_string(), t.nb().connected());
            bg(move || add_profile(&mgmt, connected));
        }));
        let admin = self.admin_url();
        sub.push(button("Admin console", !admin.is_empty(), move |_| open_url(&admin)));
        let label = if self.profile.is_empty() { "Profiles".into() } else { format!("Profile: {}", self.profile) };
        submenu(&label, true, sub)
    }

    fn devices_menu(&self) -> ksni::MenuItem<Tray> {
        let mut peers: Vec<&Value> = self.peers().iter().collect();
        let up = |p: &Value| s(p, "status") == "Connected";
        let online = peers.iter().filter(|p| up(p)).count();
        peers.sort_by_key(|p| (!up(p), short_name(s(p, "fqdn")).to_lowercase()));
        let mut sub: Menu<Tray> = Vec::new();
        if peers.is_empty() {
            sub.push(text("No devices"));
        }
        for p in &peers {
            let ip = strip_prefix(s(p, "netbirdIp"));
            let how = if up(p) {
                let kind = s(p, "connectionType");
                let latency_ms = n(p, "latency") / 1e6;
                let lat = if latency_ms >= 1.0 { format!(", {latency_ms:.0} ms") } else { String::new() };
                format!("  [{}{lat}]", if kind.is_empty() { "?" } else { kind })
            } else if s(p, "status") == "Idle" {
                "  [idle]".into()
            } else {
                String::new()
            };
            let mark = if up(p) { "●" } else { "○" };
            let label = format!("{mark} {}  {ip}{how}", short_name(s(p, "fqdn")));
            sub.push(button(&label, true, move |_| copy(&ip)));
        }
        sub.push(sep());
        sub.push(text("Click a device to copy its IP"));
        submenu(&format!("Network devices ({online}/{} connected)", peers.len()), self.status.is_some(), sub)
    }

    fn networks_menu(&self) -> ksni::MenuItem<Tray> {
        let mut nets: Vec<&Net> = self.networks.iter().filter(|n| !n.is_exit()).collect();
        nets.sort_by_key(|n| n.id.to_lowercase());
        let on = nets.iter().filter(|n| n.selected).count();
        let idle = self.busy.is_empty();
        let mut sub: Menu<Tray> = Vec::new();
        if nets.is_empty() {
            sub.push(text(if self.connected() { "No networks available" } else { "Connect to see networks" }));
        }
        for net in &nets {
            let target = if net.network.is_empty() { &net.domains } else { &net.network };
            let id = net.id.clone();
            sub.push(check(&format!("{}  ({target})", net.id), net.selected, idle, move |t: &mut Tray, v| {
                t.nb().set_network(id.clone(), v)
            }));
        }
        if !nets.is_empty() {
            sub.push(sep());
            sub.push(button("Select all (incl. future ones)", idle, |t: &mut Tray| {
                t.nb().netbird_bg("Changing networks…", "Could not select networks", &["networks", "select", "all"], 60)
            }));
        }
        let label = if nets.is_empty() { "Networks".into() } else { format!("Networks ({on}/{})", nets.len()) };
        submenu(&label, self.connected(), sub)
    }

    fn exit_nodes_menu(&self) -> ksni::MenuItem<Tray> {
        let mut exits: Vec<&Net> = self.networks.iter().filter(|n| n.is_exit()).collect();
        exits.sort_by_key(|n| n.id.to_lowercase());
        let current = self.exit_node().map(|n| n.id.clone());
        let idle = self.busy.is_empty();
        let mut options = vec![("None".to_string(), idle)];
        let mut ids = vec![String::new()];
        let mut selected = if current.is_none() { 0 } else { usize::MAX };
        for net in &exits {
            if current.as_ref() == Some(&net.id) {
                selected = ids.len();
            }
            options.push((net.id.clone(), idle));
            ids.push(net.id.clone());
        }
        let mut sub: Menu<Tray> = vec![radio(options, selected, move |t: &mut Tray, i| t.nb().set_exit_node(ids[i].clone()))];
        if exits.is_empty() {
            sub.push(text("No exit nodes in this network"));
        }
        let label = current.map(|c| format!("Exit node: {c}")).unwrap_or_else(|| "Exit nodes".into());
        submenu(&label, self.connected(), sub)
    }

    fn settings_menu(&self) -> ksni::MenuItem<Tray> {
        let ssh = b(get(self.st(), "sshServer"), "enabled");
        let idle = self.busy.is_empty();
        let unit = self.unit.clone();
        let sub = vec![
            check("Allow SSH server on this device", ssh, self.connected() && idle, |t: &mut Tray, v| t.nb().set_ssh(v)),
            check("Start with the system", self.autostart, true, |t: &mut Tray, v| {
                let unit = t.nb().unit.clone();
                bg(move || set_autostart(&unit, v));
            }),
            sep(),
            button("Restart NetBird service", idle, |t: &mut Tray| t.nb().restart_service()),
            button("Service log", true, move |_| APP.in_terminal(&["journalctl", "-u", &unit, "-n", "200", "-f"])),
        ];
        submenu("Settings", true, sub)
    }

    pub fn menu(&self) -> Menu<Tray> {
        let admin = self.admin_url();
        let mut m = Vec::new();
        if let Some(host) = host_of(&admin) {
            m.push(text(&format!("Server: {host}")));
        }
        m.extend(self.status_items());
        m.extend([sep(), self.profiles_menu(), sep()]);
        let st = self.st();
        if !s(st, "netbirdIp").is_empty() {
            let ip = strip_prefix(s(st, "netbirdIp"));
            let mode = if b(st, "usesKernelInterface") { "kernel" } else { "userspace" };
            let label = format!("This device: {} ({ip})  [{mode} WireGuard]", short_name(s(st, "fqdn")));
            m.push(button(&label, true, move |_| copy(&ip)));
        }
        m.extend([self.devices_menu(), sep(), self.networks_menu(), self.exit_nodes_menu(), sep(), self.settings_menu()]);
        m
    }

    // ---------- akcje ----------

    /// Długie polecenie (CLI netbird, systemctl) w wątku, żeby menu nie zamarzało;
    /// w tym czasie status w menu pokazuje, co się dzieje.
    fn in_background(&mut self, busy: &str, work: impl FnOnce() -> Out + Send + 'static, done: impl FnOnce(Out) + Send + 'static) {
        if !self.busy.is_empty() {
            return;
        }
        self.busy = busy.into();
        bg(move || {
            let out = work();
            update(|t| t.nb().busy.clear());
            done(out);
            refresh_now();
        });
    }

    fn netbird_bg(&mut self, busy: &str, what: &str, args: &[&str], timeout: u64) {
        let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        let what = what.to_string();
        self.in_background(
            busy,
            move || netbird(&args.iter().map(String::as_str).collect::<Vec<_>>(), timeout),
            move |out| report(&out, &what),
        );
    }

    fn disconnect(&mut self) {
        self.netbird_bg("Disconnecting…", "Could not disconnect", &["down"], 60);
    }

    fn set_network(&mut self, id: String, selected: bool) {
        let args: Vec<&str> = if selected { vec!["networks", "select", "-a", &id] } else { vec!["networks", "deselect", &id] };
        self.netbird_bg("Changing networks…", "Could not change the network selection", &args, 60);
    }

    fn set_exit_node(&mut self, id: String) {
        let current = self.exit_node().map(|n| n.id.clone());
        let work = move || {
            let mut out = Out::default();
            if let Some(cur) = current.filter(|c| *c != id) {
                out = netbird(&["networks", "deselect", &cur], 30);
            }
            if !id.is_empty() {
                out = netbird(&["networks", "select", "-a", &id], 30);
            }
            out
        };
        self.in_background("Changing exit node…", work, |out| report(&out, "Could not change the exit node"));
    }

    fn set_ssh(&mut self, enabled: bool) {
        // Ustawienia `up` działają dopiero po ponownym połączeniu ("Already connected" bez down).
        let work = move || {
            netbird(&["down"], 30);
            netbird(&["up", "--no-browser", &format!("--allow-server-ssh={enabled}")], 90)
        };
        self.in_background("Reconnecting…", work, |out| report(&out, "Could not change the SSH setting"));
    }

    fn start_service(&mut self) {
        let unit = self.unit.clone();
        self.in_background("Starting NetBird service…", move || systemctl("start", &unit), |out| {
            report(&out, "Could not start the NetBird service")
        });
    }

    fn restart_service(&mut self) {
        let unit = self.unit.clone();
        self.in_background("Restarting NetBird service…", move || systemctl("restart", &unit), |out| {
            report(&out, "Could not restart the NetBird service")
        });
    }

    /// Zmiana profilu z podmenu NetBird: przy połączeniu down → select → up (inne VPN-y są już
    /// rozłączone, skoro NetBird działa); bez połączenia tylko wybór profilu.
    fn switch_profile(&mut self, name: String) {
        let was_connected = self.connected();
        let busy = format!("Switching to {name}…");
        let n = name.clone();
        let work = move || {
            if was_connected {
                netbird(&["down"], 30);
            }
            let out = netbird(&["profile", "select", &n], 30);
            if out.ok() && was_connected {
                let up = netbird(&["up", "--no-browser"], 90);
                if !up.ok() && needs_login_text(&output(&up)) {
                    return up; // profil wymaga logowania - done() uruchomi login()
                }
            }
            out
        };
        let done = move |out: Out| {
            if !out.ok() && needs_login_text(&output(&out)) {
                update(|t| t.nb().login(up_cmd(&[])));
            } else {
                report(&out, &format!("Could not switch to profile {name}"));
            }
        };
        self.in_background(&busy, work, done);
    }

    /// Logowanie SSO: --no-browser, bo CLI sam też próbuje otworzyć przeglądarkę - otwieramy ją raz, sami.
    fn login(&mut self, cmd: Vec<String>) {
        if self.login_running {
            return;
        }
        self.login_running = true;
        bg(move || login(cmd));
    }
}

// ---------- akcje w tle ----------

fn cmd(args: &[&str]) -> Vec<String> {
    args.iter().map(|a| a.to_string()).collect()
}

fn up_cmd(extra: &[&str]) -> Vec<String> {
    let mut c = cmd(&["netbird", "up", "--no-browser"]);
    c.extend(extra.iter().map(|a| a.to_string()));
    c
}

fn copy(text: &str) {
    let text = text.to_string();
    bg(move || APP.copy_to_clipboard(&text));
}

fn systemctl(verb: &str, unit: &str) -> Out {
    run(&["pkexec", "systemctl", verb, unit], 120)
}

/// "Start with the system" = usługa włączona w systemd; z autoconnect demon sam się połączy.
fn set_autostart(unit: &str, enabled: bool) {
    let verb = if enabled { "enable" } else { "disable" };
    report(&systemctl(verb, unit), &format!("systemctl {verb} {unit} failed"));
    let now = unit_enabled(unit);
    update(|t| t.nb().autostart = now);
    refresh_now();
}

fn add_profile(mgmt_url: &str, connected: bool) {
    let Some(name) = APP.inputbox("Name of the new NetBird profile (e.g. home, work):", "") else { return };
    if name.is_empty() {
        return;
    }
    if !Regex::new(r"^[A-Za-z0-9_.-]+$").unwrap().is_match(&name) {
        APP.error("Use only letters, digits, '.', '_' and '-' in the profile name.");
        return;
    }
    let current = if mgmt_url.is_empty() { "https://".to_string() } else { mgmt_url.replace(":443", "") };
    let Some(url) = APP.inputbox("Management server URL for this profile:", &current) else { return };
    if url.is_empty() {
        return;
    }
    let out = netbird(&["profile", "add", &name], 30);
    if !out.ok() {
        APP.error(&format!("Could not add profile {name}:\n{}", output(&out)));
        return;
    }
    if connected {
        netbird(&["down"], 30);
    }
    netbird(&["profile", "select", &name], 30);
    update(|t| t.nb().login(up_cmd(&["--management-url", &url, "--admin-url", &url])));
}

/// Logowanie (blokuje do końca): adres z wyjścia CLI otwierany raz w przeglądarce.
fn login(cmd: Vec<String>) {
    update(|t| t.nb().login_running = true);
    let url = Regex::new(r"https://\S+/oauth2/auth\S*|https://\S+(device|login|authorize)\S*").unwrap();
    let mut opened = false;
    let argv: Vec<&str> = cmd.iter().map(String::as_str).collect();
    let (code, lines) = stream_lines(&argv, |line| {
        if let (false, Some(m)) = (opened, url.find(line)) {
            opened = true; // przeglądarka tylko raz na logowanie
            open_url(m.as_str());
        }
    });
    update(|t| {
        t.nb().busy.clear();
        t.nb().login_running = false;
    });
    if code != 0 {
        let tail = lines[lines.len().saturating_sub(15)..].join("\n");
        APP.error(&format!("NetBird login failed:\n{}", clean(&tail)));
    } else {
        let status: Value = serde_json::from_str(&netbird(&["status", "--json"], 30).stdout).unwrap_or(Value::Null);
        let expires = until_text(s(&status, "sessionExpiresAt"));
        let body = if expires.is_empty() { String::new() } else { format!("Session expires {expires}.") };
        APP.notify("NetBird: logged in", &body);
    }
    refresh_now();
}

struct Gathered {
    status: Option<Value>,
    error: String,
    networks: Vec<Net>,
    profiles: Vec<String>,
    profile: String,
}

/// Odpytanie CLI (każde wywołanie to osobny proces).
fn gather(unit: &str) -> Gathered {
    let mut g = Gathered { status: None, error: String::new(), networks: Vec::new(), profiles: Vec::new(), profile: String::new() };
    let out = netbird(&["status", "--json"], 8);
    match serde_json::from_str::<Value>(&out.stdout) {
        Ok(v) if v.is_object() => g.status = Some(v),
        _ => {
            g.error = output(&out);
            if g.error.is_empty() {
                g.error = "NetBird daemon is not responding".into();
            }
            if !unit_active(unit) {
                g.error = "service-down".into();
            }
        }
    }
    if let Some(st) = &g.status {
        if s(st, "daemonStatus") == "Connected" {
            g.networks = parse_networks(&netbird(&["networks", "list"], 8).stdout);
        }
        (g.profiles, g.profile) = parse_profiles(&netbird(&["profile", "list"], 8).stdout);
        if g.profile.is_empty() {
            g.profile = s(st, "profileName").into();
        }
    }
    g
}

fn apply_gathered(t: &mut NetBird, g: Gathered) {
    (t.status, t.error, t.networks, t.profiles, t.profile) = (g.status, g.error, g.networks, g.profiles, g.profile);
}

pub fn start() {
    let unit = service_unit();
    let _ = POLLER.set(Poller::start(POLL, move || {
        let g = gather(&unit);
        update(move |t| {
            if let Some(nb) = t.nb.as_mut() {
                apply_gathered(nb, g);
            }
        });
    }));
}
