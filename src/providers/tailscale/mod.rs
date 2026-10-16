//! Tailscale (dawny tailscale-tray): status, konta (przełączanie, dodawanie), to urządzenie,
//! urządzenia w sieci, exit nody, ustawienia.
//!
//! Rozmawia z tailscaled przez jego LocalAPI (unix socket). Zmiana ustawień bez roota wymaga,
//! żeby użytkownik był operatorem Tailscale: sudo tailscale set --operator=$USER (robi to install.sh).

mod localapi;

use std::sync::OnceLock;
use std::time::Duration;

use regex::Regex;
use serde_json::{json, Map, Value};
use crate::common::json::{arr, b, get, s, values};
use crate::common::menu::{button, check, radio, sep, submenu, text, Menu};
use crate::common::{bg, icon_path, open_url, run, Out, Poller};
use crate::providers::{Choice, Job, Kind, Level, Summary};
use crate::{update, Tray, APP};

use localapi::api;

const POLL: Duration = Duration::from_secs(3);
const ADMIN_URL: &str = "https://login.tailscale.com/admin/machines";
const ROUTES_URL: &str = "https://login.tailscale.com/admin/machines?q=property%3Asubnet"; // maszyny ogłaszające trasy

static POLLER: OnceLock<Poller> = OnceLock::new();

pub fn refresh_now() {
    if let Some(p) = POLLER.get() {
        p.poke();
    }
}

/// Wartości domyślne Tailscale na Linuksie (tailscale up bez flag).
fn default_prefs() -> Vec<(&'static str, Value)> {
    vec![
        ("ShieldsUp", json!(false)),
        ("CorpDNS", json!(true)),
        ("RouteAll", json!(false)),
        ("ExitNodeID", json!("")),
        ("ExitNodeIP", json!("")),
        ("ExitNodeAllowLANAccess", json!(false)),
    ]
}

/// PATCH prefs; każde pole wymaga flagi <Pole>Set, inaczej tailscaled je ignoruje.
fn set_prefs(prefs: &[(&str, Value)]) -> Result<(), String> {
    let mut body = Map::new();
    for (key, value) in prefs {
        body.insert((*key).into(), value.clone());
        body.insert(format!("{key}Set"), json!(true));
    }
    api("PATCH", "prefs", Some(&Value::Object(body))).map(|_| ())
}

fn user_name() -> String {
    std::env::var("USER").ok().filter(|u| !u.is_empty()).unwrap_or_else(|| run(&["id", "-un"], 5).stdout.trim().into())
}

/// stderr, a gdy pusty - stdout.
fn detail(out: &Out) -> String {
    if out.stderr.trim().is_empty() { out.stdout.trim().into() } else { out.stderr.trim().into() }
}

/// Polecenie tailscale jako użytkownik; przy braku uprawnień (profil bez operatora) przez pkexec,
/// od razu przywracając operatora w profilu, który jest aktywny po poleceniu.
fn tailscale_admin(args: &[&str]) -> Out {
    let mut cmd = vec!["tailscale"];
    cmd.extend_from_slice(args);
    let out = run(&cmd, 30);
    let denied = Regex::new(r"(?i)access denied|permission denied|must be root|operator").unwrap();
    if out.ok() || !denied.is_match(&format!("{}{}", out.stdout, out.stderr)) {
        return out;
    }
    let operator = format!("OPERATOR={}", user_name());
    let mut cmd = vec!["pkexec", "env", &operator, "sh", "-c", r#"tailscale "$@" && tailscale set --operator="$OPERATOR""#, "sh"];
    cmd.extend_from_slice(args);
    run(&cmd, 120)
}

/// "Run unattended" na Linuksie = tailscaled startuje z systemem, bez logowania użytkownika.
fn unattended_enabled() -> bool {
    crate::common::unit_enabled("tailscaled")
}

fn profile_label(profile: &Value) -> String {
    let user = get(profile, "UserProfile");
    let name = s(user, "DisplayName");
    let login = if s(user, "LoginName").is_empty() { s(profile, "Name") } else { s(user, "LoginName") };
    let mut label = if !name.is_empty() && !login.is_empty() && name != login {
        format!("{name} ({login})")
    } else if !name.is_empty() {
        name.into()
    } else if !login.is_empty() {
        login.into()
    } else if !s(profile, "ID").is_empty() {
        s(profile, "ID").into()
    } else {
        "?".into()
    };
    let tailnet = s(get(profile, "NetworkProfile"), "DomainName");
    if !tailnet.is_empty() && tailnet != login {
        label += &format!("  [{tailnet}]");
    }
    label
}

/// Krótka nazwa konta na liście wyboru VPN: login (albo nazwa profilu).
fn profile_short(profile: &Value) -> String {
    let login = s(get(profile, "UserProfile"), "LoginName");
    [login, s(profile, "Name"), s(profile, "ID"), "?"].into_iter().find(|t| !t.is_empty()).unwrap().into()
}

fn first_ip(node: &Value) -> String {
    let ips: Vec<&str> = arr(node, "TailscaleIPs").iter().filter_map(Value::as_str).collect();
    ips.iter().find(|ip| !ip.contains(':')).or(ips.first()).map(|ip| ip.to_string()).unwrap_or_else(|| "-".into())
}

fn node_name(node: &Value) -> String {
    let dns = s(node, "DNSName").split('.').next().unwrap_or("");
    [dns, s(node, "HostName")].into_iter().find(|n| !n.is_empty()).unwrap_or("?").into()
}

struct Icons {
    on: String,
    off: String,
    exit: String,
}

pub struct Tailscale {
    status: Option<Value>,
    prefs: Option<Value>,
    profiles: Vec<Value>,
    current_profile: String,
    error: String,
    unattended: bool,
    login_running: bool,
    icons: Icons,
}

impl Tailscale {
    pub fn detect() -> Option<Tailscale> {
        if !crate::common::cmd::which("tailscale") {
            return None;
        }
        let icon = |name: &str| icon_path(APP.id, name);
        Some(Tailscale {
            status: None,
            prefs: None,
            profiles: Vec::new(),
            current_profile: String::new(),
            error: String::new(),
            unattended: unattended_enabled(),
            login_running: false,
            icons: Icons { on: icon("tailscale-tray-on"), off: icon("tailscale-tray-disconnected"), exit: icon("tailscale-tray-exit") },
        })
    }

    pub fn gather_now(&mut self) {
        apply_gathered(self, gather());
    }

    fn backend(&self) -> &str {
        self.status.as_ref().map(|st| s(st, "BackendState")).filter(|b| !b.is_empty()).unwrap_or("NoState")
    }

    fn connected(&self) -> bool {
        self.backend() == "Running"
    }

    /// Włączony (połączony, łączy się albo czeka na zatwierdzenie maszyny).
    pub fn active(&self) -> bool {
        matches!(self.backend(), "Running" | "Starting" | "NeedsMachineAuth")
    }

    pub fn interfaces(&self) -> Vec<String> {
        vec!["tailscale0".into()]
    }

    fn me(&self) -> Option<&Value> {
        self.status.as_ref().map(|st| get(st, "Self")).filter(|me| me.is_object())
    }

    fn peers(&self) -> Vec<&Value> {
        self.status.as_ref().map(|st| values(st, "Peer")).unwrap_or_default()
    }

    fn current_user(&self) -> String {
        let Some(st) = &self.status else { return String::new() };
        let uid = match get(get(st, "Self"), "UserID") {
            Value::Number(n) => n.to_string(),
            Value::String(t) => t.clone(),
            _ => String::new(),
        };
        let user = get(get(st, "User"), &uid);
        let (name, login) = (s(user, "DisplayName"), s(user, "LoginName"));
        if !name.is_empty() && !login.is_empty() && name != login {
            format!("{name} ({login})")
        } else if !name.is_empty() {
            name.into()
        } else {
            login.into()
        }
    }

    fn exit_node(&self) -> Option<&Value> {
        self.peers().into_iter().find(|p| b(p, "ExitNode"))
    }

    pub fn summary(&self) -> Summary {
        let (level, text, icon) = if !self.error.is_empty() {
            (Level::Off, "service not running", &self.icons.off)
        } else {
            match self.backend() {
                "Running" if self.exit_node().is_some() => (Level::On, "connected (exit node)", &self.icons.exit),
                "Running" => (Level::On, "connected", &self.icons.on),
                "Starting" => (Level::Connecting, "connecting…", &self.icons.on),
                "NeedsMachineAuth" => (Level::Attention, "waiting for admin approval", &self.icons.off),
                "NeedsLogin" => (Level::Off, "logged out", &self.icons.off),
                _ => (Level::Off, "disconnected", &self.icons.off),
            }
        };
        Summary { level, text: text.into(), icon: icon.clone() }
    }

    /// Jedna pozycja na konto; przy jednym koncie sama nazwa "Tailscale".
    pub fn choices(&self) -> Vec<Choice> {
        let active = self.active();
        if self.profiles.len() <= 1 {
            return vec![Choice { kind: Kind::Tailscale, id: String::new(), detail: String::new(), active }];
        }
        let mut profiles: Vec<&Value> = self.profiles.iter().collect();
        profiles.sort_by_key(|p| profile_short(p).to_lowercase());
        profiles
            .into_iter()
            .map(|p| Choice {
                kind: Kind::Tailscale,
                id: s(p, "ID").into(),
                detail: profile_short(p),
                active: active && s(p, "ID") == self.current_profile,
            })
            .collect()
    }

    /// Połączenie: przełączenie konta (jeśli trzeba), logowanie, gdy konto jest wylogowane, WantRunning.
    pub fn connect_job(&self, id: &str) -> Job {
        let id = if id == self.current_profile { String::new() } else { id.to_string() };
        Box::new(move || {
            if !id.is_empty() && api("POST", &format!("profiles/{id}"), None).is_err() {
                let out = tailscale_admin(&["switch", &id]);
                let switched = api("GET", "profiles/current", None).map(|v| s(&v, "ID") == id).unwrap_or(false);
                if !switched {
                    return if out.code == 126 { Ok(()) } else { Err(detail(&out)) };
                }
            }
            let state = api("GET", "status", None).map(|st| s(&st, "BackendState").to_string()).unwrap_or_default();
            if state == "NeedsLogin" {
                update(|t| t.ts().login_running = true);
                login();
                return Ok(());
            }
            set_prefs(&[("WantRunning", json!(true))])
        })
    }

    pub fn disconnect_job(&self) -> Job {
        Box::new(|| set_prefs(&[("WantRunning", json!(false))]))
    }

    // ---------- menu ----------

    fn status_item(&self) -> ksni::MenuItem<Tray> {
        if !self.error.is_empty() {
            return button("Tailscale service is not running - click to start", true, |_| bg(start_service));
        }
        let current = self.current_profile.clone();
        let connect = move |t: &mut Tray| t.switch_to(Kind::Tailscale, current.clone());
        match self.backend() {
            "Running" => check("Connected", true, true, |t: &mut Tray, _| t.disconnect_all()),
            "NeedsLogin" => button("Logged out - click to log in…", !self.login_running, connect),
            "Starting" => text("Connecting…"),
            "NeedsMachineAuth" => button("Waiting for admin approval…", true, |_| open_url(ADMIN_URL)),
            _ => check("Disconnected - click to connect", false, true, move |t, _| connect(t)),
        }
    }

    fn accounts_menu(&self) -> ksni::MenuItem<Tray> {
        let user = self.current_user();
        let logged_in = !user.is_empty();
        let mut profiles: Vec<&Value> = self.profiles.iter().collect();
        profiles.sort_by_key(|p| profile_label(p).to_lowercase());
        let mut sub: Menu<Tray> = Vec::new();
        if !profiles.is_empty() {
            let ids: Vec<String> = profiles.iter().map(|p| s(p, "ID").to_string()).collect();
            let selected = ids.iter().position(|id| *id == self.current_profile).unwrap_or(usize::MAX);
            let options = profiles.iter().map(|p| (profile_label(p), true)).collect();
            sub.push(radio(options, selected, move |t: &mut Tray, i| {
                let (pid, was_connected) = (ids[i].clone(), t.ts().connected());
                bg(move || switch_account(&pid, was_connected));
            }));
            sub.push(sep());
        }
        sub.push(button("Add another account…", self.error.is_empty() && !self.login_running, |t: &mut Tray| {
            t.ts().login_running = true;
            bg(login);
        }));
        sub.push(button("Admin console", logged_in, |_| open_url(ADMIN_URL)));
        // Zatwierdzanie tras to uprawnienie admina (API z kluczem) - celowo tylko link do panelu, bez kluczy na laptopie.
        sub.push(button("Manage subnet routes…", logged_in, |_| open_url(ROUTES_URL)));
        sub.push(sep());
        sub.push(button("Log out", logged_in, |t: &mut Tray| {
            let user = t.ts().current_user();
            bg(move || logout(&user));
        }));
        submenu(if logged_in { &user } else { "Not logged in" }, true, sub)
    }

    fn devices_menu(&self) -> ksni::MenuItem<Tray> {
        let mut peers = self.peers();
        let online = peers.iter().filter(|p| b(p, "Online")).count();
        peers.sort_by_key(|p| (!b(p, "Online"), node_name(p).to_lowercase()));
        let mut sub: Menu<Tray> = Vec::new();
        if peers.is_empty() {
            sub.push(text("No devices"));
        }
        for p in &peers {
            let ip = first_ip(p);
            let mark = if b(p, "Online") { "●" } else { "○" };
            let os = if s(p, "OS").is_empty() { String::new() } else { format!("  [{}]", s(p, "OS")) };
            let label = format!("{mark} {}  {ip}{os}", node_name(p));
            sub.push(button(&label, true, move |_| copy(&ip)));
        }
        sub.push(sep());
        sub.push(text("Click a device to copy its IP"));
        submenu(&format!("Network devices ({online}/{} online)", peers.len()), self.status.is_some(), sub)
    }

    fn exit_nodes_menu(&self) -> ksni::MenuItem<Tray> {
        let mut peers: Vec<&Value> = self.peers().into_iter().filter(|p| b(p, "ExitNodeOption")).collect();
        peers.sort_by_key(|p| node_name(p).to_lowercase());
        let null = Value::Null;
        let prefs = self.prefs.as_ref().unwrap_or(&null);
        let current_id = s(prefs, "ExitNodeID");
        let label = match self.exit_node() {
            Some(n) => format!("Exit node: {}", node_name(n)),
            None => "Exit nodes".into(),
        };

        let mut options = vec![("None".to_string(), true)];
        let mut ids = vec![String::new()];
        let mut selected = if current_id.is_empty() { 0 } else { usize::MAX };
        for p in &peers {
            let online = b(p, "Online");
            let active = s(p, "ID") == current_id && !current_id.is_empty();
            if active {
                selected = ids.len();
            }
            let suffix = if online { "" } else { "  (offline)" };
            options.push((format!("{}  {}{suffix}", node_name(p), first_ip(p)), online || active));
            ids.push(s(p, "ID").into());
        }
        let mut sub: Menu<Tray> = vec![radio(options, selected, move |_: &mut Tray, i| {
            let id = ids[i].clone();
            bg(move || set_exit_node(&id));
        })];
        if peers.is_empty() {
            sub.push(text("No exit nodes in this tailnet"));
        }
        sub.push(sep());
        sub.push(check("Allow local network access", b(prefs, "ExitNodeAllowLANAccess"), true, |_, v| {
            bg(move || apply(vec![("ExitNodeAllowLANAccess", json!(v))]))
        }));
        submenu(&label, self.prefs.is_some(), sub)
    }

    fn settings_menu(&self) -> ksni::MenuItem<Tray> {
        let null = Value::Null;
        let p = self.prefs.as_ref().unwrap_or(&null);
        let ok = self.prefs.is_some();
        let sub = vec![
            check("Allow incoming connections", !b(p, "ShieldsUp"), ok, |_, v| {
                bg(move || apply(vec![("ShieldsUp", json!(!v))]))
            }),
            check("Use Tailscale DNS settings", b(p, "CorpDNS"), ok, |_, v| bg(move || apply(vec![("CorpDNS", json!(v))]))),
            check("Use Tailscale subnets", b(p, "RouteAll"), ok, |_, v| bg(move || apply(vec![("RouteAll", json!(v))]))),
            check("Run unattended (start with the system)", self.unattended, true, |_, v| bg(move || set_unattended(v))),
            sep(),
            button("Reset to defaults", ok, |_| bg(reset_defaults)),
        ];
        submenu("Settings", true, sub)
    }

    pub fn menu(&self) -> Menu<Tray> {
        let mut m = vec![self.status_item(), sep(), self.accounts_menu(), sep()];
        if let Some(me) = self.me() {
            let ip = first_ip(me);
            m.push(button(&format!("This device: {} ({ip})", node_name(me)), true, move |_| copy(&ip)));
        }
        let tailnet = self.status.as_ref().map(|st| s(get(st, "CurrentTailnet"), "Name").to_string()).unwrap_or_default();
        if !tailnet.is_empty() {
            m.push(text(&format!("Tailnet: {tailnet}")));
        }
        m.extend([self.devices_menu(), sep(), self.exit_nodes_menu(), sep(), self.settings_menu()]);
        m
    }
}

// ---------- akcje w tle ----------

fn copy(text: &str) {
    let text = text.to_string();
    bg(move || APP.copy_to_clipboard(&text));
}

fn apply(prefs: Vec<(&str, Value)>) {
    if let Err(e) = set_prefs(&prefs) {
        APP.error(&format!("Tailscale: could not change the setting:\n{e}"));
    }
    refresh_now();
}

fn set_exit_node(id: &str) {
    if id.is_empty() {
        apply(vec![("ExitNodeID", json!("")), ("ExitNodeIP", json!(""))]);
    } else {
        apply(vec![("ExitNodeID", json!(id))]);
    }
}

fn set_unattended(enabled: bool) {
    let verb = if enabled { "enable" } else { "disable" };
    let out = run(&["pkexec", "systemctl", verb, "tailscaled"], 120);
    if !out.ok_or_cancelled() {
        APP.error(&format!("systemctl {verb} tailscaled failed:\n{}", out.stderr.trim()));
    }
    let now = unattended_enabled();
    update(|t| t.ts().unattended = now);
}

fn start_service() {
    let out = run(&["pkexec", "systemctl", "start", "tailscaled"], 120);
    if !out.ok_or_cancelled() {
        APP.error(&format!("Could not start tailscaled:\n{}", out.stderr.trim()));
    }
    refresh_now();
}

fn reset_defaults() {
    if APP.yesno(
        "Reset Tailscale settings to defaults?\n\n\
         Allow incoming connections: on\nUse Tailscale DNS: on\nUse Tailscale subnets: off\n\
         Exit node: none\nAllow local network access: off",
    ) {
        apply(default_prefs());
    }
}

/// Każdy profil pamięta własne WantRunning; jak w kliencie na Windows połączenie ma przejść
/// na nowe konto. 'tailscale switch' kończy się kodem 1 ("Tailscale is stopped"), gdy docelowy
/// profil był rozłączony, więc o powodzeniu decyduje aktywny profil, nie kod wyjścia.
fn switch_account(profile_id: &str, was_connected: bool) {
    let mut res = None;
    if api("POST", &format!("profiles/{profile_id}"), None).is_err() {
        res = Some(tailscale_admin(&["switch", profile_id])); // np. bieżący profil bez operatora
    }
    let switched = api("GET", "profiles/current", None).map(|v| s(&v, "ID") == profile_id).unwrap_or(false);
    if switched && was_connected {
        if let Err(e) = set_prefs(&[("WantRunning", json!(true))]) {
            APP.error(&format!("Switched account, but could not connect:\n{e}"));
        }
    } else if !switched && !res.as_ref().is_some_and(|r| r.code == 126) {
        let why = res.as_ref().map(detail).unwrap_or_else(|| "tailscaled refused the switch".into());
        APP.error(&format!("Could not switch Tailscale account:\n{why}"));
    }
    refresh_now();
}

fn logout(user: &str) {
    if !APP.yesno(&format!("Log out {user} from Tailscale?\n\nThis device will leave the tailnet until you log in again.")) {
        return;
    }
    let out = tailscale_admin(&["logout"]);
    if !out.ok_or_cancelled() {
        APP.error(&format!("Could not log out:\n{}", detail(&out)));
    }
    refresh_now();
}

/// Nowe konto = nowy profil z domyślnymi ustawieniami, BEZ operatora. Zwykły użytkownik traciłby
/// w nim uprawnienia w połowie logowania (tak się stało 2026-09-28), więc logowanie idzie przez
/// pkexec z --operator, żeby nowy profil od razu był sterowalny z traya.
fn login() {
    let operator = format!("--operator={}", user_name());
    let url = Regex::new(r"https://login\S+").unwrap();
    let mut opened = false;
    let (code, lines) = crate::common::cmd::stream_lines(
        &["pkexec", "tailscale", "login", &operator, "--timeout=10m"],
        |line| {
            if let (false, Some(m)) = (opened, url.find(line)) {
                opened = true; // przeglądarka tylko raz na logowanie
                open_url(m.as_str());
            }
        },
    );
    if code != 0 && code != 126 {
        let tail = lines[lines.len().saturating_sub(10)..].join("\n");
        APP.error(&format!("Tailscale login failed:\n{}", tail.trim()));
    }
    update(|t| t.ts().login_running = false);
    refresh_now();
}

struct Gathered {
    status: Option<Value>,
    prefs: Option<Value>,
    error: String,
    profiles: Vec<Value>,
    current: String,
}

/// Jedno odpytanie tailscaled.
fn gather() -> Gathered {
    let (status, prefs, error) = match (api("GET", "status", None), api("GET", "prefs", None)) {
        (Ok(st), Ok(p)) => (Some(st), Some(p), String::new()),
        (Err(e), _) | (_, Err(e)) => (None, None, e),
    };
    // Osobno: bez operatora w bieżącym profilu tailscaled może odmówić listy kont,
    // a reszta menu (i przełączenie z powrotem) ma nadal działać.
    let (profiles, current) = match (api("GET", "profiles/", None), api("GET", "profiles/current", None)) {
        (Ok(list), Ok(cur)) => (list.as_array().cloned().unwrap_or_default(), s(&cur, "ID").to_string()),
        _ => (Vec::new(), String::new()),
    };
    Gathered { status, prefs, error, profiles, current }
}

fn apply_gathered(t: &mut Tailscale, g: Gathered) {
    (t.status, t.prefs, t.error, t.profiles, t.current_profile) = (g.status, g.prefs, g.error, g.profiles, g.current);
}

pub fn start() {
    let _ = POLLER.set(Poller::start(POLL, || {
        let g = gather();
        update(move |t| {
            if let Some(ts) = t.ts.as_mut() {
                apply_gathered(ts, g);
            }
        });
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels() {
        let p = json!({"ID": "a1", "Name": "x@y", "UserProfile": {"DisplayName": "Jan", "LoginName": "jan@x.pl"},
                       "NetworkProfile": {"DomainName": "tail123.ts.net"}});
        assert_eq!(profile_label(&p), "Jan (jan@x.pl)  [tail123.ts.net]");
        assert_eq!(profile_short(&p), "jan@x.pl");
        assert_eq!(profile_label(&json!({"ID": "a1"})), "a1");
        let n = json!({"DNSName": "x16.tail123.ts.net.", "TailscaleIPs": ["fd7a::1", "100.64.0.1"]});
        assert_eq!(node_name(&n), "x16");
        assert_eq!(first_ip(&n), "100.64.0.1");
        assert_eq!(first_ip(&json!({})), "-");
        assert_eq!(node_name(&json!({"HostName": "box"})), "box");
    }
}
