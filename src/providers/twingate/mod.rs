//! Twingate (dawny twingate-tray): status, konto (przełączanie, dodawanie, wylogowanie), zasoby
//! (kopiowanie adresu, uwierzytelnianie), exit networks, ustawienia.
//!
//! Stan czyta z IPC demona twingated (/run/twingate/auth.sock, SOCK_SEQPACKET, JSON) - tak samo robi CLI.
//! Połącz/rozłącz = start/stop twingate.service, bo tak robi `twingate connect/disconnect`; reguła polkit
//! z install.sh pozwala na to bez hasła użytkownikom z grupy wheel (odpowiednik operatora Tailscale).
//! Konta, exit nody i uwierzytelnianie zasobów idą przez CLI `twingate`.

mod ipc;

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use regex::Regex;
use serde_json::{json, Value};
use crate::common::json::{arr, b, get, n, s, truthy};
use crate::common::menu::{button, check, radio, sep, submenu, text, Menu};
use crate::common::{bg, icon_path, open_url, run, run_input, Out, Poller};
use crate::providers::{Choice, Job, Kind, Level, Summary};
use crate::{update, Tray, APP};

use ipc::ipc;

const PROFILES: &str = "/var/lib/twingate/profiles";
const SERVICE: &str = "twingate";
const NOTIFIER: &str = "twingate-desktop-notifier"; // otwiera przeglądarkę, gdy demon prosi o logowanie
const POLL: Duration = Duration::from_secs(3);
const RESOURCES_EVERY: Duration = Duration::from_secs(30); // każde zapytanie o zasoby to 2 linie w journalu twingated

static POLLER: OnceLock<Poller> = OnceLock::new();
/// Następne odpytanie ma pobrać też zasoby (po akcji).
static FULL: AtomicBool = AtomicBool::new(false);

pub fn refresh_now() {
    FULL.store(true, Ordering::SeqCst);
    if let Some(p) = POLLER.get() {
        p.poke();
    }
}

fn now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

/// stderr + stdout bez kolorów ANSI.
fn output(out: &Out) -> String {
    let ansi = Regex::new(r"\x1b\[[0-9;]*m").unwrap();
    ansi.replace_all(&format!("{}{}", out.stderr, out.stdout), "").trim().to_string()
}

fn report(out: &Out, what: &str) {
    if !out.ok_or_cancelled() {
        APP.error(&format!("{what}:\n{}", output(out)));
    }
}

/// "Start with the system" = twingate.service włączony w systemd (tak robi `twingate config autostart`).
fn service_enabled() -> bool {
    crate::common::unit_enabled(SERVICE)
}

/// Konta z /var/lib/twingate/profiles (czytelne dla wszystkich, tak samo czyta je `twingate account list`).
fn load_accounts() -> (Vec<Value>, String) {
    let mut accounts = Vec::new();
    let Ok(dir) = std::fs::read_dir(PROFILES) else { return (accounts, String::new()) };
    for entry in dir.flatten() {
        let Ok(raw) = std::fs::read(entry.path().join("info.json")) else { continue };
        let Ok(mut info) = serde_json::from_slice::<Value>(&raw) else { continue };
        if let Some(obj) = info.as_object_mut() {
            obj.entry("uuid").or_insert_with(|| json!(entry.file_name().to_string_lossy()));
            accounts.push(info);
        }
    }
    let current = std::fs::read_to_string(Path::new(PROFILES).join("default")).unwrap_or_default();
    (accounts, current.trim().to_string())
}

fn account_label(acc: &Value) -> String {
    let (name, email) = (s(acc, "name"), s(acc, "email"));
    let label = if !name.is_empty() && !email.is_empty() && name != email {
        format!("{name} ({email})")
    } else {
        [name, email, s(acc, "uuid"), "?"].into_iter().find(|t| !t.is_empty()).unwrap().to_string()
    };
    match account_network(acc) {
        Some(net) => format!("{label}  [{net}]"),
        None => label,
    }
}

fn account_network(acc: &Value) -> Option<&str> {
    [s(acc, "network_display_name"), s(acc, "network_slug")].into_iter().find(|t| !t.is_empty())
}

/// `twingate account switch/logout` przyjmuje email, email:network_slug albo 4-znakowe ID.
fn account_id(acc: &Value) -> String {
    let (email, slug) = (s(acc, "email"), s(acc, "network_slug"));
    if !email.is_empty() && !slug.is_empty() {
        format!("{email}:{slug}")
    } else {
        email.into()
    }
}

fn user_label(user: &Value) -> String {
    let name = [s(user, "first_name"), s(user, "last_name")].into_iter().filter(|t| !t.is_empty()).collect::<Vec<_>>();
    let (name, email) = (name.join(" "), s(user, "email"));
    if !name.is_empty() && !email.is_empty() {
        format!("{name} ({email})")
    } else if !name.is_empty() {
        name
    } else {
        email.into()
    }
}

fn resource_address(r: &Value) -> String {
    let addr = s(r, "address");
    addr.strip_suffix("/32").unwrap_or(addr).into()
}

fn resource_alias(r: &Value) -> String {
    let aliases = arr(r, "aliases");
    let alias = aliases.first().unwrap_or_else(|| get(r, "alias"));
    let alias = match alias {
        Value::Object(_) => [s(alias, "address"), s(alias, "name")].into_iter().find(|t| !t.is_empty()).unwrap_or(""),
        Value::String(t) => t,
        _ => "",
    };
    if alias == "-" { String::new() } else { alias.into() }
}

fn expires_text(ts: f64) -> String {
    let left = ts - now();
    if left <= 0.0 {
        "expired".into()
    } else if left < 3600.0 {
        format!("in {} min", ((left / 60.0) as i64).max(1))
    } else if left < 86400.0 {
        format!("in {} h", (left / 3600.0) as i64)
    } else {
        format!("in {} days", (left / 86400.0) as i64)
    }
}

fn needs_auth(r: &Value) -> bool {
    let exp = n(r, "auth_expires_at");
    let state = s(r, "auth_state");
    !matches!(state, "" | "none" | "authenticated") || (0.0 < exp && exp < now())
}

/// Domyślnie widoczny w głównej liście, gdy pola nie ma (`r.get("client_visibility", 1)`).
fn visible(r: &Value) -> bool {
    r.get("client_visibility").map(truthy).unwrap_or(true)
}

fn hhmm(ts: f64) -> String {
    use chrono::{Local, TimeZone};
    Local.timestamp_opt(ts as i64, 0).single().map(|t| t.format("%H:%M").to_string()).unwrap_or_default()
}

/// Bieżąca exit network z odpowiedzi "resources" (id, name, expires_at).
fn exit_network(data: Option<&Value>) -> Option<Value> {
    let d = data?;
    let ft = get(d, "full_tunnel");
    let net_id = ft.get("remote_network_id").filter(|v| truthy(v))?;
    let expires = get(ft, "expires_at").clone();
    for net in arr(d, "remote_networks") {
        if get(net, "id") == net_id {
            let mut net = net.clone();
            net["expires_at"] = expires;
            return Some(net);
        }
    }
    let name = net_id.as_str().map(String::from).unwrap_or_else(|| net_id.to_string());
    Some(json!({"id": net_id, "name": name, "expires_at": expires}))
}

struct Icons {
    on: String,
    off: String,
    exit: String,
    auth: String,
}

pub struct Twingate {
    status: Value,
    /// Odpowiedź na "resources": zasoby, użytkownik, exit networks.
    data: Option<Value>,
    error: String,
    accounts: Vec<Value>,
    current_account: String,
    autostart: bool,
    /// Opis trwającej akcji w tle (przełączanie konta, exit network…).
    busy: String,
    icons: Icons,
    polled: Polled,
}

impl Twingate {
    pub fn detect() -> Option<Twingate> {
        if !crate::common::cmd::which("twingate") {
            return None;
        }
        // CLI twingate sam woła sudo przy niektórych poleceniach; bez terminala potrzebuje askpass.
        if std::env::var_os("SUDO_ASKPASS").is_none() {
            let home = std::env::var("HOME").unwrap_or_default();
            for helper in [format!("{home}/.local/bin/sudo-askpass"), "/usr/bin/ksshaskpass".into()] {
                let executable = std::fs::metadata(&helper).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0);
                if executable {
                    std::env::set_var("SUDO_ASKPASS", helper);
                    break;
                }
            }
        }
        let icon = |name: &str| icon_path(APP.id, name);
        let (accounts, current_account) = load_accounts();
        Some(Twingate {
            status: json!({}),
            data: None,
            error: String::new(),
            accounts,
            current_account,
            autostart: service_enabled(),
            busy: String::new(),
            icons: Icons {
                on: icon("twingate-tray-on"),
                off: icon("twingate-tray-disconnected"),
                exit: icon("twingate-tray-exit"),
                auth: icon("twingate-tray-auth"),
            },
            polled: Polled::default(),
        })
    }

    pub fn gather_now(&mut self) {
        let mut p = std::mem::take(&mut self.polled);
        gather(&mut p, true);
        (self.status, self.data, self.error) = (p.status.clone(), p.data.clone(), p.error.clone());
        self.polled = p;
    }

    fn state(&self) -> String {
        if self.error.is_empty() { s(&self.status, "msg").into() } else { "Not running".into() }
    }

    fn connected(&self) -> bool {
        self.state() == "Online"
    }

    /// Włączony = usługa działa (demon odpowiada), także w trakcie łączenia i logowania.
    pub fn active(&self) -> bool {
        self.error.is_empty() && !self.status.as_object().is_none_or(|o| o.is_empty())
    }

    /// Interfejs klienta Twingate na Linuksie.
    pub fn interfaces(&self) -> Vec<String> {
        vec!["sdwan0".into()]
    }

    fn data(&self) -> &Value {
        static NULL: Value = Value::Null;
        self.data.as_ref().unwrap_or(&NULL)
    }

    fn is_admin(&self) -> bool {
        b(get(self.data(), "user"), "is_admin")
    }

    pub fn summary(&self) -> Summary {
        let state = self.state();
        let (level, text, icon) = match state.as_str() {
            "Online" if exit_network(self.data.as_ref()).is_some() => (Level::On, "connected (exit network)".into(), &self.icons.exit),
            "Online" => (Level::On, "connected".into(), &self.icons.on),
            "Not running" => (Level::Off, "disconnected".into(), &self.icons.off),
            "Authenticating" => (Level::Attention, "sign-in required".into(), &self.icons.auth),
            "Connecting" | "" => (Level::Connecting, "connecting…".into(), &self.icons.on),
            other => (Level::Attention, other.to_lowercase(), &self.icons.off),
        };
        Summary { level, text, icon: icon.clone() }
    }

    /// Jedna pozycja na konto (sieć Twingate); przy jednym koncie sama nazwa "Twingate".
    pub fn choices(&self) -> Vec<Choice> {
        let active = self.active();
        if self.accounts.len() <= 1 {
            return vec![Choice { kind: Kind::Twingate, id: String::new(), detail: String::new(), active }];
        }
        let mut accounts: Vec<&Value> = self.accounts.iter().collect();
        accounts.sort_by_key(|a| account_label(a).to_lowercase());
        accounts
            .into_iter()
            .map(|a| Choice {
                kind: Kind::Twingate,
                id: s(a, "uuid").into(),
                detail: account_network(a).map(String::from).unwrap_or_else(|| account_label(a)),
                active: active && s(a, "uuid") == self.current_account,
            })
            .collect()
    }

    /// Połączenie: przełączenie konta (jeśli trzeba) i start usługi z notifierem (otwiera logowanie).
    pub fn connect_job(&self, id: &str) -> Job {
        let switch = (!id.is_empty() && id != self.current_account)
            .then(|| self.accounts.iter().find(|a| s(a, "uuid") == id).map(account_id))
            .flatten();
        let uuid = id.to_string();
        Box::new(move || {
            if let Some(acc) = switch {
                let out = run(&["twingate", "account", "switch", &acc], 120);
                if load_accounts().1 != uuid {
                    let why = output(&out);
                    return Err(if why.is_empty() { "twingate refused the account switch".into() } else { why });
                }
            }
            let out = run(&["systemctl", "start", SERVICE], 120);
            run(&["systemctl", "--user", "start", NOTIFIER], 30);
            if out.ok_or_cancelled() { Ok(()) } else { Err(output(&out)) }
        })
    }

    pub fn disconnect_job(&self) -> Job {
        Box::new(|| {
            let out = run(&["systemctl", "stop", SERVICE], 120);
            if out.ok_or_cancelled() { Ok(()) } else { Err(output(&out)) }
        })
    }

    /// Długie polecenie (systemctl, CLI twingate) w wątku, żeby menu nie zamarzało;
    /// w tym czasie status w menu pokazuje, co się dzieje.
    fn in_background(&mut self, busy: &str, work: impl FnOnce() -> Out + Send + 'static, done: impl FnOnce(Out) + Send + 'static) {
        if !self.busy.is_empty() {
            return;
        }
        self.busy = busy.into();
        bg(move || {
            let out = work();
            update(|t| t.tg().busy.clear());
            done(out);
            refresh_now();
        });
    }

    // ---------- menu ----------

    fn status_item(&self) -> ksni::MenuItem<Tray> {
        if !self.busy.is_empty() {
            return text(&self.busy);
        }
        match self.state().as_str() {
            "Online" => check("Connected", true, true, |t: &mut Tray, _| t.disconnect_all()),
            "Not running" => {
                let current = self.current_account.clone();
                check("Disconnected - click to connect", false, true, move |t: &mut Tray, _| {
                    t.switch_to(Kind::Twingate, current.clone())
                })
            }
            "Authenticating" => button("Sign-in required - click to sign in…", true, |t: &mut Tray| t.tg().reconnect()),
            "Connecting" => text("Connecting…"),
            other => button(
                &format!("{} - click to reconnect", if other.is_empty() { "Offline" } else { other }),
                true,
                |t: &mut Tray| t.tg().reconnect(),
            ),
        }
    }

    fn accounts_menu(&self) -> ksni::MenuItem<Tray> {
        let d = self.data();
        let current = self.accounts.iter().find(|a| s(a, "uuid") == self.current_account).cloned();
        let label = [user_label(get(d, "user")), current.as_ref().map(account_label).unwrap_or_default()]
            .into_iter()
            .find(|t| !t.is_empty())
            .unwrap_or_else(|| "Not signed in".into());
        let mut accounts: Vec<Value> = self.accounts.clone();
        accounts.sort_by_key(|a| account_label(a).to_lowercase());
        let mut sub: Menu<Tray> = Vec::new();
        if !accounts.is_empty() {
            let selected = accounts.iter().position(|a| s(a, "uuid") == self.current_account).unwrap_or(usize::MAX);
            let options = accounts.iter().map(|a| (account_label(a), true)).collect();
            sub.push(radio(options, selected, move |t: &mut Tray, i| t.tg().switch_account(accounts[i].clone())));
            sub.push(sep());
        }
        sub.push(button("Add another account…", true, |_| APP.in_terminal(&["twingate", "account", "add"])));
        let admin_url = s(d, "admin_url").to_string();
        sub.push(button("Admin console", !admin_url.is_empty() && self.is_admin(), move |_| open_url(&admin_url)));
        sub.push(sep());
        let has_current = current.is_some();
        sub.push(button("Log out", has_current, move |_| {
            if let Some(acc) = current.clone() {
                bg(move || logout(acc));
            }
        }));
        submenu(&label, true, sub)
    }

    fn resource_item(&self, r: &Value) -> ksni::MenuItem<Tray> {
        let (addr, alias) = (resource_address(r), resource_alias(r));
        let star = if b(r, "is_favorite") { "★ " } else { "" };
        let lock = if needs_auth(r) { "  (sign-in needed)" } else { "" };
        let name = s(r, "name").to_string();
        let shown = if alias.is_empty() { &addr } else { &alias };
        let label = format!("{star}{}  {shown}{lock}", if name.is_empty() { "?" } else { &name });
        let mut sub: Menu<Tray> = Vec::new();
        if !alias.is_empty() {
            let a = alias.clone();
            sub.push(button(&format!("Copy alias  {alias}"), true, move |_| copy(&a)));
        }
        let a = addr.clone();
        sub.push(button(&format!("Copy address  {addr}"), true, move |_| copy(&a)));
        let open = s(r, "open_url").to_string();
        if !open.is_empty() {
            sub.push(button("Open in browser", true, move |_| open_url(&open)));
        }
        sub.push(sep());
        let auth_label = if needs_auth(r) { "Authenticate…" } else { "Re-authenticate…" };
        sub.push(button(auth_label, true, move |_| {
            let name = name.clone();
            bg(move || authenticate(&name));
        }));
        let exp = n(r, "auth_expires_at");
        if exp != 0.0 {
            let t = if exp < now() { "Auth expired".into() } else { format!("Auth expires {}", expires_text(exp)) };
            sub.push(text(&t));
        }
        let admin = s(r, "admin_url").to_string();
        if !admin.is_empty() && self.is_admin() {
            sub.push(button("Open in admin console", true, move |_| open_url(&admin)));
        }
        submenu(&label, true, sub)
    }

    fn resources_menu(&self) -> ksni::MenuItem<Tray> {
        let all = arr(self.data(), "resources");
        let mut main: Vec<&Value> = all.iter().filter(|r| visible(r)).collect();
        let mut hidden: Vec<&Value> = all.iter().filter(|r| !visible(r)).collect();
        main.sort_by_key(|r| (!b(r, "is_favorite"), s(r, "name").to_lowercase()));
        hidden.sort_by_key(|r| s(r, "name").to_lowercase());
        let mut sub: Menu<Tray> = Vec::new();
        if main.is_empty() {
            sub.push(text(if self.connected() { "No resources" } else { "Connect to see resources" }));
        }
        sub.extend(main.iter().map(|r| self.resource_item(r)));
        if !hidden.is_empty() {
            sub.push(sep());
            let more = hidden.iter().map(|r| self.resource_item(r)).collect();
            sub.push(submenu(&format!("Background resources ({})", hidden.len()), true, more));
        }
        submenu(&format!("Resources ({})", main.len()), self.data.is_some(), sub)
    }

    fn exit_networks_menu(&self) -> ksni::MenuItem<Tray> {
        let mut nets: Vec<&Value> = arr(self.data(), "remote_networks").iter().collect();
        nets.sort_by_key(|n| s(n, "name").to_lowercase());
        let current = exit_network(self.data.as_ref());
        let label = match &current {
            Some(c) => {
                let exp = n(c, "expires_at");
                let until = if exp != 0.0 { format!(" (until {})", hhmm(exp)) } else { String::new() };
                format!("Exit network: {}{until}", s(c, "name"))
            }
            None => "Exit networks".into(),
        };
        let mut options = vec![("None (only Resources go through Twingate)".to_string(), true)];
        let mut names = vec![String::new()];
        let mut selected = if current.is_none() { 0 } else { usize::MAX };
        for net in &nets {
            if current.as_ref().is_some_and(|c| get(net, "id") == get(c, "id")) {
                selected = names.len();
            }
            let name = s(net, "name");
            options.push((if name.is_empty() { "?".into() } else { name.into() }, true));
            names.push(name.into());
        }
        let mut sub: Menu<Tray> = vec![radio(options, selected, move |t: &mut Tray, i| t.tg().set_exit_network(names[i].clone()))];
        if nets.is_empty() {
            sub.push(text("No exit networks in this network"));
        }
        submenu(&label, self.connected() && self.busy.is_empty(), sub)
    }

    fn settings_menu(&self) -> ksni::MenuItem<Tray> {
        let sub = vec![
            check("Start with the system", self.autostart, true, |_, v| bg(move || set_autostart(v))),
            sep(),
            button("Restart Twingate service", self.busy.is_empty() && self.active(), |t: &mut Tray| t.tg().reconnect()),
            button("Service log", true, |_| APP.in_terminal(&["journalctl", "-u", SERVICE, "-n", "200", "-f"])),
        ];
        submenu("Settings", true, sub)
    }

    pub fn menu(&self) -> Menu<Tray> {
        let mut m = vec![self.status_item(), sep(), self.accounts_menu(), sep()];
        let network = s(self.data(), "network_name");
        if !network.is_empty() {
            m.push(text(&format!("Network: {network}")));
        }
        m.extend([self.resources_menu(), sep(), self.exit_networks_menu(), sep(), self.settings_menu()]);
        m
    }

    // ---------- akcje ----------

    fn reconnect(&mut self) {
        let work = || {
            run(&["systemctl", "--user", "start", NOTIFIER], 30);
            run(&["systemctl", "restart", SERVICE], 120)
        };
        self.in_background("Reconnecting…", work, |out| report(&out, "Could not restart Twingate"));
    }

    fn set_exit_network(&mut self, name: String) {
        let has_current = exit_network(self.data.as_ref()).is_some();
        let cmd: Vec<String> = if name.is_empty() {
            vec!["twingate".into(), "exit-node".into(), "stop".into()]
        } else {
            let verb = if has_current { "switch" } else { "start" };
            vec!["twingate".into(), "exit-node".into(), verb.into(), name.clone()]
        };
        let work = move || run(&cmd.iter().map(String::as_str).collect::<Vec<_>>(), 60);
        let done = move |out: Out| {
            // O powodzeniu decyduje stan demona, nie kod wyjścia CLI.
            let data = ipc(Some(&json!({"cmd": "resources"})), Duration::from_secs(3)).ok().and_then(|(_, d)| d);
            let now = exit_network(data.as_ref()).map(|n| s(&n, "name").to_string()).unwrap_or_default();
            if now != name && !out.ok() {
                APP.error(&format!("Could not change the exit network:\n{}", output(&out)));
            }
        };
        self.in_background("Changing exit network…", work, done);
    }

    fn switch_account(&mut self, acc: Value) {
        let id = account_id(&acc);
        let uuid = s(&acc, "uuid").to_string();
        let work = move || run(&["twingate", "account", "switch", &id], 120);
        let done = move |out: Out| {
            if load_accounts().1 != uuid {
                let why = output(&out);
                APP.error(&format!(
                    "Could not switch Twingate account:\n{}",
                    if why.is_empty() { "twingate refused the switch" } else { &why }
                ));
            }
        };
        self.in_background("Switching account…", work, done);
    }
}

// ---------- akcje w tle ----------

fn copy(text: &str) {
    let text = text.to_string();
    bg(move || APP.copy_to_clipboard(&text));
}

/// CLI wysyła "auth" do demona, a przeglądarkę z logowaniem otwiera twingate-notifier.
fn authenticate(resource: &str) {
    run(&["systemctl", "--user", "start", NOTIFIER], 30);
    let out = run(&["twingate", "auth", resource], 300);
    if !out.ok() {
        APP.error(&format!("Could not authenticate {resource}:\n{}", output(&out)));
    }
}

/// To samo co `twingate config autostart`: usługa systemowa + globalnie włączony notifier.
fn set_autostart(enabled: bool) {
    let verb = if enabled { "enable" } else { "disable" };
    let script = format!("systemctl {verb} {SERVICE} && systemctl --global {verb} {NOTIFIER}");
    let out = run(&["pkexec", "sh", "-c", &script], 120);
    report(&out, &format!("systemctl {verb} {SERVICE} failed"));
    let now = service_enabled();
    update(|t| t.tg().autostart = now);
    refresh_now();
}

fn logout(acc: Value) {
    let question = format!("Log out {}?\n\nTwingate Resources will be unavailable until you sign in again.", account_label(&acc));
    if !APP.yesno(&question) {
        return;
    }
    let id = account_id(&acc);
    // CLI pyta "Are you sure? [y/N]" na stdin.
    let work = move || run_input(&["twingate", "account", "logout", &id], 120, "y\n");
    update(|t| t.tg().in_background("Logging out…", work, |out| report(&out, "Could not log out")));
}

/// Stan pollera między odpytaniami: zasoby pobierane rzadziej niż status.
#[derive(Default)]
struct Polled {
    status: Value,
    data: Option<Value>,
    data_time: Option<Instant>,
    error: String,
}

fn gather(p: &mut Polled, full: bool) {
    let old_msg = s(&p.status, "msg").to_string();
    match ipc(None, Duration::from_secs(5)) {
        Ok((status, _)) => {
            p.status = status;
            p.error.clear();
        }
        Err(e) => {
            p.status = json!({});
            p.data = None;
            p.error = e;
        }
    }
    // Zasoby osobno i rzadziej: status jest tani i nie loguje, a brak odpowiedzi na "resources"
    // (np. w trakcie logowania) nie może udawać, że usługa nie działa.
    let stale = p.data_time.is_none_or(|t| t.elapsed() > RESOURCES_EVERY);
    if p.error.is_empty() && (full || stale || s(&p.status, "msg") != old_msg) {
        p.data_time = Some(Instant::now());
        p.data = ipc(Some(&json!({"cmd": "resources"})), Duration::from_secs(3)).ok().and_then(|(_, d)| d);
    }
}

pub fn start() {
    let mut polled = Polled::default();
    let _ = POLLER.set(Poller::start(POLL, move || {
        gather(&mut polled, FULL.swap(false, Ordering::SeqCst));
        let (status, data, error) = (polled.status.clone(), polled.data.clone(), polled.error.clone());
        let (accounts, current) = load_accounts();
        update(move |t| {
            if let Some(tg) = t.tg.as_mut() {
                (tg.status, tg.data, tg.error) = (status, data, error);
                (tg.accounts, tg.current_account) = (accounts, current);
            }
        });
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_texts() {
        let r = json!({"name": "NAS", "address": "10.20.0.2/32", "aliases": [{"address": "nas.lan"}]});
        assert_eq!(resource_address(&r), "10.20.0.2");
        assert_eq!(resource_alias(&r), "nas.lan");
        assert_eq!(resource_alias(&json!({"alias": "-"})), "");
        assert!(!needs_auth(&json!({"auth_state": "authenticated"})));
        assert!(needs_auth(&json!({"auth_state": "required"})));
        assert!(needs_auth(&json!({"auth_expires_at": 1})));
        assert!(visible(&json!({})));
        assert!(!visible(&json!({"client_visibility": 0})));
    }

    #[test]
    fn account_texts() {
        let a = json!({"name": "Jan", "email": "j@x.pl", "network_slug": "firma", "uuid": "u1"});
        assert_eq!(account_label(&a), "Jan (j@x.pl)  [firma]");
        assert_eq!(account_id(&a), "j@x.pl:firma");
        assert_eq!(user_label(&json!({"first_name": "Jan", "last_name": "K", "email": "j@x.pl"})), "Jan K (j@x.pl)");
    }

    #[test]
    fn exit_network_lookup() {
        let d = json!({"full_tunnel": {"remote_network_id": "n1", "expires_at": 5},
                       "remote_networks": [{"id": "n1", "name": "Home"}]});
        let net = exit_network(Some(&d)).unwrap();
        assert_eq!(s(&net, "name"), "Home");
        assert_eq!(n(&net, "expires_at"), 5.0);
        assert!(exit_network(Some(&json!({"full_tunnel": null}))).is_none());
        assert_eq!(expires_text(now() + 7300.0), "in 2 h");
    }
}
