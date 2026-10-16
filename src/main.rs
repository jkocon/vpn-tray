//! Jedna ikona w zasobniku dla wszystkich VPN-ów: Tailscale, Twingate, NetBird i WireGuard
//! (połączenia NetworkManagera). Na raz działa tylko jeden VPN - wybór sieci z listy rozłącza
//! pozostałe i łączy wybraną.
//!
//! Menu (lewy lub prawy klik): nagłówek z aktywnym VPN-em, lista wyboru (None + każde konto, profil
//! i połączenie WireGuard), podmenu każdego VPN-a z dawnego osobnego traya (urządzenia, sieci, exit
//! node, ustawienia…), About, Exit. VPN-a, którego nie ma w systemie, nie ma w menu.
//!
//! `--only <tailscale|twingate|netbird|wireguard>` = tylko ten jeden VPN (jak dawne osobne traye),
//! `--dump` = jedno odpytanie i menu jako tekst.

mod common;
mod nfs;
mod providers;

use std::sync::OnceLock;

use ksni::blocking::Handle;
use crate::common::menu::{button, radio, sep, submenu, text, Menu};
use crate::common::{bg, icon_path, App};

use providers::netbird::NetBird;
use providers::tailscale::Tailscale;
use providers::twingate::Twingate;
use providers::wireguard::WireGuard;
use providers::{Choice, Confirm, Job, Kind, Summary};

pub const APP: App = App { name: "VPN Tray", id: "vpn-tray" };

static HANDLE: OnceLock<Handle<Tray>> = OnceLock::new();

/// Zmiana stanu traya spoza wątku ksni (z pollera albo wątku akcji).
pub fn update(f: impl FnOnce(&mut Tray)) {
    if let Some(h) = HANDLE.get() {
        h.update(f);
    }
}

/// Odśwież wszystkie VPN-y (po przełączeniu).
pub fn refresh_all() {
    providers::tailscale::refresh_now();
    providers::twingate::refresh_now();
    providers::netbird::refresh_now();
    providers::wireguard::refresh_now();
}

/// Przełączenie gotowe do wykonania (w tle albo z `--switch`).
struct Switch {
    label: String,
    /// Interfejsy VPN-ów, które znikną (albo zmienią trasy) - udziały NFS za nimi są odmontowywane.
    ifaces: Vec<String>,
    confirm: Option<Confirm>,
    downs: Vec<(Kind, Job)>,
    up: Option<Job>,
}

impl Switch {
    /// Wykonanie (blokuje); Err = zebrane komunikaty, Ok także po anulowaniu pytania.
    fn run(self) -> Result<(), String> {
        if let Some(confirm) = self.confirm {
            if !confirm() {
                return Ok(());
            }
        }
        let mut errors = Vec::new();
        let mounts = nfs::behind(&self.ifaces);
        if !mounts.is_empty() {
            errors.extend(nfs::unmount(&mounts));
            let list = mounts.iter().map(|m| format!("{} ({})", m.target, m.server)).collect::<Vec<_>>().join("\n");
            APP.notify("Unmounted NFS shares behind the VPN", &list);
        }
        for (k, job) in self.downs {
            if let Err(e) = job() {
                errors.push(format!("Could not disconnect {}:\n{e}", k.name()));
            }
        }
        if let Some(up) = self.up {
            if let Err(e) = up() {
                errors.push(format!("Could not connect {}:\n{e}", self.label));
            }
        }
        if errors.is_empty() { Ok(()) } else { Err(errors.join("\n\n")) }
    }
}

pub struct Tray {
    pub ts: Option<Tailscale>,
    pub tg: Option<Twingate>,
    pub nb: Option<NetBird>,
    pub wg: Option<WireGuard>,
    /// Trwające przełączanie między VPN-ami.
    pub busy: String,
    off_icon: String,
}

impl Tray {
    // Akcje z podmenu dostawcy istnieją tylko wtedy, gdy ten dostawca jest w trayu.
    pub fn ts(&mut self) -> &mut Tailscale {
        self.ts.as_mut().expect("Tailscale provider")
    }

    pub fn tg(&mut self) -> &mut Twingate {
        self.tg.as_mut().expect("Twingate provider")
    }

    pub fn nb(&mut self) -> &mut NetBird {
        self.nb.as_mut().expect("NetBird provider")
    }

    pub fn wg(&mut self) -> &mut WireGuard {
        self.wg.as_mut().expect("WireGuard provider")
    }

    fn kinds(&self) -> Vec<Kind> {
        let present = [self.ts.is_some(), self.tg.is_some(), self.nb.is_some(), self.wg.is_some()];
        Kind::ALL.into_iter().zip(present).filter(|(_, p)| *p).map(|(k, _)| k).collect()
    }

    fn active(&self, kind: Kind) -> bool {
        match kind {
            Kind::Tailscale => self.ts.as_ref().is_some_and(Tailscale::active),
            Kind::Twingate => self.tg.as_ref().is_some_and(Twingate::active),
            Kind::NetBird => self.nb.as_ref().is_some_and(NetBird::active),
            Kind::WireGuard => self.wg.as_ref().is_some_and(WireGuard::active),
        }
    }

    /// Interfejsy sieciowe włączonych VPN-ów.
    fn active_interfaces(&self) -> Vec<String> {
        let mut all = Vec::new();
        all.extend(self.ts.iter().filter(|p| p.active()).flat_map(Tailscale::interfaces));
        all.extend(self.tg.iter().filter(|p| p.active()).flat_map(Twingate::interfaces));
        all.extend(self.nb.iter().filter(|p| p.active()).flat_map(NetBird::interfaces));
        all.extend(self.wg.iter().filter(|p| p.active()).flat_map(WireGuard::interfaces));
        all
    }

    fn summary(&self, kind: Kind) -> Option<Summary> {
        match kind {
            Kind::Tailscale => self.ts.as_ref().map(Tailscale::summary),
            Kind::Twingate => self.tg.as_ref().map(Twingate::summary),
            Kind::NetBird => self.nb.as_ref().map(NetBird::summary),
            Kind::WireGuard => self.wg.as_ref().map(WireGuard::summary),
        }
    }

    fn choices(&self) -> Vec<Choice> {
        let mut all = Vec::new();
        all.extend(self.ts.iter().flat_map(Tailscale::choices));
        all.extend(self.tg.iter().flat_map(Twingate::choices));
        all.extend(self.nb.iter().flat_map(NetBird::choices));
        all.extend(self.wg.iter().flat_map(WireGuard::choices));
        all
    }

    fn provider_menu(&self, kind: Kind) -> Menu<Self> {
        match kind {
            Kind::Tailscale => self.ts.as_ref().map(Tailscale::menu),
            Kind::Twingate => self.tg.as_ref().map(Twingate::menu),
            Kind::NetBird => self.nb.as_ref().map(NetBird::menu),
            Kind::WireGuard => self.wg.as_ref().map(WireGuard::menu),
        }
        .unwrap_or_default()
    }

    fn connect_job(&self, kind: Kind, id: &str) -> Option<Job> {
        match kind {
            Kind::Tailscale => self.ts.as_ref().map(|p| p.connect_job(id)),
            Kind::Twingate => self.tg.as_ref().map(|p| p.connect_job(id)),
            Kind::NetBird => self.nb.as_ref().map(|p| p.connect_job(id)),
            Kind::WireGuard => self.wg.as_ref().map(|p| p.connect_job(id)),
        }
    }

    fn disconnect_job(&self, kind: Kind) -> Option<Job> {
        match kind {
            Kind::Tailscale => self.ts.as_ref().map(Tailscale::disconnect_job),
            Kind::Twingate => self.tg.as_ref().map(Twingate::disconnect_job),
            Kind::NetBird => self.nb.as_ref().map(NetBird::disconnect_job),
            Kind::WireGuard => self.wg.as_ref().map(WireGuard::disconnect_job),
        }
    }

    fn confirm(&self, kind: Kind, id: &str) -> Option<Confirm> {
        match kind {
            Kind::WireGuard => self.wg.as_ref().and_then(|p| p.confirm(id)),
            _ => None,
        }
    }

    /// Plan przełączenia na jedną sieć: pytanie (opcjonalne), rozłączenie pozostałych VPN-ów,
    /// połączenie wybranego (dostawca sam zmienia konto/profil i rozłącza swoje inne sieci).
    fn plan(&self, kind: Kind, id: &str) -> Option<Switch> {
        let label = self.choices().into_iter().find(|c| c.kind == kind && c.id == id).map(|c| c.label()).unwrap_or(kind.name().into());
        let up = self.connect_job(kind, id)?;
        let downs = self
            .kinds()
            .into_iter()
            .filter(|k| *k != kind && self.active(*k))
            .filter_map(|k| self.disconnect_job(k).map(|j| (k, j)))
            .collect();
        // Wszystkie aktywne VPN-y: także ten sam dostawca z innym profilem/kontem zmienia trasy.
        let ifaces = self.active_interfaces();
        Some(Switch { label, ifaces, confirm: self.confirm(kind, id), downs, up: Some(up) })
    }

    /// Plan "None": rozłączenie wszystkiego, co działa.
    fn plan_off(&self) -> Switch {
        let downs =
            self.kinds().into_iter().filter(|k| self.active(*k)).filter_map(|k| self.disconnect_job(k).map(|j| (k, j))).collect();
        Switch { label: "None".into(), ifaces: self.active_interfaces(), confirm: None, downs, up: None }
    }

    fn run_in_background(&mut self, plan: Switch, busy: String) {
        if !self.busy.is_empty() {
            return;
        }
        self.busy = busy;
        bg(move || {
            let result = plan.run();
            update(|t| t.busy.clear());
            refresh_all();
            if let Err(e) = result {
                APP.error(&e);
            }
        });
    }

    pub fn switch_to(&mut self, kind: Kind, id: String) {
        if !self.busy.is_empty() {
            return;
        }
        if self.choices().iter().any(|c| c.kind == kind && c.id == id && c.active) {
            return; // już połączone
        }
        if let Some(plan) = self.plan(kind, &id) {
            let busy = format!("Switching to {}…", plan.label);
            self.run_in_background(plan, busy);
        }
    }

    pub fn disconnect_all(&mut self) {
        let plan = self.plan_off();
        if !plan.downs.is_empty() {
            self.run_in_background(plan, "Disconnecting…".into());
        }
    }

    /// Ikona i podpowiedź: stan aktywnego VPN-a (jego własna ikona), a gdy nic nie działa - szara tarcza.
    fn icon(&self) -> (String, String) {
        let active: Vec<(Kind, Summary)> =
            self.kinds().into_iter().filter(|k| self.active(*k)).filter_map(|k| self.summary(k).map(|s| (k, s))).collect();
        match active.iter().max_by_key(|(_, s)| s.level) {
            Some((kind, s)) => {
                let mut tip = format!("{}: {}", kind.name(), s.text);
                if active.len() > 1 {
                    tip.push_str(&format!(" (+{} more VPN on)", active.len() - 1));
                }
                (s.icon.clone(), tip)
            }
            None if !self.busy.is_empty() => (self.off_icon.clone(), self.busy.clone()),
            None => (self.off_icon.clone(), "VPN: off".into()),
        }
    }

    fn about(&mut self) {
        let lines: Vec<String> = self
            .kinds()
            .into_iter()
            .filter_map(|k| self.summary(k).map(|s| format!("{}: {}", k.name(), s.text)))
            .collect();
        bg(move || {
            APP.about(&format!(
                "{} {}\nOne tray icon for Tailscale, Twingate, NetBird and WireGuard -\nonly one VPN is on at a time.\n\n{}",
                APP.name,
                env!("CARGO_PKG_VERSION"),
                if lines.is_empty() { "No VPN found".into() } else { lines.join("\n") },
            ));
        });
    }
}

impl ksni::Tray for Tray {
    const MENU_ON_ACTIVATE: bool = true;

    fn id(&self) -> String {
        APP.id.into()
    }

    fn title(&self) -> String {
        "VPN".into()
    }

    fn category(&self) -> ksni::Category {
        ksni::Category::SystemServices
    }

    fn icon_name(&self) -> String {
        self.icon().0
    }

    fn tool_tip(&self) -> ksni::ToolTip {
        ksni::ToolTip { title: self.icon().1, ..Default::default() }
    }

    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        let choices = self.choices();
        let active: Vec<&Choice> = choices.iter().filter(|c| c.active).collect();
        let header = if active.is_empty() {
            "VPN: off".to_string()
        } else {
            format!("VPN: {}", active.iter().map(|c| c.label()).collect::<Vec<_>>().join(", "))
        };
        let mut m: Menu<Self> = vec![text(&header), sep()];
        let idle = self.busy.is_empty();
        if !idle {
            m.push(text(&self.busy));
        }
        if active.len() > 1 {
            let (kind, id) = (active[0].kind, active[0].id.clone());
            m.push(text("⚠ More than one VPN is on"));
            m.push(button(&format!("Keep only {}", active[0].label()), idle, move |t: &mut Tray| t.switch_to(kind, id.clone())));
        }
        if self.kinds().is_empty() {
            m.push(text("No VPN found (Tailscale, Twingate, NetBird, NetworkManager)"));
        } else {
            let mut options = vec![("None (all off)".to_string(), idle)];
            options.extend(choices.iter().map(|c| (c.label(), idle)));
            let selected = choices.iter().position(|c| c.active).map(|i| i + 1).unwrap_or(0);
            let targets: Vec<(Kind, String)> = choices.iter().map(|c| (c.kind, c.id.clone())).collect();
            m.push(radio(options, selected, move |t: &mut Tray, i| {
                if i == 0 {
                    t.disconnect_all();
                } else if let Some((kind, id)) = targets.get(i - 1) {
                    t.switch_to(*kind, id.clone());
                }
            }));
        }
        m.push(sep());
        for kind in self.kinds() {
            let state = self.summary(kind).map(|s| s.text).unwrap_or_default();
            let mark = if self.active(kind) { "●" } else { "○" };
            m.push(submenu(&format!("{mark} {}  ({state})", kind.name()), true, self.provider_menu(kind)));
        }
        m.extend([sep(), button("About", true, Tray::about), sep(), button("Exit", true, |_| std::process::exit(0))]);
        m
    }
}

fn usage() -> ! {
    eprintln!(
        "usage: vpn-tray [--only tailscale|twingate|netbird|wireguard] [--dump] [--version]\n       \
         vpn-tray --switch none|<vpn>[:<network>]   (e.g. netbird:firma, wireguard:kurant)"
    );
    std::process::exit(2);
}

/// Wykrycie i jedno odpytanie dostawców (bez ikony): `--dump` i `--switch`.
fn gathered(only: Option<Kind>) -> Tray {
    let wanted = |k: Kind| only.is_none_or(|o| o == k);
    let mut tray = Tray {
        ts: if wanted(Kind::Tailscale) { Tailscale::detect() } else { None },
        tg: if wanted(Kind::Twingate) { Twingate::detect() } else { None },
        nb: if wanted(Kind::NetBird) { NetBird::detect() } else { None },
        wg: if wanted(Kind::WireGuard) { WireGuard::detect() } else { None },
        busy: String::new(),
        off_icon: icon_path(APP.id, "vpn-tray-off"),
    };
    tray.ts.iter_mut().for_each(Tailscale::gather_now);
    tray.tg.iter_mut().for_each(Twingate::gather_now);
    tray.nb.iter_mut().for_each(NetBird::gather_now);
    tray.wg.iter_mut().for_each(WireGuard::gather_now);
    tray
}

/// `--switch netbird:firma` - to samo co wybór z listy, do skrótów klawiszowych i skryptów.
/// Sieć = id albo początek opisu (nazwa profilu, konta, połączenia), bez rozróżniania wielkości liter.
fn switch_cli(target: &str, only: Option<Kind>) -> i32 {
    let tray = gathered(only);
    let plan = if target.eq_ignore_ascii_case("none") || target.eq_ignore_ascii_case("off") {
        tray.plan_off()
    } else {
        let (key, net) = target.split_once(':').unwrap_or((target, ""));
        let Some(kind) = Kind::from_key(key) else {
            eprintln!("vpn-tray: unknown VPN '{key}' (tailscale, twingate, netbird, wireguard)");
            return 2;
        };
        let net = net.to_lowercase();
        let choices: Vec<Choice> = tray.choices().into_iter().filter(|c| c.kind == kind).collect();
        let found = choices.iter().find(|c| net.is_empty() || c.id.to_lowercase() == net || c.detail.to_lowercase().starts_with(&net));
        let Some(choice) = found else {
            eprintln!("vpn-tray: no such network. Available:");
            for c in tray.choices() {
                eprintln!("  {}:{}  ({})", c.kind.key(), c.detail.split_whitespace().next().unwrap_or(""), c.label());
            }
            return 2;
        };
        match tray.plan(kind, &choice.id) {
            Some(plan) => plan,
            None => return 2,
        }
    };
    let label = plan.label.clone();
    match plan.run() {
        Ok(()) => {
            println!("vpn-tray: {label}");
            0
        }
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut dump = false;
    let mut only = None;
    let mut switch = None;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--version" => {
                println!("vpn-tray {}", env!("CARGO_PKG_VERSION"));
                return;
            }
            "--dump" => dump = true,
            "--switch" => switch = Some(it.next().cloned().unwrap_or_else(|| usage())),
            "--only" => only = Some(it.next().and_then(|k| Kind::from_key(k)).unwrap_or_else(|| usage())),
            _ => usage(),
        }
    }
    let wanted = |k: Kind| only.is_none_or(|o| o == k);

    if let Some(target) = switch {
        std::process::exit(switch_cli(&target, only));
    }

    let lock_name = match only {
        Some(k) => format!("vpn-tray-{}.lock", k.key()),
        None => "vpn-tray.lock".into(),
    };
    let _lock = match crate::common::single_instance_lock(APP.id, &lock_name) {
        _ if dump => None,
        Ok(Some(file)) => Some(file),
        Ok(None) => {
            APP.notify("VPN Tray is already running", "The icon is in the system tray.");
            return;
        }
        Err(e) => {
            eprintln!("Cannot create the single-instance lock: {e}");
            std::process::exit(1);
        }
    };

    if dump {
        let tray = gathered(only);
        println!("icon: {}\n{}", ksni::Tray::tool_tip(&tray).title, crate::common::menu::dump(&ksni::Tray::menu(&tray)));
        return;
    }
    // Wykrywanie przed startem wątków (NetBird i Twingate ustawiają zmienne środowiska).
    let tray = Tray {
        ts: if wanted(Kind::Tailscale) { Tailscale::detect() } else { None },
        tg: if wanted(Kind::Twingate) { Twingate::detect() } else { None },
        nb: if wanted(Kind::NetBird) { NetBird::detect() } else { None },
        wg: if wanted(Kind::WireGuard) { WireGuard::detect() } else { None },
        busy: String::new(),
        off_icon: icon_path(APP.id, "vpn-tray-off"),
    };
    let present = (tray.ts.is_some(), tray.tg.is_some(), tray.nb.is_some(), tray.wg.is_some());
    match crate::common::spawn_tray(tray) {
        Ok(handle) => {
            let _ = HANDLE.set(handle);
        }
        Err(e) => {
            eprintln!("Cannot create the tray icon: {e}");
            std::process::exit(1);
        }
    }
    if present.0 {
        providers::tailscale::start();
    }
    if present.1 {
        providers::twingate::start();
    }
    if present.2 {
        providers::netbird::start();
    }
    if present.3 {
        providers::wireguard::start();
    }
    crate::common::park_forever();
}
