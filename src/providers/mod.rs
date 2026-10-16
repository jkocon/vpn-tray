//! Dostawcy VPN. Każdy ma własny stan, własny wątek odpytywania (zawieszony CLI jednego VPN-a nie
//! zamraża reszty) i własne podmenu - przeniesione z osobnych trayów. Do wspólnej listy wyboru
//! każdy daje swoje "sieci" (konta, profile, połączenia) oraz zadania połącz/rozłącz.

pub mod netbird;
pub mod tailscale;
pub mod twingate;
pub mod wireguard;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Tailscale,
    Twingate,
    NetBird,
    WireGuard,
}

impl Kind {
    pub const ALL: [Kind; 4] = [Kind::Tailscale, Kind::Twingate, Kind::NetBird, Kind::WireGuard];

    pub fn name(self) -> &'static str {
        match self {
            Kind::Tailscale => "Tailscale",
            Kind::Twingate => "Twingate",
            Kind::NetBird => "NetBird",
            Kind::WireGuard => "WireGuard",
        }
    }

    /// Nazwa w argumentach (`--only netbird`).
    pub fn key(self) -> &'static str {
        match self {
            Kind::Tailscale => "tailscale",
            Kind::Twingate => "twingate",
            Kind::NetBird => "netbird",
            Kind::WireGuard => "wireguard",
        }
    }

    pub fn from_key(key: &str) -> Option<Kind> {
        Kind::ALL.into_iter().find(|k| k.key() == key.to_lowercase())
    }
}

/// Pozycja na liście wyboru: jedna sieć jednego VPN-a.
#[derive(Clone, Debug, PartialEq)]
pub struct Choice {
    pub kind: Kind,
    /// Konto / profil / UUID połączenia; "" = bieżące.
    pub id: String,
    /// Tekst po nazwie VPN-a (np. nazwa profilu); "" = sama nazwa.
    pub detail: String,
    /// Ta sieć jest teraz połączona albo się łączy.
    pub active: bool,
}

impl Choice {
    pub fn label(&self) -> String {
        if self.detail.is_empty() { self.kind.name().into() } else { format!("{} – {}", self.kind.name(), self.detail) }
    }
}

/// Stan VPN-a do ikony, podpowiedzi i nagłówka podmenu.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Off,
    Connecting,
    On,
    /// Połączony albo włączony, ale wymaga uwagi (logowanie, serwer nie odpowiada).
    Attention,
}

#[derive(Clone, Debug)]
pub struct Summary {
    pub level: Level,
    /// "connected", "connecting…", "sign-in required"…
    pub text: String,
    /// Pełna ścieżka ikony stanu.
    pub icon: String,
}

/// Zadanie w tle (połącz/rozłącz); Err = komunikat dla użytkownika.
pub type Job = Box<dyn FnOnce() -> Result<(), String> + Send>;

/// Pytanie przed przełączeniem (np. WireGuard w sieci, w której już jesteś); false = anuluj.
pub type Confirm = Box<dyn FnOnce() -> bool + Send>;
