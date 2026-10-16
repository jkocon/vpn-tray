//! Części wspólne dla wszystkich VPN-ów (dawniej kopiowane w tailscale-, twingate-, netbird-
//! i wireguard-tray): polecenia z limitem czasu, okienka kdialog, powiadomienia, schowek, ikony,
//! blokada jednej instancji, odpytywanie w tle i pozycje menu ksni.
//!
//! ksni (StatusNotifierItem + DBusMenu) zamiast GTK/AppIndicator: menu otwiera się lewym klikiem
//! tak samo jak wcześniej (MENU_ON_ACTIVATE), a nie trzeba GTK ani pygobject.

#![allow(dead_code, unused_imports)] // nie każdy tray używa wszystkiego

pub mod cmd;
pub mod desktop;
pub mod json;
pub mod menu;

use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::PathBuf;
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::Duration;

pub use cmd::{run, run_input, Out};
pub use desktop::{open_url, App};

/// Prywatny katalog w XDG_RUNTIME_DIR (albo ~/.cache, nigdy przewidywalna ścieżka w /tmp).
pub fn runtime_dir(app: &str) -> io::Result<PathBuf> {
    let base = match std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from).filter(|d| d.is_dir()) {
        Some(dir) => dir,
        None => {
            let home = std::env::var_os("HOME").ok_or_else(|| io::Error::other("HOME is not set"))?;
            PathBuf::from(home).join(".cache")
        }
    };
    let dir = base.join(app);
    fs::DirBuilder::new().recursive(true).mode(0o700).create(&dir)?;
    Ok(dir)
}

/// Zablokowany plik (trzymać otwarty) albo None, gdy tray już działa w tej sesji.
/// Ta sama nazwa pliku co w wersji w Pythonie (XDG_RUNTIME_DIR/<name>), więc obie się wykluczają.
pub fn single_instance_lock(app: &str, name: &str) -> io::Result<Option<File>> {
    let dir = match std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from).filter(|d| d.is_dir()) {
        Some(dir) => dir,
        None => runtime_dir(app)?,
    };
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(dir.join(name))?;
    // SAFETY: flock na deskryptorze, który należy do nas.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let err = io::Error::last_os_error();
        return if err.kind() == io::ErrorKind::WouldBlock { Ok(None) } else { Err(err) };
    }
    Ok(Some(file))
}

/// Katalog z ikonami stanu: obok binarki (instalacja w /usr/local/lib/<app>), a przy `cargo run`
/// katalog icons/ w źródłach.
pub fn icon_dir(app: &str) -> PathBuf {
    let beside = std::env::current_exe().ok().and_then(|exe| exe.parent().map(|d| d.join("icons")));
    if let Some(dir) = beside.filter(|d| d.is_dir()) {
        return dir;
    }
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("icons");
    if source.is_dir() {
        return source;
    }
    PathBuf::from(format!("/usr/local/lib/{app}/icons"))
}

/// FNV-1a: stabilny między wersjami Rusta, wystarczy do wykrycia zmiany pliku.
fn content_hash(data: &[u8]) -> u64 {
    data.iter().fold(0xcbf29ce484222325u64, |h, b| (h ^ *b as u64).wrapping_mul(0x100000001b3))
}

/// Pełna ścieżka do kopii ikony z hashem zawartości w nazwie.
///
/// Pełna ścieżka, nie nazwa: Plasma ignoruje IconThemePath z płaskim katalogiem i obcina nieznaną
/// nazwę do "<app>" (ikona aplikacji). Hash w nazwie: Plasma trzyma w cache ikonę spod tej samej
/// ścieżki, więc po zmianie pliku pokazywała starą wersję.
pub fn icon_path(app: &str, name: &str) -> String {
    let src = icon_dir(app).join(format!("{name}.svg"));
    let copy = || -> io::Result<PathBuf> {
        let data = fs::read(&src)?;
        let dst = runtime_dir(app)?.join(format!("{name}-{:010x}.svg", content_hash(&data) & 0xff_ffff_ffff));
        if !dst.exists() {
            fs::write(&dst, &data)?;
        }
        Ok(dst)
    };
    copy().unwrap_or(src).to_string_lossy().into_owned()
}

/// Wątek, który co `interval` (albo od razu po `poke`) woła `tick`. Odpytywanie demona to osobne
/// procesy i gniazda, więc nigdy nie idzie w wątku ksni (menu by zamarzało).
pub struct Poller {
    tx: Mutex<Sender<()>>,
}

impl Poller {
    pub fn start(interval: Duration, mut tick: impl FnMut() + Send + 'static) -> Poller {
        let (tx, rx) = mpsc::channel::<()>();
        thread::spawn(move || loop {
            tick();
            match rx.recv_timeout(interval) {
                Ok(()) => while rx.try_recv().is_ok() {}, // kilka próśb naraz = jedno odświeżenie
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return,
            }
        });
        Poller { tx: Mutex::new(tx) }
    }

    /// Odśwież teraz (np. po zmianie ustawienia).
    pub fn poke(&self) {
        if let Ok(tx) = self.tx.lock() {
            let _ = tx.send(());
        }
    }
}

/// Uruchom w osobnym wątku. Wywołania zwrotne menu ksni trzymają blokadę traya, więc wszystko,
/// co czeka (polecenia, okienka kdialog, Handle::update), musi iść poza nimi.
pub fn bg(f: impl FnOnce() + Send + 'static) {
    thread::spawn(f);
}

/// Ikona w zasobniku. Działa też bez hosta zasobnika i pokazuje się, gdy on się pojawi
/// (panel Plasmy potrafi wstać później niż autostart).
pub fn spawn_tray<T: ksni::Tray>(tray: T) -> Result<ksni::blocking::Handle<T>, ksni::Error> {
    use ksni::blocking::TrayMethods;
    tray.assume_sni_available(true).spawn()
}

/// Główny wątek nie ma nic do roboty - tray działa w wątku ksni, odpytywanie w wątkach dostawców.
pub fn park_forever() -> ! {
    loop {
        thread::park();
    }
}

pub fn unit_enabled(unit: &str) -> bool {
    run(&["systemctl", "is-enabled", unit], 30).stdout.trim() == "enabled"
}

pub fn unit_active(unit: &str) -> bool {
    run(&["systemctl", "is-active", unit], 30).stdout.trim() == "active"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_stable() {
        assert_eq!(content_hash(b""), 0xcbf29ce484222325);
        assert_eq!(content_hash(b"a"), 0xaf63dc4c8601ec8c);
    }
}
