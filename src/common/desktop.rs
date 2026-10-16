//! Okienka (kdialog), powiadomienia, przeglądarka, schowek, terminal.

use crate::common::cmd::{run, spawn, which};

/// Nazwa i ikona aplikacji do okienek i powiadomień.
#[derive(Clone, Copy)]
pub struct App {
    /// "Tailscale Tray"
    pub name: &'static str,
    /// "tailscale-tray" (ikona w hicolor i id traya)
    pub id: &'static str,
}

impl App {
    pub fn notify(&self, title: &str, body: &str) {
        spawn(&["notify-send", "-a", self.name, "-i", self.id, title, body]);
    }

    pub fn error(&self, msg: &str) {
        spawn(&["kdialog", "--title", self.name, "--error", msg]);
    }

    /// Pytanie tak/nie; czeka na odpowiedź, więc tylko poza wątkiem ksni.
    pub fn yesno(&self, text: &str) -> bool {
        run(&["kdialog", "--title", self.name, "--yesno", text], 600).ok()
    }

    /// Pole tekstowe; None = anulowane.
    pub fn inputbox(&self, text: &str, default: &str) -> Option<String> {
        let out = run(&["kdialog", "--title", self.name, "--inputbox", text, default], 600);
        out.ok().then(|| out.stdout.trim().to_string())
    }

    pub fn about(&self, text: &str) {
        let title = format!("About {}", self.name);
        spawn(&["kdialog", "--title", &title, "--icon", self.id, "--msgbox", text]);
    }

    pub fn copy_to_clipboard(&self, text: &str) {
        // Proces bez okna nie ustawi schowka sam; wl-copy na Waylandzie, xclip/xsel na X11.
        let wayland = std::env::var_os("WAYLAND_DISPLAY").is_some();
        let ok = if wayland && which("wl-copy") {
            run(&["wl-copy", "--", text], 5).ok()
        } else if which("xclip") {
            crate::common::cmd::run_input(&["xclip", "-selection", "clipboard"], 5, text).ok()
        } else if which("xsel") {
            crate::common::cmd::run_input(&["xsel", "--clipboard", "--input"], 5, text).ok()
        } else {
            false
        };
        if ok {
            self.notify("Copied to clipboard", text);
        } else {
            self.error("Could not copy to the clipboard (install wl-clipboard).");
        }
    }

    /// Interaktywne polecenie CLI (pyta o sieć itp.) w oknie terminala.
    pub fn in_terminal(&self, cmd: &[&str]) {
        let script = "\"$@\"; echo; printf \"Press Enter to close… \"; read _";
        for term in ["konsole", "alacritty", "kitty", "xterm"] {
            if which(term) {
                let mut argv = vec![term, "-e", "sh", "-c", script, "sh"];
                argv.extend_from_slice(cmd);
                spawn(&argv);
                return;
            }
        }
        self.error(&format!("No terminal emulator found to run:\n{}", cmd.join(" ")));
    }
}

/// Przeglądarka przez xdg-open (bez czekania).
pub fn open_url(url: &str) {
    if !url.is_empty() {
        spawn(&["xdg-open", url]);
    }
}
