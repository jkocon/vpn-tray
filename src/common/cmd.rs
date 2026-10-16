//! Polecenia zewnętrzne z limitem czasu.

use std::io::{Read, Write};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// Wynik polecenia; `code` = -1, gdy proces nie wystartował albo zabił go sygnał.
#[derive(Clone, Debug, Default)]
pub struct Out {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Out {
    pub fn ok(&self) -> bool {
        self.code == 0
    }

    /// 0 albo 126 (anulowane okno pkexec) - wtedy nie ma czego zgłaszać.
    pub fn ok_or_cancelled(&self) -> bool {
        self.code == 0 || self.code == 126
    }

    /// stderr + stdout bez białych znaków na brzegach.
    pub fn text(&self) -> String {
        format!("{}{}", self.stderr, self.stdout).trim().to_string()
    }
}

/// Polecenie z limitem czasu (w sekundach), które przy przekroczeniu ubija całą grupę procesów:
/// CLI potrafią odpalać pod spodem procesy, które wiszą (np. twingate-notifier).
pub fn run(cmd: &[&str], timeout: u64) -> Out {
    run_with(cmd, timeout, None)
}

/// Jak `run`, z tekstem na stdin (np. odpowiedź "y" na pytanie CLI).
pub fn run_input(cmd: &[&str], timeout: u64, input: &str) -> Out {
    run_with(cmd, timeout, Some(input))
}

fn run_with(cmd: &[&str], timeout: u64, input: Option<&str>) -> Out {
    let Some((prog, args)) = cmd.split_first() else { return Out { code: -1, ..Default::default() } };
    let mut command = Command::new(prog);
    command
        .args(args)
        .stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = match command.spawn() {
        Ok(c) => c,
        Err(e) => return Out { code: -1, stdout: String::new(), stderr: format!("{prog}: {e}") },
    };
    if let (Some(text), Some(mut stdin)) = (input, child.stdin.take()) {
        let text = text.to_string();
        thread::spawn(move || {
            let _ = stdin.write_all(text.as_bytes());
        });
    }
    let reader = |pipe: Option<Box<dyn Read + Send>>| {
        thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(mut p) = pipe {
                let _ = p.read_to_end(&mut buf);
            }
            String::from_utf8_lossy(&buf).into_owned()
        })
    };
    let out_t = reader(child.stdout.take().map(|p| Box::new(p) as Box<dyn Read + Send>));
    let err_t = reader(child.stderr.take().map(|p| Box::new(p) as Box<dyn Read + Send>));

    let deadline = Instant::now() + Duration::from_secs(timeout);
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() >= deadline => {
                timed_out = true;
                // SAFETY: killpg na grupie procesów, którą sami utworzyliśmy (process_group(0)).
                unsafe { libc::killpg(child.id() as i32, libc::SIGKILL) };
                break child.wait().ok();
            }
            Ok(None) => thread::sleep(Duration::from_millis(30)),
            Err(_) => break None,
        }
    };
    let stdout = out_t.join().unwrap_or_default();
    let mut stderr = err_t.join().unwrap_or_default();
    if timed_out {
        stderr.push_str(&format!("\n(timed out after {timeout}s)"));
    }
    let code = status.map(|s| s.code().unwrap_or_else(|| if s.signal().is_some() { -1 } else { 0 })).unwrap_or(-1);
    Out { code, stdout, stderr }
}

/// Uruchom i nie czekaj (okienko, przeglądarka, terminal); proces jest zbierany w tle.
pub fn spawn(cmd: &[&str]) {
    let Some((prog, args)) = cmd.split_first() else { return };
    match Command::new(prog).args(args).stdin(Stdio::null()).process_group(0).spawn() {
        Ok(mut child) => {
            thread::spawn(move || {
                let _ = child.wait();
            });
        }
        Err(e) => eprintln!("{prog}: {e}"),
    }
}

/// Uruchom z połączonym stdout+stderr i podawaj każdą linię do `on_line` (np. żeby wyłapać adres
/// logowania). Zwraca kod wyjścia i wszystkie linie.
pub fn stream_lines(cmd: &[&str], mut on_line: impl FnMut(&str)) -> (i32, Vec<String>) {
    use std::io::BufRead;
    // 2>&1 przez sh, żeby kolejność linii z obu strumieni się zgadzała.
    let mut child = match Command::new("sh")
        .args(["-c", "exec \"$@\" 2>&1", "sh"])
        .args(cmd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .process_group(0)
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return (-1, vec![e.to_string()]),
    };
    let mut lines = Vec::new();
    if let Some(out) = child.stdout.take() {
        for line in std::io::BufReader::new(out).lines().map_while(Result::ok) {
            on_line(&line);
            lines.push(line);
        }
    }
    let code = child.wait().ok().and_then(|s| s.code()).unwrap_or(-1);
    (code, lines)
}

pub fn which(name: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|d| d.join(name).is_file()))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captures_output_and_code() {
        let out = run(&["sh", "-c", "echo out; echo err >&2; exit 3"], 5);
        assert_eq!(out.code, 3);
        assert_eq!(out.stdout, "out\n");
        assert_eq!(out.text(), "err\nout");
    }

    #[test]
    fn kills_on_timeout() {
        let start = Instant::now();
        let out = run(&["sh", "-c", "sleep 30 & sleep 30"], 1);
        assert!(start.elapsed() < Duration::from_secs(5));
        assert!(!out.ok());
        assert!(out.stderr.contains("timed out"));
    }

    #[test]
    fn feeds_stdin() {
        assert_eq!(run_input(&["cat"], 5, "y\n").stdout, "y\n");
    }

    #[test]
    fn streams_both_streams() {
        let mut seen = Vec::new();
        let (code, lines) = stream_lines(&["sh", "-c", "echo a; echo b >&2; exit 2"], |l| seen.push(l.to_string()));
        assert_eq!(code, 2);
        assert_eq!(lines, ["a", "b"]);
        assert_eq!(seen, lines);
    }

    #[test]
    fn missing_program() {
        assert_eq!(run(&["/nonexistent/prog"], 5).code, -1);
    }
}
