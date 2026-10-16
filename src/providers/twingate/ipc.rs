//! IPC demona twingated: /run/twingate/auth.sock, SOCK_SEQPACKET, JSON - tak samo rozmawia CLI.
//! std nie ma gniazd SEQPACKET, więc przez libc.

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::Duration;

use serde_json::Value;

const SOCKET: &str = "/run/twingate/auth.sock";
const BUF: usize = 1 << 20; // SEQPACKET: jeden recv = jeden pakiet, za mały bufor obciąłby go

struct Conn(OwnedFd);

impl Conn {
    fn connect(timeout: Duration) -> io::Result<Conn> {
        // SAFETY: zwykłe wywołania gniazd; deskryptor od razu trafia do OwnedFd.
        unsafe {
            let fd = libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0);
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let conn = Conn(OwnedFd::from_raw_fd(fd));
            let tv = libc::timeval { tv_sec: timeout.as_secs() as _, tv_usec: timeout.subsec_micros() as _ };
            for opt in [libc::SO_RCVTIMEO, libc::SO_SNDTIMEO] {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    opt,
                    &tv as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::timeval>() as libc::socklen_t,
                );
            }
            let mut addr: libc::sockaddr_un = std::mem::zeroed();
            addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
            let path = CString::new(SOCKET).unwrap();
            for (dst, src) in addr.sun_path.iter_mut().zip(path.as_bytes_with_nul()) {
                *dst = *src as libc::c_char;
            }
            let len = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
            if libc::connect(fd, &addr as *const _ as *const libc::sockaddr, len) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(conn)
        }
    }

    fn recv(&self) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; BUF];
        // SAFETY: bufor ma BUF bajtów.
        let n = unsafe { libc::recv(self.0.as_raw_fd(), buf.as_mut_ptr() as *mut libc::c_void, BUF, 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        if n == 0 {
            return Err(io::Error::other("twingated zamknął połączenie"));
        }
        buf.truncate(n as usize);
        Ok(buf)
    }

    fn recv_json(&self) -> io::Result<Value> {
        serde_json::from_slice(&self.recv()?).map_err(io::Error::other)
    }

    fn send(&self, data: &[u8]) -> io::Result<()> {
        // SAFETY: wskaźnik i długość z jednego wycinka.
        let n = unsafe { libc::send(self.0.as_raw_fd(), data.as_ptr() as *const libc::c_void, data.len(), 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

fn cmd_of(v: &Value) -> &str {
    v.get("cmd").and_then(Value::as_str).unwrap_or("")
}

/// Status i opcjonalnie odpowiedź na komendę.
///
/// Po połączeniu demon sam wysyła {"cmd": "status", "msg": "Online", ...} i {"cmd": "status-end"};
/// samo połączenie nie zostawia śladu w journalu. Odpowiedź na "resources" to nagłówek
/// {"cmd": "resources", "content-length": N}, a po nim JSON w kolejnych pakietach.
pub fn ipc(cmd: Option<&Value>, timeout: Duration) -> Result<(Value, Option<Value>), String> {
    let talk = || -> io::Result<(Value, Option<Value>)> {
        let conn = Conn::connect(timeout)?;
        let mut status = Value::Object(Default::default());
        loop {
            let msg = conn.recv_json()?;
            match cmd_of(&msg) {
                "status-end" => break,
                "status" => status = msg,
                _ => {}
            }
        }
        let Some(cmd) = cmd else { return Ok((status, None)) };
        conn.send(cmd.to_string().as_bytes())?;
        let header = loop {
            let msg = conn.recv_json()?;
            if cmd_of(&msg) == cmd_of(cmd) {
                break msg; // wcześniejsze to powiadomienia wysłane w międzyczasie
            }
        };
        let Some(length) = header.get("content-length").and_then(Value::as_u64) else {
            return Ok((status, Some(header)));
        };
        let mut body = Vec::new();
        while (body.len() as u64) < length {
            match conn.recv() {
                Ok(chunk) => body.extend_from_slice(&chunk),
                Err(_) => break,
            }
        }
        Ok((status, Some(serde_json::from_slice(&body).map_err(io::Error::other)?)))
    };
    talk().map_err(|e| format!("twingated nie odpowiada: {e}"))
}
