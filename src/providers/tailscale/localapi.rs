//! LocalAPI tailscaled: HTTP po unix sockecie (/var/run/tailscale/tailscaled.sock).
//!
//! HTTP/1.0 z Connection: close - odpowiedź kończy się zamknięciem połączenia, więc wystarczy
//! przeczytać wszystko; chunked jest obsłużone na wszelki wypadek.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use serde_json::Value;

const SOCKET: &str = "/var/run/tailscale/tailscaled.sock";

pub fn api(method: &str, path: &str, body: Option<&Value>) -> Result<Value, String> {
    let fail = |e: std::io::Error| format!("tailscaled nie odpowiada: {e}");
    let mut sock = UnixStream::connect(SOCKET).map_err(fail)?;
    sock.set_read_timeout(Some(Duration::from_secs(5))).map_err(fail)?;
    sock.set_write_timeout(Some(Duration::from_secs(5))).map_err(fail)?;
    let body = body.map(Value::to_string).unwrap_or_default();
    let request = format!(
        "{method} /localapi/v0/{path} HTTP/1.0\r\nHost: local-tailscaled.sock\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    sock.write_all(request.as_bytes()).map_err(fail)?;
    let mut raw = Vec::new();
    sock.read_to_end(&mut raw).map_err(fail)?;
    let (code, data) = parse_response(&raw).ok_or_else(|| "tailscaled nie odpowiada: bad HTTP response".to_string())?;
    if code >= 400 {
        let msg = String::from_utf8_lossy(&data).trim().to_string();
        return Err(if msg.is_empty() { format!("HTTP {code}") } else { msg });
    }
    if data.iter().all(u8::is_ascii_whitespace) {
        return Ok(Value::Null);
    }
    serde_json::from_slice(&data).map_err(|e| format!("tailscaled: bad JSON: {e}"))
}

/// (kod, ciało) z surowej odpowiedzi HTTP.
fn parse_response(raw: &[u8]) -> Option<(u16, Vec<u8>)> {
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&raw[..split]).ok()?;
    let body = &raw[split + 4..];
    let mut lines = head.split("\r\n");
    let code = lines.next()?.split_whitespace().nth(1)?.parse().ok()?;
    let chunked = lines.any(|l| {
        let l = l.to_ascii_lowercase();
        l.starts_with("transfer-encoding:") && l.contains("chunked")
    });
    Some((code, if chunked { dechunk(body)? } else { body.to_vec() }))
}

fn dechunk(mut body: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let eol = body.windows(2).position(|w| w == b"\r\n")?;
        let size_text = std::str::from_utf8(&body[..eol]).ok()?;
        let size = usize::from_str_radix(size_text.split(';').next()?.trim(), 16).ok()?;
        body = &body[eol + 2..];
        if size == 0 {
            return Some(out);
        }
        out.extend_from_slice(body.get(..size)?);
        body = body.get(size + 2..)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_and_chunked() {
        let r = b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{\"a\":1}";
        assert_eq!(parse_response(r), Some((200, b"{\"a\":1}".to_vec())));
        let r = b"HTTP/1.1 403 Forbidden\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nacce\r\n9\r\nss denied\r\n0\r\n\r\n";
        assert_eq!(parse_response(r), Some((403, b"access denied".to_vec())));
        assert_eq!(parse_response(b"garbage"), None);
    }
}
