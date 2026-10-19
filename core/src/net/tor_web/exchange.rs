//! One request as the core wrote it, sent by the browser, and the reply written back as HTTP.

use super::xhr::request;

/// Send `bytes`, an HTTP/1.1 request the core wrote, to `host`, and return the reply as HTTP/1.1
/// with its length declared, or none when the browser could not send it.
pub(super) fn send(host: &str, bytes: &[u8]) -> Option<Vec<u8>> {
    let split = bytes.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = core::str::from_utf8(bytes.get(..split)?).ok()?;
    let body = core::str::from_utf8(bytes.get(split.checked_add(4)?..)?).ok()?;
    let mut line = head.lines().next()?.split(' ');
    let (method, path) = (line.next()?, line.next()?);
    let url = format!("https://{host}{path}");
    let (status, text) = request(method, &url, (!body.is_empty()).then_some(body))?;
    let mut reply =
        format!("HTTP/1.1 {status:03} -\r\nContent-Length: {}\r\n\r\n", text.len()).into_bytes();
    reply.extend_from_slice(text.as_bytes());
    Some(reply)
}
