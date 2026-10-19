//! A stream that collects the HTTP request the core writes and, on the first read, has the browser
//! send it and plays the reply back as HTTP. The core's own parser then reads it as it would any
//! reply, with the same limits.

use std::io::{Cursor, Error, ErrorKind, Read, Result, Write};

pub struct TorStream {
    host: String,
    request: Vec<u8>,
    reply: Option<Cursor<Vec<u8>>>,
}

impl TorStream {
    pub(super) fn to(host: &str) -> TorStream {
        TorStream { host: host.to_owned(), request: Vec::new(), reply: None }
    }
}

impl Read for TorStream {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.reply.is_none() {
            let reply = super::exchange::send(&self.host, &self.request)
                .ok_or_else(|| Error::from(ErrorKind::ConnectionRefused))?;
            self.reply = Some(Cursor::new(reply));
        }
        self.reply.as_mut().map_or(Ok(0), |r| r.read(buf))
    }
}

impl Write for TorStream {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        if self.reply.is_some() {
            return Err(Error::from(ErrorKind::BrokenPipe));
        }
        self.request.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}
