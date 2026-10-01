//! A Tor stream for the synchronous transport, blocking on the client's runtime per call. Each
//! read and write gives up after `STALL`, so a silent server is skipped, not waited on.

use arti_client::DataStream;
use std::io::{Error, ErrorKind, Read, Result, Write};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::runtime::Handle;
use tokio::time::timeout;

pub(super) const STALL: Duration = Duration::from_secs(30);

fn stalled<T>(r: core::result::Result<Result<T>, tokio::time::error::Elapsed>) -> Result<T> {
    r.unwrap_or_else(|_| Err(Error::new(ErrorKind::TimedOut, "no progress")))
}

pub struct TorStream {
    rt: Handle,
    inner: DataStream,
}

impl TorStream {
    pub(super) fn new(rt: Handle, inner: DataStream) -> TorStream {
        TorStream { rt, inner }
    }
}

impl Read for TorStream {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        stalled(self.rt.block_on(async { timeout(STALL, self.inner.read(buf)).await }))
    }
}

impl Write for TorStream {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        stalled(self.rt.block_on(async { timeout(STALL, self.inner.write(buf)).await }))
    }

    fn flush(&mut self) -> Result<()> {
        stalled(self.rt.block_on(async { timeout(STALL, self.inner.flush()).await }))
    }
}
