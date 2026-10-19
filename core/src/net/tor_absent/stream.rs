//! A stream that cannot exist, since no `Tor` can open one.

use std::io::{Read, Result, Write};

pub enum TorStream {}

impl Read for TorStream {
    fn read(&mut self, _: &mut [u8]) -> Result<usize> {
        match *self {}
    }
}

impl Write for TorStream {
    fn write(&mut self, _: &[u8]) -> Result<usize> {
        match *self {}
    }

    fn flush(&mut self) -> Result<()> {
        match *self {}
    }
}
