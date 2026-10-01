// Tests assert by panicking, so the lints that forbid it are off here.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use super::probe::probe_at;
use crate::error::NetError;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

// The probe against a listener answering like a local client, and listeners that do not. A
// proxy asking for credentials is not the expected loopback client, and offering it a host
// name would trust something that already misbehaved, so it is refused, never negotiated.
fn listener_answering(answer: [u8; 2]) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let address = listener.local_addr().expect("address");
    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut greeting = [0u8; 3];
            if stream.read_exact(&mut greeting).is_ok() {
                let _ = stream.write_all(&answer);
            }
        }
    });
    address
}

#[test]
fn a_client_that_takes_no_authentication_answers_the_probe() {
    assert!(probe_at(listener_answering([5, 0])).is_ok());
}

#[test]
fn a_proxy_that_wants_credentials_is_refused() {
    assert_eq!(probe_at(listener_answering([5, 2])), Err(NetError::ProxyRefused));
}

#[test]
fn something_that_is_not_socks_is_refused() {
    assert_eq!(probe_at(listener_answering([72, 84])), Err(NetError::ProxyProtocol));
}

#[test]
fn nothing_listening_is_an_unreachable_proxy() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let address = listener.local_addr().expect("address");
    drop(listener);
    assert_eq!(probe_at(address), Err(NetError::ProxyUnreachable));
}

/// The greeting bytes: version five, one method, no authentication. Asserted so a change fails
/// here, not against a running Orbot.
#[test]
fn the_probe_offers_no_authentication_and_nothing_else() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let address = listener.local_addr().expect("address");
    let seen = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut greeting = [0u8; 3];
        stream.read_exact(&mut greeting).expect("greeting");
        let _ = stream.write_all(&[5, 0]);
        greeting
    });
    probe_at(address).expect("the listener answers");
    assert_eq!(seen.join().expect("joined"), [5, 1, 0]);
}
