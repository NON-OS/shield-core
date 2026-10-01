/*
 * A test asserts by panicking, and a measurement prints what it read, so the
 * lints that forbid panicking and indexing are off here and nowhere else.
 */
#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

use nox_shield_core::error::NetError;
use nox_shield_core::net::{check_endpoint, Endpoint, Route};

/// A real version 3 onion name, the Tor Project's own. The check decodes the name, so an
/// invented one of the right shape would be refused.
const REAL: &str = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion";

fn at(host: &str, route: Route) -> Endpoint {
    Endpoint {
        host: host.into(),
        port: 9735,
        proxy_host: "127.0.0.1".into(),
        proxy_port: Endpoint::proxy_default(route),
        route,
    }
}

#[test]
fn an_onion_service_through_a_local_proxy_is_admitted() {
    assert!(check_endpoint(&at(REAL, Route::Tor)).is_ok());
}

/// A name that ends in .onion and is not one. This is what a suffix test
/// admitted: a string somebody invented, which the wallet would then point at
/// and fail to reach with nothing to say about why.
#[test]
fn a_name_that_only_ends_in_onion_is_refused() {
    for invented in [
        "sequencerplaceholderaddress.onion",
        "expyuzz4wqqyqhjn5cxdspyuzz4wqqyqhjn5cxdspyuzz4wqqyqhjn5cd.onion",
        "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wi1.onion",
        ".onion",
    ] {
        assert_eq!(
            check_endpoint(&at(invented, Route::Tor)).err(),
            Some(NetError::EndpointRefused),
            "{invented} is not a version 3 onion name and was admitted"
        );
    }
}

#[test]
fn a_clearnet_host_over_tor_is_refused() {
    assert_eq!(
        check_endpoint(&at("sequencer.example.com", Route::Tor)).err(),
        Some(NetError::EndpointRefused),
        "an exit node would see the request and who kept making it"
    );
}

#[test]
fn a_raw_address_over_nym_is_refused() {
    assert_eq!(
        check_endpoint(&at("203.0.113.7", Route::Nym)).err(),
        Some(NetError::EndpointRefused)
    );
}

#[test]
fn a_proxy_on_another_host_is_refused() {
    let mut endpoint = at(REAL, Route::Tor);
    endpoint.proxy_host = "10.0.0.5".into();
    assert_eq!(check_endpoint(&endpoint).err(), Some(NetError::EndpointRefused));
}

#[test]
fn the_default_proxy_ports_are_the_ones_those_clients_listen_on() {
    assert_eq!(Endpoint::proxy_default(Route::Tor), 9050);
    assert_eq!(Endpoint::proxy_default(Route::Nym), 1080);
}
