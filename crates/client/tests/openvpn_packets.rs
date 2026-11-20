#![cfg(feature = "openvpn")]

use std::{
    fs,
    path::PathBuf,
    time::{Duration, Instant},
};

use kerlico_client::{Client, ClientConfig, Running};
use kerlico_shared::Packet;

#[test]
#[ignore = "requires the local OpenVPN packet fixture"]
fn round_trip_with_openvpn_peer() {
    let folder: PathBuf = std::env::var_os("KERLICO_OPENVPN_PACKET_FIXTURE")
        .unwrap()
        .into();
    let document = fs::read_to_string(folder.join("kerlico-client.json")).unwrap();
    let Running::Tunnel(mut session) =
        Client::start(ClientConfig::parse(&document, None).unwrap()).unwrap()
    else {
        panic!("expected an OpenVPN tunnel")
    };
    let outgoing = fs::read(folder.join("outgoing.ip")).unwrap();
    let expected = fs::read(folder.join("expected.ip")).unwrap();
    session
        .send(Packet::from_ip_packet(outgoing).unwrap())
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Ok(reply) = session.recv() {
            assert_eq!(reply.as_bytes(), expected);
            return;
        }
    }
    panic!("timed out waiting for the official OpenVPN peer to return the IP packet");
}
