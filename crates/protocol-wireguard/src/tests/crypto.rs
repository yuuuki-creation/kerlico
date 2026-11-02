use super::*;
use crate::{config::{CommonOptions, PeerOptions}, crypto::{CryptoPeer, PeerIndex}, packet::udp_packet};
use std::net::SocketAddr;

fn pair(psk: Option<u8>) -> (CryptoPeer, CryptoPeer) {
    let a = serde_json::from_value::<CommonOptions>(tunnel(1, 2)).unwrap().prepare().unwrap();
    let b = serde_json::from_value::<CommonOptions>(tunnel(2, 1)).unwrap().prepare().unwrap();
    let a_peer = serde_json::from_value::<PeerOptions>(peer(2, None, psk)).unwrap().prepare().unwrap();
    let b_peer = serde_json::from_value::<PeerOptions>(peer(1, Some(2), psk)).unwrap().prepare().unwrap();
    let a_index = PeerIndex::new(&a, std::slice::from_ref(&a_peer));
    let b_index = PeerIndex::new(&b, std::slice::from_ref(&b_peer));
    (CryptoPeer::new(&a, &a_peer, 1, None, a_index.limiter), CryptoPeer::new(&b, &b_peer, 1, None, b_index.limiter))
}
fn handshake(a: &mut CryptoPeer, b: &mut CryptoPeer, source: SocketAddr, target: SocketAddr) {
    let init = a.initiate().unwrap();
    let response = b.receive(source, &init).unwrap();
    assert!(!response.authenticated && response.plain.is_none());
    let confirmed = a.receive(target, &response.network[0]).unwrap();
    assert!(confirmed.authenticated && confirmed.plain.is_none());
    let complete = b.receive(source, &confirmed.network[0]).unwrap();
    assert!(complete.authenticated && complete.plain.is_none());
    assert!(a.ready() && b.ready());
}
#[test]
fn encrypted_transport_replay_and_roaming_require_real_authentication() {
    for psk in [None, Some(9)] {
        let (mut a, mut b) = pair(psk);
        let source: SocketAddr = "127.0.0.1:1200".parse().unwrap();
        let target = "127.0.0.1:1300".parse().unwrap();
        handshake(&mut a, &mut b, source, target);
        let ip = udp_packet("10.77.0.2:1400".parse().unwrap(), "192.0.2.5:1500".parse().unwrap(), b"authenticated").unwrap();
        let packet = a.encrypt(&ip).unwrap().unwrap();
        let moved = "127.0.0.1:1201".parse().unwrap();
        let received = b.receive(moved, &packet).unwrap();
        assert!(received.authenticated);
        assert_eq!(received.plain.unwrap(), ip);
        assert_eq!(b.endpoint, Some(moved));
        assert!(b.receive(source, &packet).is_err());
        assert_eq!(b.endpoint, Some(moved));
        let mut corrupt = a.encrypt(&ip).unwrap().unwrap();
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(b.receive(source, &corrupt).is_err());
        assert_eq!(b.endpoint, Some(moved));
        handshake(&mut a, &mut b, moved, target);
        let next = a.encrypt(&ip).unwrap().unwrap();
        assert_eq!(b.receive(moved, &next).unwrap().plain.unwrap(), ip);
    }
}
#[test]
fn mismatched_psk_never_confirms_peer() {
    let (mut a, _) = pair(Some(9));
    let (_, mut b) = pair(Some(8));
    let init = a.initiate().unwrap();
    let response = b.receive("127.0.0.1:1200".parse().unwrap(), &init).unwrap();
    assert!(!response.authenticated);
    assert!(a.receive("127.0.0.1:1300".parse().unwrap(), &response.network[0]).is_err());
    assert!(!a.ready() && !b.ready());
    assert!(b.endpoint.is_none());
}
