use kerlico_shared::{Accept, Handoff, ListenAddr, NodeTag, OpenError, Settings, UserEmail};

struct WireguardAccept;

impl Accept for WireguardAccept {
    fn add_user(&mut self, email: &UserEmail, account: &Settings) -> Result<(), OpenError> {
        let _ = (email, account, kerlico_wireguard::label());
        unimplemented!("wireguard add user")
    }

    fn remove_user(&mut self, email: &UserEmail) -> Result<(), OpenError> {
        let _ = email;
        unimplemented!("wireguard remove user")
    }

    fn accept(&mut self) -> Result<Handoff, OpenError> {
        unimplemented!("wireguard accept")
    }
}

pub fn listen(
    tag: &NodeTag,
    bind: &ListenAddr,
    settings: &Settings,
) -> Result<Box<dyn Accept>, OpenError> {
    let _ = (tag, bind, settings, WireguardAccept);
    unimplemented!("wireguard listen")
}
