use kerlico_shared::{Accept, Handoff, ListenAddr, NodeTag, OpenError, Settings, UserEmail};

struct OpenvpnAccept;

impl Accept for OpenvpnAccept {
    fn add_user(&mut self, email: &UserEmail, account: &Settings) -> Result<(), OpenError> {
        let _ = (email, account, kerlico_openvpn::label());
        unimplemented!("openvpn add user")
    }

    fn remove_user(&mut self, email: &UserEmail) -> Result<(), OpenError> {
        let _ = email;
        unimplemented!("openvpn remove user")
    }

    fn accept(&mut self) -> Result<Handoff, OpenError> {
        unimplemented!("openvpn accept")
    }
}

pub fn listen(
    tag: &NodeTag,
    bind: &ListenAddr,
    settings: &Settings,
) -> Result<Box<dyn Accept>, OpenError> {
    let _ = (tag, bind, settings, OpenvpnAccept);
    unimplemented!("openvpn listen")
}
