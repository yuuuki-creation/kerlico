#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Transport {
    Tcp,
    Udp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Multiplexing {
    Off,
    Low,
    Middle,
    High,
}

impl Multiplexing {
    pub(crate) fn factor(self) -> usize {
        match self {
            Self::Off => 0,
            Self::Low => 1,
            Self::Middle => 2,
            Self::High => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandshakeMode {
    Standard,
    NoWait,
}

#[derive(Clone, Debug)]
pub struct ClientOptions {
    pub transport: Transport,
    pub mtu: u16,
    pub multiplexing: Multiplexing,
    pub handshake: HandshakeMode,
    pub low_entropy: u8,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            transport: Transport::Tcp,
            mtu: 1400,
            multiplexing: Multiplexing::Low,
            handshake: HandshakeMode::Standard,
            low_entropy: 0,
        }
    }
}
