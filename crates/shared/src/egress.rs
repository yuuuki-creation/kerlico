/// The five exits this module can choose.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Exit {
    NativeV4,
    NativeV6,
    WarpV4,
    WarpV6,
    Landing,
}

impl Exit {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::NativeV4 => "native-v4",
            Self::NativeV6 => "native-v6",
            Self::WarpV4 => "warp-v4",
            Self::WarpV6 => "warp-v6",
            Self::Landing => "landing",
        }
    }

    pub fn uplink_name(self) -> String {
        format!("outbound>>>{}>>>traffic>>>uplink", self.tag())
    }

    pub fn downlink_name(self) -> String {
        format!("outbound>>>{}>>>traffic>>>downlink", self.tag())
    }

    pub const fn is_v4(self) -> bool {
        matches!(self, Self::NativeV4 | Self::WarpV4)
    }

    pub const fn is_v6(self) -> bool {
        matches!(self, Self::NativeV6 | Self::WarpV6)
    }
}

/// Set on the node at creation. `Default` is the blank outbound field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutboundChoice {
    Manual(Exit),
    Default,
}

impl OutboundChoice {
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "default" => Some(Self::Default),
            "native-v4" => Some(Self::Manual(Exit::NativeV4)),
            "native-v6" => Some(Self::Manual(Exit::NativeV6)),
            "warp-v4" => Some(Self::Manual(Exit::WarpV4)),
            "warp-v6" => Some(Self::Manual(Exit::WarpV6)),
            "landing" => Some(Self::Manual(Exit::Landing)),
            _ => None,
        }
    }
}
