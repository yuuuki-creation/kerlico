// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// (c) ZeroTier, Inc.
// https://www.zerotier.com/
//
// Module layout for a Rust translation of ZeroTierOne tag 1.16.2 node/ sources.
// Each module names the upstream files it was translated from.

//! Sans-IO ZeroTier client node. The caller owns sockets and clocks: it feeds datagrams and
//! local frames into [`Node`] and drains [`Event`]s.

mod address;
mod certificate;
mod dictionary;
mod identity;
mod inet;
mod network;
mod node;
mod packet;
mod reader;
mod world;

pub use address::{Address, Mac, MulticastGroup};
pub use certificate::CertificateOfMembership;
pub use identity::{Identity, IdentityError};
pub use network::{NetworkConfig, Route, embedded_address};
pub use node::{Event, Frame, IdentityCheck, IdentityVerdict, JoinStatus, Node, NodeOptions, Seed};
pub use world::default_planet_roots;
