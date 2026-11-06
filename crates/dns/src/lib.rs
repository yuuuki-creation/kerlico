//! 统一 DNS 管线：`Local` 出网解析、路由解析、劫持与 `dns.listen` 报文、DNS 出站和控制面查询共用同一条路径。
//!
//! 查询顺序与 Mihomo 一致：hosts → DNS 规则（sing-box）→ Fake-IP → 缓存 → `nameserver-policy` →
//! `nameserver` 与 `fallback`（`fallback-filter`）。组内并发查询，第一个有效应答胜出。

pub mod cache_file;
pub mod fakeip;
pub mod listener;
pub mod matcher;
pub mod server;
pub mod upstream;
pub mod wire;

mod cache;
mod hosts;
mod pipeline;
mod spec;

pub use fakeip::{CacheFileSpec, FakeDnsInput, FakeDnsPoolSpec, FakeIpPool, ReverseMappingCache};
pub use matcher::{NoSets, SetLookup};
pub use pipeline::{AnswerSource, DnsAnswer, DnsResolver, GroupKind, Purpose};
pub use server::Via;
pub use spec::{
    DnsPolicyMap, DnsPolicyValue, DnsQueryTypeInput, DnsReferences, DnsRuleSpec, DnsServerInput,
    DnsServerSpec, DnsSpec, DnsTlsSpec, FallbackFilterSpec, HostsValue,
};
pub use upstream::DnsDialer;
