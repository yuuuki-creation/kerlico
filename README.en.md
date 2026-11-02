# kerlico

[简体中文](README.md)

`kerlico` is a unified client-and-server proxy core written in Rust, informed by the architectures of mihomo, sing-box, and Xray-core, and compiled into a single executable.

**[Version 1.0.0](docs/releases/1.0.0.md)** has been published as a source-first release, with full-tree builds, verification, and binary packaging running on dedicated Linux workers.

## Key Features & Current Scope

- **Unified Client/Server Core & 23 Protocol Modules**: Includes VLESS, VMess, Trojan, Shadowsocks, SS2022, SSR, AnyTLS, ShadowTLS, Snell, TUIC, Hysteria v1, Hysteria2, ShadowQUIC, Mieru, Naive, TrustTunnel, Sudoku, SOCKS, HTTP, SSH, Gost Relay, Tor, and WireGuard as modular crates selectable via Cargo features.
- **Independent Nodes & Shared Outbound Dispatcher**: IPv4 and IPv6 inbound nodes maintain separate listeners, authentication scopes, and quotas while sharing a single runtime outbound dispatcher (`EgressRuntime`). Local egress follows per-node `ipv4-only`, `ipv6-only`, or `dual-stack` (IPv4-preferred) policy, while remote proxy outbounds pass original targets through without local website DNS resolution.
- **Multi-User Accounts & Telemetry**: Separates management accounts (`AccountSpec`) from protocol-native credentials (`native_credential`) and provides single-boundary payload accounting, bounded in-memory flow records (`Telemetry`), optional SQLite usage/bandwidth/access history, and read-only `history` queries.
- **Remaining Work**: Automatic CLI wiring and cross-process device-level CF WARP sharing, independent DNS/error history, complete bilingual user documentation, and six additional tunnel/overlay endpoints (see [STATUS.md](STATUS.md)). Protocol test results apply to their recorded inputs; the next release still requires validation of its final input.

## Quick Start (Configuration Schema v2)

Target build baseline: **Rust 1.99.1 on Linux x86_64**.

```sh
cargo build --locked --release -p kerlico
cargo run --locked -p kerlico -- modules
cargo run --locked -p kerlico -- check -c examples/config-v2-minimal.json
```

- Configuration schema **v2** is required; see the [Configuration v2 Migration Guide](docs/config-v2-migration.en.md).
- Keep real deployment credentials in Git-ignored private files rather than committed examples.

Use `kerlico --lang en ...` for English or `kerlico --lang zh-CN ...` for Simplified Chinese. The CLI otherwise selects its language from `LC_ALL`, `LC_MESSAGES`, then `LANG`. Help, parser errors, configuration results, and runtime diagnostics use that language; module identifiers and structured data stay stable. See [CLI languages](docs/localization.en.md) for examples and diagnostic coverage boundaries.

## License

Original code is licensed under [GPL-3.0-only](LICENSE). Third-party and vendored materials retain their original licenses and notices (see [docs/licensing.md](docs/licensing.md)).
