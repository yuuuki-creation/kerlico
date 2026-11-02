# kerlico

[简体中文](README.md)

Version 1.0.0 is a source-first release requested before further testing. It does not certify that this tree builds or passes its complete test suite. Linux binaries will be added only after a corresponding build exists. See the [release notes](docs/releases/1.0.0.md).

The Rust codebase uses one executable for client and server roles. It contains 23 protocol modules, including newly written native Tor TCP outbound and WireGuard client/server code. Their presence does not establish interoperability. Named outbounds share one dispatcher; nodes retain separate authentication and cancellation scopes.

Automatic WARP provisioning, durable usage/access and bandwidth history, six further tunnel/overlay endpoints, and complete CLI localization remain unfinished. The latest development SSR run passed 191 of 192 checks. Earlier results apply only to their recorded inputs.

The intended environment is Rust 1.99.1 on Linux x86_64. These are instructions for the build after publication, not a successful release validation claim.

```sh
cargo build --locked --release -p kerlico
cargo run --locked -p kerlico -- modules
cargo run --locked -p kerlico -- check -c examples/local-forward-v2.json
```

Configuration schema 2 is required; older examples are not all migrated. Keep actual credentials in ignored private files. Runtime messages currently remain primarily Chinese.

Original code uses [GPL-3.0-only](LICENSE). Vendored dependencies retain their original licenses and notices.
