# Configuration v2 Migration Guide

Updated: 2026-11-02 (Asia/Shanghai)

The current codebase requires **Configuration Schema v2 (JSON v2)**. Legacy v1 files must be migrated before use. Refer to [examples/config-v2-minimal.json](../examples/config-v2-minimal.json) for a minimal template and [docs/interfaces/config.md](interfaces/config.md) for the full specification.

## Migration Steps

1. **Update Schema Version & Shared Outbounds**: Set root `"version"` to `2`. Retain named `outbounds`; multiple inbound nodes referencing the same outbound `tag` share a single runtime instance.
2. **Create Management Accounts**: Run `kerlico account-new --prefix <name>` (reading the management password from `stdin`) and place the generated account object (`user_id`, `username`, and Argon2id PHC `password_hash`) under the root `accounts` array.
3. **Separate Node Members & Protocol-Native Credentials**:
   - Move per-user inbound authentication secrets from protocol `options` into `members[].native_credential`, binding each entry to a management `user_id`.
   - Keep transport settings, TLS certificates, outer protection secrets (such as ShadowTLS handshake passwords or SS2022 AES EIH `identity_key`), and resource limits under protocol `options`.
4. **Configure IPv4 and IPv6 Nodes Independently**: Declare `members` and protocol secrets separately for IPv4 and IPv6 listeners. A management `user_id` must be explicitly listed in each node's `members` to access that node, using distinct protocol secrets per node.
5. **Set Node Target Family Mode (`mode`)**: Configure `ipv4-only`, `ipv6-only`, or `dual-stack` (default) for locally governed target paths (`TargetPolicy::Local`). Remote proxy paths (`TargetPolicy::Remote`) pass the original target through without local website DNS resolution.
6. **Validate Configuration**: Run `kerlico check -c <config.json>` for pure compile-time validation without binding sockets or modifying host networking.

## Notes on Special Roles & Behavior Changes

- **Per-Protocol `native_credential` Shapes**: See the table in the [Chinese migration guide](config-v2-migration.md) for exact JSON shapes across all supported inbound protocols.
- **Outbound-Only Protocols (SSH / Gost Relay / Tor)**: Remote credentials and state directories remain inside each named `outbound.options`.
- **Unauthenticated Local Inbounds (`local_inbounds`)**: Loopback-only unauthenticated modes are configured under `local_inbounds` (`Source::Local`) without fabricating management users.
- **XDRIVE Storage Transport**: XDRIVE connects directly to the explicitly configured storage URL and no longer reads `HTTP_PROXY`, `HTTPS_PROXY`, or `NO_PROXY` environment variables implicitly.
