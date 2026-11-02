# Configuration v2 migration

The migration source accepts v2 only. This implementation wave has not been built or tested as a complete tree. Existing v1 files remain historical evidence, not runnable configurations for this tree.

The [minimal v2 configuration](../examples/config-v2-minimal.json) uses a local TCP forward without management accounts. The operating system assigns its listening port. Its target is a separately started loopback service on port 18080. The example has not yet been checked or run with this migration tree.

1. Set version to 2. Keep named outbounds. Multiple nodes referring to the same tag share one runtime instance.
2. Read a management password from standard input with account-new and save its JSON output under accounts. Keep user_id stable. The default username includes its UUID suffix.
3. Move native inbound authentication material from options to members[].native_credential. Bind each member to an explicit management user_id. Transport, certificates, protection secrets and resource limits remain protocol options.
4. Configure IPv4 and IPv6 listeners independently. Reusing a management account requires explicit membership at each node, and native credentials remain separate.
5. Set mode to ipv4-only, ipv6-only or dual-stack for locally governed target paths. Remote proxy paths retain the original target and never resolve website names locally.
6. Run check for pure validation, then validate the complete role and combination matrix in a dedicated worker workspace. Check does not deploy WARP or modify the host network.

Management passwords use Argon2id PHC verifiers and do not become protocol credentials. Native wire formats remain unchanged. See the native credential mapping in the [Chinese migration guide](config-v2-migration.md).

Unauthenticated legacy modes remain explicitly local and never acquire a fabricated management user. SSH and Gost Relay currently provide outbound roles only; their remote credentials stay in the named outbound configuration.

The current telemetry API reports unique payload accounting and bounded in-memory records. Persistent history, bandwidth history, retention settings and automatic WARP family completion are still incomplete. Configuration v2 does not imply that release requirements have passed.


XDRIVE storage no longer reads HTTP_PROXY, HTTPS_PROXY or NO_PROXY implicitly. It connects only to the explicitly configured storage URL and does not add an implicit proxy chain. This is an accepted configuration behavior change. The previous pinned reqwest graph did not include HTTP/2. The owned HTTP/1 client preserves the previously used path, with URL/query handling, template headers, JSON/XML, OAuth and request deadlines requiring current-tree validation.
