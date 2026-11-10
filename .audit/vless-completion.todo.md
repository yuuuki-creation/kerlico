# VLESS completion

- [x] Read the Principles section of poteto-mode.
- [x] Phase A: Frame — replace all legal VLESS combinations of the locally cached Xray baseline; no remote Git fetch/pull, no old branch, no mieru changes.
- [x] Phase B: Design the workflow — enumerate legal combinations and build a repeatable bidirectional Xray harness; classify unsupported and unverified separately.
- [ ] Phase C: Run the loop — reproduce each gap, implement one unit, test actual bytes against Xray.
- [ ] Transport: plain/TLS/REALITY carriers, full duplex, large transfers, HTTP versions, aliases and all supported Xray transports.
- [ ] VLESS: TCP/UDP/mux/reverse, Vision and UDP443, encryption modes/tickets/relay keys, authentication and fallback.
- [ ] Phase D: Keep the audit trail — append evidence at each checkpoint.
- [ ] Phase E: Verify and hand back — full matrix, independent review, leaf builds and dependency isolation.

Parallel coverage (swarm):
- [x] Frame: Xray source is the baseline; return evidenced gaps, not support claims.
- [x] Fan out: configuration matrix, crypto/Vision review, HTTP/2 implementation in isolated worktree.
- [ ] Aggregate: inspect each report and diff; run tests from the root snapshot.
- [ ] Report: distinguish verified, failed and absent combinations.

skip: architect design arena for initial mechanical fixes; no new ownership or architecture decision is being made.

Throughput checkpoint: the existing suite passes on the worker but covers mostly small self-roundtrips. Invest first in a matrix harness; do not infer interoperability from unit-test counts.

Advanced phase (explicitly confirmed by user):
- [x] Implement ordered TCP/UDP final masks; current root behavior matrix and carrier-owned Realm/XDNS callbacks still need final rerun.
- [x] Import TLS1.0/1.1, ClientHello fingerprints, ECH, certificate/root policies; final role matrix remains.
- [ ] Finish REALITY target flight reuse, Unix targets, spider and rate-limit role integration.
- [x] Implement KCP and QUIC settings; [ ] finish XHTTP server h2Params and final socket/gRPC/WebSocket/H2 matrix.
- [x] Implement Hysteria masquerade and XHTTP/XDrive XMUX; [ ] reusable outbound Mux and cross-carrier XUDP GlobalID.
- [ ] Reverse bridge configuration within node/outbound architecture.
- [ ] Final source review, current-root official wire matrix, separate leaf builds.

2026-11-09 core review found reverse user revocation and H1 chunk partial-write defects; patches integrated, behavior regressions pending.
2026-11-10 local checkpoint: 15/15 VPS carrier flows and 210 library tests passed. Pinned Xray matrix on an earlier integrated snapshot was 353/354; the sole failure remains the documented plain HTTPUpgrade early-data peer bug. Work continues on the items above; this checkpoint is not full-replacement completion.

Session 2026-11-10 (pickup, Claude):
- [x] Session pickup: prior trail read; resume point is the unchecked Advanced-phase items and Phase C/D/E.
- [x] Rebuild worker: perf-01 toolchain reinstalled after the 2026-11-10 worker wipe; pinned Xray 26.10.31 a4a3dff rebuilt from reference source.
- [x] Baseline on ce51460: lib, vless_flow, official matrix with control, leaf builds.
- [x] Client leaf: local SOCKS5/HTTP entry for VLESS sharing one front-end with mieru (merged, 18/18 against Xray).
- [x] REALITY target/Unix/xver/limits, XHTTP h2Params/XMUX, Mux reuse/GlobalID/UDP443/reverse bridge, sockopt, UDP size rules: merged unit by unit. REALITY camouflage (R2) stopped by a safety check; left to the user.
- [x] Final: full matrix on final snapshot (456/456 twice on d631f25), independent review, separate leaf builds, vless.md updated.
Rule from user 2026-11-10: no compiling or testing on the local machine; all builds and tests run on the worker. Worker toolchains stay installed after use.
- [x] Independent review of ce51460..114f21b; findings fixed in unit F2 (merged a6e3af8).
- [x] Unit F3: one Mux uplink for every Mux carrier (merged c6f1cb5).
- [x] Unit F4: TLS server group choice so Xray `randomized` fingerprints never get a HelloRetryRequest (merged; deliberately more lenient than Go, which retries and fails with uTLS too).
- [x] Unit F5: VLESS response header leaves with the first downlink bytes, as Xray's SetFlushNext (merged d631f25).
- [x] User decisions 2026-11-11: REALITY key_share and the Unix-target exception aligned with Xray; TLS group choice stays more lenient than Go. REALITY camouflage (R2) stays undone: a safety check stopped it.
- [x] Follow-up outside VLESS: intermittent mieru 02-rust-to-official UDP order failure was the test fixture; fixed and merged (539b8c3).
