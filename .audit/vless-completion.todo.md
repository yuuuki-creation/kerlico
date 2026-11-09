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
