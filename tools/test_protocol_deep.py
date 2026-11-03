#!/usr/bin/env python3
"""深度测试工具自身的测试：探针对真实 socket 和受控故障目标给出预期度量，判定把度量分到预期的类。

不需要 kerlico，也不需要 worker。
"""
import json
import socket
import time
import unittest

import interop_cross_host as xh
import protocol_deep as deep

DIRECT = {"kind": "direct"}
LOCAL = "127.0.0.1"
CAPS = deep.REFERENCE_CAPS


class TargetCase(unittest.TestCase):
    def target(self, **options):
        target = deep.DeepTarget(**options)
        self.addCleanup(target.stop)
        return target


class DuplexTest(TargetCase):
    def test_intact_echo_passes(self):
        target = self.target()
        result = deep.duplex_probe(DIRECT, LOCAL, target.port, 1 << 21, stall=5)
        self.assertEqual(deep.judge_duplex(result, CAPS).verdict, deep.PASS, result)
        self.assertEqual((result["sent"], result["received"]), (1 << 21, 1 << 21))

    def test_truncated_echo_is_eof_at_the_cut(self):
        target = self.target(tcp_mode="truncate", arg=4096)
        result = deep.duplex_probe(DIRECT, LOCAL, target.port, 1 << 16, stall=5)
        judgement = deep.judge_duplex(result, CAPS)
        self.assertEqual((judgement.verdict, judgement.klass, result["received"]), (deep.FAIL, "eof", 4096))

    def test_corrupt_byte_is_digest_with_its_offset(self):
        target = self.target(tcp_mode="corrupt", arg=12345)
        result = deep.duplex_probe(DIRECT, LOCAL, target.port, 1 << 16, stall=5)
        self.assertEqual((result["klass"], result["first_diff"]), ("digest", 12345))

    def test_silent_target_is_stall_within_the_window(self):
        target = self.target(tcp_mode="stall_after", arg=1024)
        started = time.monotonic()
        result = deep.duplex_probe(DIRECT, LOCAL, target.port, 1 << 16, stall=0.5)
        self.assertLess(time.monotonic() - started, 5)
        self.assertEqual((result["klass"], result["received"]), ("stall", 1024))

    def test_slow_but_moving_stream_outlasting_the_stall_window_passes(self):
        """上一轮的教训：发送和接收共用超时时，慢流被判成断流。"""
        target = self.target(tcp_mode="throttle", arg=1 << 19, rcvbuf=1 << 14)
        result = deep.duplex_probe(DIRECT, LOCAL, target.port, 3 << 20, stall=1.0, sndbuf=1 << 14)
        self.assertTrue(result["ok"], result)
        self.assertTrue(deep.sender_outlasted_stall(result), f"发送没有被阻塞过停滞窗口，这条用例证明不了什么：{result}")

    def test_refused_connection_is_a_connect_class(self):
        target = self.target()
        port = target.port
        target.stop()
        time.sleep(0.6)
        result = deep.duplex_probe(DIRECT, LOCAL, port, 1024, stall=1)
        self.assertEqual(result["klass"], "connect_refused")

    def test_connections_carry_distinct_payloads(self):
        self.assertNotEqual(deep.pattern(1024, 1), deep.pattern(1024, 2))
        self.assertEqual(deep.pattern(1024, 1), deep.pattern(1024, 1))


class HalfCloseTest(TargetCase):
    def test_full_response_and_eof_after_write_close(self):
        target = self.target()
        result = deep.half_close_probe(DIRECT, LOCAL, target.port, [1, 65536, 1 << 20], stall=5, eof_wait=5)
        self.assertEqual(deep.judge_half_close(result, CAPS).verdict, deep.PASS, result)
        self.assertTrue(all(item["eof_seen"] and item["write_closed"] for item in result["rounds"]))

    def test_missing_eof_fails_only_when_the_outbound_promises_it(self):
        target = self.target(tcp_mode="no_eof")
        result = deep.half_close_probe(DIRECT, LOCAL, target.port, [1024], stall=5, eof_wait=0.5)
        self.assertEqual(result["rounds"][0]["klass"], "no_eof")
        self.assertEqual(deep.judge_half_close(result, CAPS).klass, "no_eof")
        without = deep.Caps(tcp_eof=False)
        self.assertEqual(deep.judge_half_close(result, without).verdict, deep.PASS)

    def test_truncated_response_is_eof_even_without_tcp_eof_capability(self):
        target = self.target(tcp_mode="truncate", arg=100)
        result = deep.half_close_probe(DIRECT, LOCAL, target.port, [1024], stall=5, eof_wait=1)
        self.assertEqual(deep.judge_half_close(result, deep.Caps(tcp_eof=False)).klass, "eof")


class EmptyTest(TargetCase):
    def test_empty_connections_end_and_entry_keeps_working(self):
        target = self.target()
        result = deep.empty_probe(DIRECT, LOCAL, target.port, rounds=3, eof_wait=3, stall=3)
        self.assertEqual(deep.judge_empty(result, CAPS).verdict, deep.PASS, result)

    def test_target_that_never_closes_is_no_eof(self):
        target = self.target(tcp_mode="no_eof")
        result = deep.empty_probe(DIRECT, LOCAL, target.port, rounds=1, eof_wait=0.3, stall=3)
        self.assertEqual(deep.judge_empty(result, CAPS).klass, "no_eof")


class BoundaryTest(TargetCase):
    def test_every_size_verified_and_only_oversize_fail(self):
        target = self.target(tcp_mode="truncate", arg=2000)
        result = deep.boundary_probe(DIRECT, LOCAL, target.port, [1, 2000, 2001, 4096], stall=2)
        self.assertEqual([item["size"] for item in result["failed"]], [2001, 4096])
        self.assertEqual(deep.judge_boundaries(result, CAPS).klass, "eof")


class ConcurrencyTest(TargetCase):
    def test_parallel_counts_exactly_the_failed_connections(self):
        target = self.target(tcp_mode="flaky", arg=8)
        result = deep.parallel_probe(DIRECT, LOCAL, target.port, conns=32, size=1 << 14, stall=5)
        self.assertEqual(result["failed"], 4, result)
        self.assertEqual(deep.judge_parallel(result, CAPS).klass, "conn_failures")

    def test_parallel_passes_on_healthy_target(self):
        target = self.target()
        result = deep.parallel_probe(DIRECT, LOCAL, target.port, conns=16, size=1 << 16, stall=5)
        self.assertEqual(deep.judge_parallel(result, CAPS).verdict, deep.PASS, result)

    def test_churn_counts_failures(self):
        target = self.target(tcp_mode="flaky", arg=10)
        result = deep.churn_probe(DIRECT, LOCAL, target.port, count=40, workers=4, size=64, stall=3)
        self.assertEqual(result["failed"], 4, result)
        self.assertEqual(deep.judge_churn(result, CAPS).klass, "conn_failures")

    def test_short_counts_failures(self):
        target = self.target(tcp_mode="flaky", arg=10)
        result = deep.short_probe(DIRECT, LOCAL, target.port, count=30, size=64, stall=3)
        self.assertEqual(result["failed"], 3, result)
        self.assertEqual(deep.judge_short(result, CAPS).klass, "conn_failures")


class IdleTest(TargetCase):
    def test_connection_surviving_idle_passes(self):
        target = self.target()
        result = deep.idle_probe(DIRECT, LOCAL, target.port, idle=0.2, size=1 << 16, stall=3)
        self.assertEqual(deep.judge_idle(result, CAPS).verdict, deep.PASS, result)

    def test_connection_closed_during_idle_fails(self):
        target = self.target(tcp_mode="idle_close", arg=0.2)
        result = deep.idle_probe(DIRECT, LOCAL, target.port, idle=0.6, size=1 << 16, stall=2)
        self.assertLess(result["closed_after"], 0.6)
        self.assertEqual(deep.judge_idle(result, CAPS).klass, "idle_closed")

    def test_closing_at_the_documented_limit_passes_elsewhere_fails(self):
        caps = deep.Caps(idle_limit=30.0)
        self.assertEqual(deep.judge_idle({"klass": "eof", "closed_after": 30.4}, caps).verdict, deep.PASS)
        self.assertEqual(deep.judge_idle({"klass": "eof", "closed_after": 12.0}, caps).klass, "idle_closed")
        self.assertEqual(deep.judge_idle({"klass": "eof", "closed_after": 30.4}, CAPS).klass, "idle_closed")

    def test_idle_limit_bands(self):
        base = {"klass": "", "limit": 10.0, "expect_upper": 40.0, "wait_max": 60}
        self.assertEqual(deep.judge_idle_limit({**base, "closed_after": 10.5}, CAPS).verdict, deep.PASS)
        self.assertEqual(deep.judge_idle_limit({**base, "closed_after": 2.0}, CAPS).klass, "idle_early")
        self.assertEqual(deep.judge_idle_limit({**base, "closed_after": 50.0}, CAPS).klass, "idle_late")
        self.assertEqual(deep.judge_idle_limit({**base, "closed_after": None}, CAPS).klass, "idle_not_enforced")

    def test_idle_limit_probe_sees_the_close(self):
        target = self.target(tcp_mode="idle_close", arg=0.5)
        result = deep.idle_limit_probe(DIRECT, LOCAL, target.port, wait_max=5, stall=2)
        self.assertIsNotNone(result["closed_after"])
        self.assertLess(result["closed_after"], 2)

    def test_idle_limit_probe_reports_no_close(self):
        target = self.target()
        result = deep.idle_limit_probe(DIRECT, LOCAL, target.port, wait_max=0.3, stall=2)
        self.assertIsNone(result["closed_after"])


class InflightTest(TargetCase):
    def wait(self, flow, predicate, budget=5):
        deadline = time.monotonic() + budget
        while time.monotonic() < deadline:
            if predicate(flow.status()):
                return flow.status()
            time.sleep(0.02)
        self.fail(f"等不到预期状态：{flow.status()}")

    def test_flow_progresses_then_reports_end_when_target_closes(self):
        target = self.target(tcp_mode="truncate", arg=1 << 17)
        flow = deep.Inflight(DIRECT, LOCAL, target.port)
        self.addCleanup(flow.halt.set)
        status = self.wait(flow, lambda item: item["ended"])
        self.assertEqual(status["klass"], "eof")
        self.assertEqual(status["received"], 1 << 17)

    def test_flow_does_not_end_while_target_is_healthy(self):
        target = self.target()
        flow = deep.Inflight(DIRECT, LOCAL, target.port)
        self.addCleanup(flow.halt.set)
        self.wait(flow, lambda item: item["received"] > 0)
        time.sleep(0.3)
        self.assertFalse(flow.status()["ended"])


class UdpTest(TargetCase):
    def route(self, target):
        return {"kind": "direct", "host": LOCAL, "port": target.port}

    def test_one_byte_and_large_sizes(self):
        target = self.target()
        result = deep.udp_sizes_probe(self.route(target), [1, 64, 1200, 60000], count=2, wait=0.5, tries=2)
        self.assertTrue(all(item["ok"] for item in result["rounds"]), result)

    def test_size_limit_reports_exact_sizes(self):
        target = self.target(udp_mode="limit", arg=100)
        result = deep.udp_sizes_probe(self.route(target), [64, 1200], count=2, wait=0.1, tries=2)
        self.assertEqual([item["ok"] for item in result["rounds"]], [True, False])

    def burst(self, target):
        return deep.udp_burst_probe(self.route(target), count=200, size=128, pps=4000, drain=0.3)

    def test_burst_counts_loss_duplicates_and_reorder(self):
        self.assertEqual(self.burst(self.target())["lost"], 0)
        self.assertEqual(self.burst(self.target(udp_mode="drop_half"))["lost"], 100)
        self.assertEqual(self.burst(self.target(udp_mode="dup"))["duplicates"], 200)
        self.assertGreater(self.burst(self.target(udp_mode="reorder"))["reordered"], 50)


def rounds(path, bare=None, loop=None):
    return {"path": path, "bare": bare if bare is not None else [{"size": 64, "ok": True}], "loop": loop or []}


class UdpSizeJudgeTest(unittest.TestCase):
    def test_path_limit_is_not_a_protocol_failure(self):
        metrics = rounds([{"size": 64, "ok": True}, {"size": 1400, "ok": False, "klass": "no_reply"}], loop=[{"size": 1400, "ok": True}])
        judgement = deep.judge_udp_sizes(metrics, CAPS)
        self.assertEqual(judgement.verdict, deep.PASS)
        self.assertIn("路径受限 1400", judgement.reason)

    def test_protocol_limit_above_1200_is_reported_not_failed(self):
        metrics = rounds([{"size": 64, "ok": True}, {"size": 8192, "ok": False, "klass": "no_reply"}], loop=[{"size": 8192, "ok": False}])
        judgement = deep.judge_udp_sizes(metrics, CAPS)
        self.assertEqual(judgement.verdict, deep.PASS)
        self.assertIn("回环也不通 8192", judgement.reason)

    def test_failure_at_or_below_1200_on_both_paths_fails(self):
        metrics = rounds([{"size": 1200, "ok": False, "klass": "no_reply"}], loop=[{"size": 1200, "ok": False}])
        self.assertEqual(deep.judge_udp_sizes(metrics, CAPS).klass, "udp_below_1200")

    def test_small_packet_failure_fails_even_if_loopback_passes(self):
        metrics = rounds([{"size": 64, "ok": False, "klass": "no_reply"}], loop=[{"size": 64, "ok": True}])
        self.assertEqual(deep.judge_udp_sizes(metrics, CAPS).klass, "udp_small_fail")

    def test_dead_bare_path_is_tool_error(self):
        metrics = rounds([{"size": 64, "ok": False, "klass": "no_reply"}], bare=[{"size": 64, "ok": False}])
        self.assertEqual(deep.judge_udp_sizes(metrics, CAPS).verdict, deep.TOOL_ERROR)


def burst(**extra):
    return {"received": 1000, "lost": 0, "loss": 0.0, "duplicates": 0, "reordered": 0, "corrupt": 0, **extra}


class UdpBurstJudgeTest(unittest.TestCase):
    def test_excess_loss_on_loopback_too_fails(self):
        metrics = {"bare": burst(), "path": burst(received=500, loss=0.5), "loop": burst(received=500, loss=0.5)}
        self.assertEqual(deep.judge_udp_burst(metrics, CAPS).klass, "udp_loss")

    def test_excess_loss_only_with_rtt_is_its_own_class(self):
        metrics = {"bare": burst(hops=[0.0, 0.0]), "path": burst(received=500, loss=0.5), "loop": burst()}
        self.assertEqual(deep.judge_udp_burst(metrics, CAPS).klass, "udp_loss_with_rtt")

    def test_loss_within_tolerance_of_the_hop_baseline_passes(self):
        metrics = {"bare": burst(loss=0.3, hops=[0.3, 0.0]), "path": burst(received=500, loss=0.5), "loop": None}
        self.assertEqual(deep.judge_udp_burst(metrics, CAPS).verdict, deep.PASS)

    def test_duplicates_beyond_baseline_fail(self):
        metrics = {"bare": burst(), "path": burst(duplicates=3), "loop": None}
        self.assertEqual(deep.judge_udp_burst(metrics, CAPS).klass, "udp_dup")

    def test_dead_bare_path_is_tool_error(self):
        metrics = {"bare": burst(received=0, loss=1.0), "path": burst(), "loop": None}
        self.assertEqual(deep.judge_udp_burst(metrics, CAPS).verdict, deep.TOOL_ERROR)


class UdpMultiJudgeTest(unittest.TestCase):
    def test_unsupported_association_is_na(self):
        self.assertEqual(deep.judge_udp_multi({"klass": "socks_reply_7"}, CAPS).verdict, deep.NA)

    def test_classes(self):
        self.assertEqual(deep.judge_udp_multi({"klass": "", "ok": 20}, CAPS).verdict, deep.PASS)
        self.assertEqual(deep.judge_udp_multi({"klass": "", "ok": 10, "cross_talk": 10}, CAPS).klass, "cross_talk")
        self.assertEqual(deep.judge_udp_multi({"klass": "", "ok": 19, "wrong_source": 1}, CAPS).klass, "wrong_source")
        self.assertEqual(deep.judge_udp_multi({"klass": "", "ok": 19, "loss": 1}, CAPS).klass, "udp_loss")


def auth_metrics(**extra):
    ok = {"ok": True, "klass": ""}
    return {"before": ok, "after": ok, "attempts": [{"ok": False, "klass": "eof"}], "flow_progress": True, "flow_during": {"ended": False, "klass": ""}, "wrong_target": {"conns": 0, "bytes_in": 0}, "node": True, **extra}


class AuthJudgeTest(unittest.TestCase):
    def test_rejected_credential_passes(self):
        self.assertEqual(deep.judge_auth(auth_metrics(), CAPS).verdict, deep.PASS)

    def test_any_contact_with_the_target_is_a_bypass_even_if_echo_failed(self):
        self.assertEqual(deep.judge_auth(auth_metrics(wrong_target={"conns": 1, "bytes_in": 0}), CAPS).klass, "auth_bypass")

    def test_node_exit_or_collateral_damage_fails(self):
        self.assertEqual(deep.judge_auth(auth_metrics(node=False), CAPS).klass, "node_died")
        self.assertEqual(deep.judge_auth(auth_metrics(after={"ok": False, "klass": "eof"}), CAPS).klass, "good_user_failed")
        self.assertEqual(deep.judge_auth(auth_metrics(flow_during={"ended": True, "klass": "eof"}), CAPS).klass, "good_user_failed")


class RecoveryJudgeTest(unittest.TestCase):
    def metrics(self, **extra):
        return {"flow_progress": True, "flow": {"klass": "eof"}, "time_to_error": 1.0, "error_budget": 150, "new_conn_after": 2.0, "attempts": 1, "last_klass": "", "sent": 1, "received": 1, **extra}

    def test_classes(self):
        self.assertEqual(deep.judge_recovery(self.metrics(), CAPS).verdict, deep.PASS)
        self.assertEqual(deep.judge_recovery(self.metrics(time_to_error=None), CAPS).klass, "hang")
        self.assertEqual(deep.judge_recovery(self.metrics(new_conn_after=None), CAPS).klass, "no_recovery")
        self.assertEqual(deep.judge_recovery(self.metrics(flow_progress=False), CAPS).klass, "no_flow")


class UnreachableJudgeTest(unittest.TestCase):
    def metrics(self, **extra):
        failed = {"ok": False, "klass": "socks_reply_5"}
        return {"closed": failed, "via_canary": failed, "canary": {"conns": 0}, "followup": {"ok": True, "klass": ""}, "node_down": failed, "node_down_target": {"conns": 0}, "stall": 45, **extra}

    def test_clean_failure_passes(self):
        self.assertEqual(deep.judge_unreachable(self.metrics(), CAPS).verdict, deep.PASS)

    def test_any_direct_contact_is_fallback(self):
        self.assertEqual(deep.judge_unreachable(self.metrics(canary={"conns": 1}), CAPS).klass, "fallback_direct")
        self.assertEqual(deep.judge_unreachable(self.metrics(node_down_target={"conns": 1}), CAPS).klass, "fallback_direct")

    def test_silence_is_hang(self):
        hung = {"ok": False, "klass": "stall"}
        self.assertEqual(deep.judge_unreachable(self.metrics(closed=hung), CAPS).klass, "hang")
        self.assertEqual(deep.judge_unreachable(self.metrics(node_down=hung), CAPS).klass, "hang")


class WeakJudgeTest(unittest.TestCase):
    def test_completed_transfer_reports_ratio_to_kernel(self):
        judgement = deep.judge_weak({"ok": True, "mib_s": 1.0, "kernel_mib_s": 4.0, "kernel_ok": True, "longest_gap": 1}, CAPS)
        self.assertEqual(judgement.verdict, deep.PASS)
        self.assertIn("0.25", judgement.reason)

    def test_stall_fails_setup_problem_is_tool_error(self):
        self.assertEqual(deep.judge_weak({"ok": False, "klass": "stall", "error": "stall@1", "kernel_ok": True}, CAPS).klass, "stall")
        self.assertEqual(deep.judge_weak({"ok": False, "klass": "setup", "error": "x", "kernel_ok": True}, CAPS).verdict, deep.TOOL_ERROR)

    def test_failed_kernel_baseline_is_tool_error(self):
        self.assertEqual(deep.judge_weak({"ok": False, "klass": "eof", "kernel_ok": False}, CAPS).verdict, deep.TOOL_ERROR)


def proc(fds=20, threads=8, rss=20000):
    return {"alive": True, "fds": fds, "threads": threads, "rss_kib": rss}


class ResourceJudgeTest(unittest.TestCase):
    def metrics(self, first=None, last=None, **extra):
        base = {"node": proc(), "client": proc()}
        first = first or {"node": proc(), "client": proc()}
        last = last or first
        return {"warm_failed": 0, "base": base, "samples": [first, {"settled_after": 3.0, **last}], "storms": [{"parallel_failed": 0, "short_failed": 0}], **extra}

    def test_back_to_baseline_passes(self):
        self.assertEqual(deep.judge_resources(self.metrics(), CAPS).verdict, deep.PASS)

    def test_allocator_high_water_is_not_a_leak_but_a_trend_is(self):
        high = {"node": proc(rss=200000), "client": proc()}
        self.assertEqual(deep.judge_resources(self.metrics(first=high), CAPS).verdict, deep.PASS)
        grown = {"node": proc(rss=300000), "client": proc()}
        self.assertEqual(deep.judge_resources(self.metrics(first=high, last=grown), CAPS).klass, "rss_growth")

    def test_each_leak_kind_has_its_class(self):
        self.assertEqual(deep.judge_resources(self.metrics(last={"node": proc(fds=100), "client": proc()}), CAPS).klass, "fd_leak")
        self.assertEqual(deep.judge_resources(self.metrics(last={"node": proc(threads=40), "client": proc()}), CAPS).klass, "thread_leak")
        self.assertEqual(deep.judge_resources(self.metrics(last={"node": {"alive": False}, "client": proc()}), CAPS).klass, "process_died")
        self.assertEqual(deep.judge_resources(self.metrics(last={"node": proc(), "client": proc(), "active_flows": 3}), CAPS).klass, "flows_leak")


class ExitJudgeTest(unittest.TestCase):
    def role(self, **extra):
        return {"rc": 0, "elapsed": 1, "flow_progress": True, "flow_ended_after": 0.5, "log": "", **extra}

    def test_classes(self):
        self.assertEqual(deep.judge_exit({"budget": 10, "client": self.role(), "node": self.role()}, CAPS).verdict, deep.PASS)
        self.assertEqual(deep.judge_exit({"budget": 10, "client": self.role(rc="killed"), "node": self.role()}, CAPS).klass, "exit_not_clean")
        self.assertEqual(deep.judge_exit({"budget": 10, "client": self.role(), "node": self.role(rc=1)}, CAPS).klass, "exit_not_clean")
        self.assertEqual(deep.judge_exit({"budget": 10, "client": self.role(), "node": self.role(flow_ended_after=None)}, CAPS).klass, "flow_hang")


class AccountingJudgeTest(unittest.TestCase):
    def metrics(self, **extra):
        usage = lambda size: {"upload_bytes": size, "download_bytes": size}
        return {"transfers": {"good": {"ok": True, "klass": ""}, "member1": {"ok": True, "klass": ""}}, "expected": {"a": 300, "b": 100}, "users": {"a": usage(300), "b": usage(100)}, "engine": usage(400), "active_flows": 0, **extra}

    def test_exact_counts_pass(self):
        self.assertEqual(deep.judge_accounting(self.metrics(), CAPS).verdict, deep.PASS)

    def test_one_byte_off_fails(self):
        users = {"a": {"upload_bytes": 301, "download_bytes": 300}, "b": {"upload_bytes": 100, "download_bytes": 100}}
        self.assertEqual(deep.judge_accounting(self.metrics(users=users), CAPS).klass, "usage_mismatch")

    def test_attribution_to_wrong_user_fails(self):
        self.assertEqual(deep.judge_accounting(self.metrics(expected={"a": 100, "b": 300}), CAPS).klass, "usage_mismatch")

    def test_engine_double_count_fails(self):
        engine = {"upload_bytes": 800, "download_bytes": 800}
        self.assertEqual(deep.judge_accounting(self.metrics(engine=engine), CAPS).klass, "usage_mismatch")


class ControlMechanismTest(unittest.TestCase):
    def control(self, expect=deep.FAIL, classes=("eof",)):
        return deep.Control("integrity_duplex_32m", "x", "bare", {}, expect, classes)

    def test_control_that_never_reached_its_premise_does_not_count(self):
        control = deep.Control("integrity_duplex_32m", "x", "bare", {}, deep.PASS, premise=deep.sender_outlasted_stall)
        self.assertTrue(deep.control_matches(control, deep.good(), {"send_elapsed": 4.0, "stall": 3.0}))
        self.assertFalse(deep.control_matches(control, deep.good(), {"send_elapsed": 1.0, "stall": 3.0}))

    def test_failure_of_the_wrong_class_does_not_validate_a_bad_control(self):
        self.assertTrue(deep.control_matches(self.control(), deep.bad("eof")))
        self.assertFalse(deep.control_matches(self.control(), deep.bad("connect_refused")))
        self.assertFalse(deep.control_matches(self.control(), deep.good()))

    def test_good_control_must_pass(self):
        self.assertTrue(deep.control_matches(self.control(deep.PASS, ()), deep.good()))
        self.assertFalse(deep.control_matches(self.control(deep.PASS, ()), deep.bad("eof")))
        self.assertFalse(deep.control_matches(self.control(deep.PASS, ()), deep.Judgement(deep.TOOL_ERROR)))

    def test_mismatched_control_downgrades_that_scenario_only(self):
        untrusted = deep.untrusted_scenarios([{"scenario": "a", "matched": False}, {"scenario": "b", "matched": True}])
        self.assertEqual(untrusted, ["a"])
        downgraded = deep.apply_trust({"scenario": "a", "verdict": deep.FAIL, "klass": "eof"}, set(untrusted))
        self.assertEqual((downgraded["verdict"], downgraded["klass"], downgraded["raw_verdict"]), (deep.TOOL_ERROR, "control_mismatch", deep.FAIL))
        kept = deep.apply_trust({"scenario": "b", "verdict": deep.FAIL, "klass": "eof"}, set(untrusted))
        self.assertEqual(kept["verdict"], deep.FAIL)

    def test_process_death_overrides_a_passing_probe(self):
        judgement = deep.apply_liveness(deep.good("ok"), {"node_alive": False, "client_alive": True})
        self.assertEqual(judgement.klass, "process_died")
        self.assertEqual(deep.apply_liveness(deep.good(), {"node_alive": True}).verdict, deep.PASS)

    def test_every_scenario_has_a_good_and_a_bad_control(self):
        for scenario in deep.SCENARIOS:
            controls = [item for item in deep.CONTROLS if item.scenario == scenario.name]
            self.assertTrue(any(item.expect == deep.PASS for item in controls), scenario.name)
            bad = [item for item in controls if item.expect == deep.FAIL]
            self.assertTrue(bad, scenario.name)
            self.assertTrue(all(item.expect_class for item in bad), scenario.name)

    def test_control_table_names_real_scenarios(self):
        self.assertTrue({item.scenario for item in deep.CONTROLS} <= set(deep.SCENARIO_BY_NAME))


class ApplicabilityTest(unittest.TestCase):
    def test_udp_scenarios_are_na_without_udp(self):
        caps = deep.Caps(udp=False)
        for name in ("udp_sizes", "udp_burst_1000", "udp_multi_target"):
            self.assertTrue(deep.SCENARIO_BY_NAME[name].applies(caps), name)
        self.assertIsNone(deep.SCENARIO_BY_NAME["integrity_duplex_32m"].applies(caps))

    def test_member_scenarios_follow_check_results(self):
        self.assertTrue(deep.SCENARIO_BY_NAME["accounting_two_users"].applies(deep.Caps(multi_member=False)))
        self.assertTrue(deep.SCENARIO_BY_NAME["auth_disabled_member"].applies(deep.Caps(disabled_member=False)))
        self.assertTrue(deep.SCENARIO_BY_NAME["weak_loss5"].applies(deep.Caps(netns=False)))


class GraftTest(unittest.TestCase):
    material = xh.Material("ca", "cert", "key")

    def test_second_member_differs_only_in_credentials(self):
        for carrier in xh.CARRIERS:
            spec = carrier.build(self.material)
            fresh = carrier.build(self.material)
            grafted = deep.graft_client(carrier, spec, fresh)
            original, text = json.dumps(spec.client), json.dumps(grafted)
            self.assertNotEqual(original, text, carrier.key)
            if carrier.protocol == "wireguard":
                self.assertEqual(grafted["peer"]["public_key"], spec.client["peer"]["public_key"])
                self.assertEqual(grafted["tunnel"]["private_key"], fresh.client["tunnel"]["private_key"])
                continue
            for key, value in spec.member.items():
                if isinstance(value, str) and value and value != fresh.member[key]:
                    self.assertNotIn(value, text, f"{carrier.key} 仍带旧凭据 {key}")
                    self.assertIn(fresh.member[key], text, f"{carrier.key} 没有新凭据 {key}")


class ListeningParseTest(unittest.TestCase):
    def test_parses_proc_net_lines(self):
        text = "  sl  local_address rem_address   st\n   0: 0100007F:7A69 00000000:0000 0A 0\n   1: 0100007F:1F90 00000000:0000 01 0\n"
        self.assertTrue(deep.parse_listening(text, "tcp", 0x7A69))
        self.assertFalse(deep.parse_listening(text, "tcp", 0x1F90), "ESTABLISHED 不算监听")
        self.assertTrue(deep.parse_listening(text, "udp", 0x1F90))
        self.assertFalse(deep.parse_listening(text, "tcp", 1))


class OverrideTest(unittest.TestCase):
    def test_parses_json_values(self):
        self.assertEqual(deep.parse_overrides(["udp_burst_1000.pps=100"]), {"udp_burst_1000": {"pps": 100}})

    def test_unknown_parameter_is_refused(self):
        with self.assertRaises(SystemExit):
            deep.parse_overrides(["udp_burst_1000.nope=1"])


class SelectTest(unittest.TestCase):
    def test_full_name_excludes_longer_carrier_names(self):
        self.assertEqual([item.key for item in deep.select_carriers("vless/raw-tls")], ["vless/raw-tls"])
        self.assertGreater(len(deep.select_carriers("vless")), 1)


class ScrubTest(unittest.TestCase):
    def test_addresses_and_machine_paths_are_removed(self):
        scrubber = xh.Scrubber()
        scrubber.add("198.51.100.7", "perf-01-mesh-v4")
        cleaned = deep.scrub({"log": "dial 198.51.100.7:443 from 203.0.113.9 at /srv/build/kerlico/deep/run/1/log"}, scrubber)["log"]
        self.assertIn("perf-01-mesh-v4", cleaned)
        self.assertNotIn("203.0.113.9", cleaned)
        self.assertNotIn("/srv/", cleaned)


def sample_document(**results):
    record = {"protocol": "ss2022", "carrier": "aes-128-gcm", "placement": xh.PLACEMENTS[0].label, "family": "ipv4", "scenario": "integrity_duplex_32m", "verdict": deep.FAIL, "klass": "eof", "reason": "已发 1，已收 0/2", "metrics": {}, "evidence": {"node_rc": 0, "node_log": "boom"}, "retest": {"verdict": deep.FAIL, "klass": "eof", "reason": ""}, **results}
    return {"binary_sha256": "0136fc5e" * 8, "tool_sha256": "ab" * 32, "network": "mesh", "controls": [{"scenario": "integrity_duplex_32m", "label": "bad-truncate", "expect": deep.FAIL, "expect_class": ["eof"], "verdict": deep.FAIL, "klass": "eof", "matched": True, "reason": ""}], "untrusted": [], "baselines": [], "results": [record]}


class ReportTest(unittest.TestCase):
    def test_groups_by_protocol_and_shows_evidence(self):
        text = deep.render_report(sample_document())
        self.assertIn("## ss2022", text)
        self.assertIn("| aes-128-gcm | P0 | integrity_duplex_32m | **fail** | eof |", text)
        self.assertIn("boom", text)
        self.assertIn("复测 fail", text)
        self.assertIn("bad-truncate", text)

    def test_refuses_to_render_addresses_or_paths(self):
        with self.assertRaises(ValueError):
            deep.render_report(sample_document(reason="dial 198.51.100.7"))
        with self.assertRaises(ValueError):
            deep.render_report(sample_document(reason="open /srv/build/kerlico/deep/x"))


class TargetTest(TargetCase):
    def test_target_counts_connections_and_bytes(self):
        target = self.target()
        deep.duplex_probe(DIRECT, LOCAL, target.port, 1000, stall=3)
        deep.duplex_probe(DIRECT, LOCAL, target.port, 500, stall=3)
        time.sleep(0.1)
        self.assertEqual(target.stats()["conns"], 2)
        self.assertEqual(target.stats()["bytes_in"], 1500)

    def test_loopback_only_target_is_not_reachable_from_outside_loopback(self):
        target = self.target(loopback_only=True)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            try:
                probe.connect(("192.0.2.1", 9))
                outward = probe.getsockname()[0]
            except OSError:
                self.skipTest("没有外向地址")
        if outward.startswith("127."):
            self.skipTest("没有外向地址")
        with self.assertRaises(OSError):
            socket.create_connection((outward, target.port), timeout=1).close()
        self.assertTrue(deep.duplex_probe(DIRECT, LOCAL, target.port, 64, stall=2)["ok"])


if __name__ == "__main__":
    unittest.main()
