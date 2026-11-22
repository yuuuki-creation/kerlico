"""Measure WireGuard userspace and kernel peers on two private veth links."""
import argparse
from contextlib import ExitStack
import hashlib
import itertools
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from bench_openvpn import measure_after_warmup
from resources import Resources

CLIENT = ("ip", "netns", "exec", "wg-client")
ORIGIN = ("ip", "netns", "exec", "wg-origin")


def run(*args, input=None):
    return subprocess.check_output(args, input=input, text=True).strip()


def ip(*args, ns=None):
    return run("ip", *(("-n", ns) if ns else ()), *args)


def process(stack, log, *args):
    output = stack.enter_context(log.open("w"))
    child = subprocess.Popen(args, stdout=output, stderr=output)

    def close():
        if child.poll() is None:
            child.send_signal(signal.SIGTERM)
            try:
                child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()

    stack.callback(close)
    return child


def keys(temp, name):
    private = run("wg", "genkey")
    keyfile = temp / name
    keyfile.write_text(private + "\n")
    return private, run("wg", "pubkey", input=private + "\n"), keyfile


def wait_for_origin(child, log):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if child.poll() is not None:
            raise RuntimeError(log.read_text()[-1000:] or "iperf origin exited during startup")
        if run(*ORIGIN, "ss", "-H", "-ltn", "sport = :5201"):
            return
        time.sleep(0.025)
    raise TimeoutError("iperf origin did not listen on TCP port 5201")


def link_pair(name, address, peer, peer_address, ns):
    ip("link", "add", name, "type", "veth", "peer", "name", peer)
    ip("link", "set", peer, "netns", ns)
    ip("addr", "add", address, "dev", name)
    ip("addr", "add", peer_address, "dev", peer, ns=ns)
    ip("link", "set", name, "up")
    ip("link", "set", peer, "up", ns=ns)


def configure():
    ip("link", "set", "lo", "up")
    for ns in ("wg-client", "wg-origin"):
        ip("netns", "add", ns)
        ip("link", "set", "lo", "up", ns=ns)
    link_pair("underlay", "10.15.2.1/30", "underlay-peer", "10.15.2.2/30", "wg-client")
    link_pair("uplink", "10.15.1.1/30", "uplink-peer", "10.15.1.2/30", "wg-origin")
    ip("route", "add", "10.15.0.0/30", "via", "10.15.1.1", ns="wg-origin")
    ip("link", "add", "wg-peer", "type", "wireguard", ns="wg-client")
    ip("addr", "add", "10.15.0.2/30", "dev", "wg-peer", ns="wg-client")
    ip("link", "set", "wg-peer", "mtu", "1200", "up", ns="wg-client")
    ip("route", "add", "10.15.1.0/30", "dev", "wg-peer", ns="wg-client")
    run("sysctl", "-q", "-w", "net.ipv4.ip_forward=1")


def window(kind, binary, temp, logs, args, rate, payload, direction):
    with ExitStack() as stack:
        key, public, keyfile = keys(temp, "dut-key")
        _, peer_public, peer_file = keys(temp, "peer-key")
        for previous in run(*CLIENT, "wg", "show", "wg-peer", "peers").split():
            run(*CLIENT, "wg", "set", "wg-peer", "peer", previous, "remove")
        peer_endpoint = [] if args.initiator else ["endpoint","10.15.2.1:51820"]
        run(*CLIENT, "wg", "set", "wg-peer", "listen-port", "51821", "private-key", str(peer_file), "peer", public,
            *peer_endpoint, "allowed-ips", "10.15.0.1/32,10.15.1.0/30")
        child = None
        if kind == "kernel":
            ip("link", "add", "wg-dut", "type", "wireguard")
            stack.callback(ip, "link", "delete", "wg-dut")
        elif kind == "wireguard-go":
            child = process(stack, logs / "dut.log", "taskset", "-c", "1,2", binary, "-f", "wg-dut")
        elif kind == "client-tun":
            config = temp / "client.json"
            config.write_text(json.dumps({"protocol":"wireguard","peer":"10.15.2.2:51821",
                "settings":{"privateKey":key,"publicKey":peer_public,"allowedIPs":["10.15.0.2/32"],"mtu":1200}}))
            child = process(stack, logs/"dut.log","taskset","-c","1,2",args.client,"--tun","wg-dut",str(config))
        else:
            config = temp / "dut.json"
            options = {
                "listen": "10.15.2.1:51820", "privateKey": key, "tun": "wg-dut", "mtu": 1200,
                "peers": [{"publicKey": peer_public, "allowedIPs": ["10.15.0.2/32"]}],
            }
            if kind == "egress":
                options["egress"] = {"device": "underlay", "class": "1:2"}
                run("tc", "qdisc", "add", "dev", "underlay", "root", "handle", "1:", "prio", "bands", "2", "priomap", *(("0",) * 16))
                stack.callback(run, "tc", "qdisc", "del", "dev", "underlay", "root")
                run("tc", "qdisc", "add", "dev", "underlay", "parent", "1:2", "handle", "20:", "netem", "limit", "1024", "slot", "250us", "250us")
            config.write_text(json.dumps(options))
            child = process(stack, logs / "dut.log", "taskset", "-c", "1,2", binary, str(config))
        # A userspace TUN can appear before wireguard-go's control socket
        # accepts requests. Probe the same control path used by wg set.
        probe = (("wg", "show", "wg-dut", "public-key") if kind == "wireguard-go"
                 else ("ip", "link", "show", "wg-dut"))
        for _ in range(50):
            if child is not None and child.poll() is not None:
                raise RuntimeError((logs / "dut.log").read_text()[-1000:] or "device process exited")
            if subprocess.run(probe, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL).returncode == 0:
                break
            time.sleep(0.1)
        else:
            raise TimeoutError("wg-dut did not become ready in the private network namespace")
        if kind in ("kernel", "wireguard-go"):
            remote_endpoint = ["endpoint","10.15.2.2:51821"] if args.initiator else []
            run("wg", "set", "wg-dut", "private-key", str(keyfile), "listen-port", "51820",
                "peer", peer_public, *remote_endpoint, "allowed-ips", "10.15.0.2/32")
        ip("addr", "add", "10.15.0.1/30", "dev", "wg-dut")
        ip("link", "set", "wg-dut", "mtu", "1200", "up")
        if args.initiator:
            run("ping","-I","wg-dut","-c","1","-W","3","10.15.0.2")
        origin_log = logs / "origin.log"
        origin = process(stack, origin_log, *ORIGIN, "taskset", "-c", "0", args.iperf, "-s")
        run(*CLIENT, "ping", "-c", "1", "-W", "3", "10.15.1.2")
        wait_for_origin(origin, origin_log)
        streams = 8 if payload == "tcp" else 1
        command = [*CLIENT, "taskset", "-c", "3", args.iperf, "-c", "10.15.1.2",
                   "-P", str(streams), "-b", str(rate * 1000000 // streams), "-t", str(args.seconds),
                   "-O", str(args.warmup), "--json-stream", "--forceflush", "--pacing-timer", "1000"]
        if direction == "down":
            command.append("-R")
        if payload == "udp":
            command.extend(["-u", "-l", "1100"])
        pid = child.pid if child is not None else os.getpid()
        sample_file = "resources.csv" if child else "observer-and-guest.csv"
        with Resources(pid, logs / sample_file) as resources:
            before_mem = meminfo()
            result, _, wall, end = measure_after_warmup(command, pid, logs, args.seconds + args.warmup + 15)
            after_mem = meminfo()
        usage = resources.window(end - wall, end)
        received = result["end"]["sum_received"]
        size = received["bytes"]
        goodput = received["bits_per_second"] / 1e6
        if kind == "kernel":
            # The sampler uses our PID for its time anchor. This is not WireGuard process memory or CPU.
            usage = {k:v for k,v in usage.items() if k.startswith(("guest_", "sample", "start_", "end_"))}
        if kind == "egress":
            qdisc = json.loads(run("tc", "-s", "-j", "qdisc", "show", "dev", "underlay"))
            (logs / "qdisc.json").write_text(json.dumps(qdisc) + "\n")
            if not any(q.get("kind") == "netem" and q.get("packets",0)>0 for q in qdisc):
                raise ValueError("no packets counted in the egress queue")
        return dict(goodput_mbps=goodput, received_bytes=size, lost_percent=received.get("lost_percent"),
                    retransmits=result["end"].get("sum_sent",{}).get("retransmits"),
                    matched_load=abs(goodput/rate-1)<=.02 and (received.get("lost_percent") or 0)<=.1,
                    resources=usage, guest_mem_before_kib=before_mem, guest_mem_after_kib=after_mem)


def meminfo():
    fields = {"MemAvailable", "Slab", "SReclaimable", "SUnreclaim"}
    return {k:int(v.split()[0]) for k,v in (line.split(":",1) for line in Path("/proc/meminfo").read_text().splitlines()) if k in fields}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("output", type=Path)
    p.add_argument("--kerlico", required=True, type=Path)
    p.add_argument("--wireguard-go", required=True, type=Path)
    p.add_argument("--client", type=Path)
    p.add_argument("--initiator", action="store_true", help="compare local tunnel initiators against the same listening kernel peer")
    p.add_argument("--iperf", required=True, type=Path)
    p.add_argument("--rates", nargs="+", type=int, default=[20,50,100,200,500,1000])
    p.add_argument("--payloads", nargs="+", choices=["tcp","udp"], default=["tcp","udp"])
    p.add_argument("--directions", nargs="+", choices=["up","down"], default=["up","down"])
    p.add_argument("--implementations", nargs="+", choices=["kernel","wireguard-go","kerlico","egress","client-tun"],
                   default=["kernel","wireguard-go","kerlico","egress"])
    p.add_argument("--rounds", type=int, default=3)
    p.add_argument("--seconds", type=int, default=20)
    p.add_argument("--warmup", type=int, default=3)
    args = p.parse_args()
    if "client-tun" in args.implementations and not (args.initiator and args.client):
        p.error("client-tun requires --client and --initiator")
    if args.initiator and set(args.implementations)-{"kernel","wireguard-go","client-tun"}:
        p.error("--initiator compares kernel, wireguard-go and client-tun")
    if os.geteuid() != 0:
        p.error("Linux network namespace, TUN and WireGuard privileges required")
    if os.environ.get("WG_STUDY_NS") != "1":
        os.execvp("unshare", ["unshare", "--net", "--mount", "--propagation", "private",
                              "env", "WG_STUDY_NS=1", sys.executable, *sys.argv])
    assert os.readlink("/proc/self/ns/net") != os.readlink("/proc/1/ns/net")
    args.output.mkdir(parents=True, exist_ok=True)
    binary_paths = [args.kerlico,args.wireguard_go,args.iperf] + ([args.client] if args.client else [])
    metadata = dict(kernel=os.uname().release, mtu=1200, server_cpus="1,2", origin_cpu=0, client_cpu=3,
                    dut_initiates=args.initiator, dut_receives_tunnel_payload_on="up",
                    seconds=args.seconds, warmup=args.warmup, binaries={
                      p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in binary_paths})
    meta = args.output / "metadata.json"
    if meta.exists() and json.loads(meta.read_text()) != metadata:
        p.error("existing series has different inputs")
    meta.write_text(json.dumps(metadata, indent=2) + "\n")
    for mount in ("/run/netns","/run/wireguard"):
        Path(mount).mkdir(exist_ok=True)
        run("mount", "-t", "tmpfs", "-o", "mode=0700", "tmpfs", mount)
    configure()
    for payload,direction,rate,round_id in itertools.product(args.payloads,args.directions,args.rates,range(args.rounds)):
        names=args.implementations
        order=names[round_id%len(names):]+names[:round_id%len(names)]
        for kind in order:
            base=args.output / payload / direction / str(rate) / f"{round_id+1}-{kind}"
            if (base/"measured.json").exists():
                continue
            logs=base / f"attempt-{time.time_ns()}"
            logs.mkdir(parents=True)
            row=dict(implementation=kind,payload=payload,direction=direction,rate_mbps=rate,round=round_id+1)
            with tempfile.TemporaryDirectory() as private:
                try:
                    row.update(window(kind, args.wireguard_go if kind=="wireguard-go" else args.kerlico,
                                      Path(private),logs,args,rate,payload,direction),status="measured")
                except Exception as exc:
                    row.update(status="error",error=str(exc),matched_load=False)
                    (logs/"traceback.txt").write_text(traceback.format_exc())
            encoded=json.dumps(row)+"\n"
            (logs/"result.json").write_text(encoded)
            if row["status"]=="measured":
                (base/"measured.json").write_text(encoded)
            print(encoded,end="",flush=True)


if __name__=="__main__":
    main()
