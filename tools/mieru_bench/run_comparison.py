#!/usr/bin/env python3
"""在专用 Linux worker 的回环网络比较两个服务端，只管理本次拥有的进程。"""
import argparse
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time

from sample_process import sample_processes


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def events(path):
    result = []
    if path.exists():
        for line in path.read_text(errors='replace').splitlines():
            try:
                result.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return result


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def dump(path, value, uid=None):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2))
    path.chmod(0o600)
    if uid is not None:
        os.chown(path, uid, uid)


class Process:
    def __init__(self, command, folder, name, cpus, uid, extra=None):
        self.path = folder / (name + '.jsonl')
        self.log = self.path.open('wb')
        self.path.chmod(0o600)
        env = os.environ.copy()
        for key in ['MITA_CONFIG_FILE', 'MITA_CONFIG_JSON_FILE', 'MITA_UDS_PATH', 'MITA_INSECURE_UDS']:
            env.pop(key, None)
        env.update(extra or {})
        self.process = subprocess.Popen(['taskset', '-c', ','.join(map(str, cpus)), 'setpriv', '--reuid', str(uid), '--regid', str(uid), '--clear-groups', *command], cwd=folder, env=env, stdout=self.log, stderr=subprocess.STDOUT, start_new_session=True)

    def wait_event(self, name, timeout=20):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for event in events(self.path):
                if event.get('event') == name:
                    return event
            require(self.process.poll() is None, '任务进程提前退出，请查私有日志')
            time.sleep(0.02)
        raise RuntimeError('等待基准事件超时：' + name)

    def stop(self):
        if self.process.poll() is None:
            os.killpg(self.process.pid, signal.SIGTERM)
            try:
                self.process.wait(5)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait(5)
        self.log.close()


def wait_port(process, port):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        require(process.process.poll() is None, '代理服务端启动失败')
        try:
            with socket.create_connection(('127.0.0.1', port), 0.2):
                return
        except OSError:
            time.sleep(0.03)
    raise RuntimeError('代理端口未就绪')


def run_side(args, name, duration, cpus):
    folder = args.output / name
    folder.mkdir(mode=0o700)
    os.chown(folder, args.uid, args.uid)
    target_port, proxy_port = free_port(), free_port()
    while proxy_port == target_port:
        proxy_port = free_port()
    echo = server = load = None
    try:
        echo = Process([str(args.bench_bin), 'echo', '--listen', f'127.0.0.1:{target_port}'], folder, 'echo', cpus['echo'], args.uid, {'GOMAXPROCS': '1'})
        echo.wait_event('ready')
        direct = name == 'baseline'
        if not direct:
            config = folder / 'server.json'
            if name == 'kerlico':
                dump(config, {'warp': {'secretKey': 'invalid'}, 'inbounds': [{'tag': 'benchmark', 'protocol': 'mieru', 'listen': '127.0.0.1', 'port': proxy_port, 'outbound': 'native-v4', 'settings': {'transport': 'TCP', 'users': [{'email': 'test-user', 'username': 'test-user', 'password': 'test-password'}]}}]}, args.uid)
                server = Process([str(args.kerlico_bin), str(config)], folder, 'server', cpus['server'], args.uid)
            else:
                dump(config, {'listenIPAddress': '127.0.0.1', 'portBindings': [{'port': proxy_port, 'protocol': 'TCP'}], 'users': [{'name': 'test-user', 'password': 'test-password', 'allowPrivateIP': True, 'allowLoopbackIP': True}], 'mtu': 1400, 'loggingLevel': 'ERROR', 'trafficPattern': {'lowEntropy': {'mode': 'LOW_ENTROPY_MODE_OFF'}}}, args.uid)
                server = Process([str(args.mita_bin), 'run'], folder, 'server', cpus['server'], args.uid, {'GOMAXPROCS': '4', 'MITA_CONFIG_JSON_FILE': str(config), 'MITA_UDS_PATH': str(folder / 'mita.sock'), 'MITA_INSECURE_UDS': '1'})
            wait_port(server, proxy_port)
        warmup = 2 if direct else 5
        planned_ms = int(time.time() * 1000) + 10000
        command = [str(args.bench_bin), 'load', '--target', f'127.0.0.1:{target_port}', '--label', name, '--duration', f'{duration}s', '--warmup', f'{warmup}s', '--concurrency', '8', '--block-size', '32768', '--latency-size', '64', '--start-at', str(planned_ms), '--hold-after-final', '2s']
        if direct:
            command.append('--direct')
        else:
            command += ['--peer', f'127.0.0.1:{proxy_port}']
        load = Process(command, folder, 'client', cpus['client'], args.uid, {'GOMAXPROCS': '3'})
        ready = load.wait_event('ready', 30)
        owned = {'client': load.process.pid, 'echo': echo.process.pid}
        if server is not None:
            owned['server'] = server.process.pid
        resources = sample_processes(owned, ready['scheduled_start_unix_ns'], duration, folder / 'resources.json')
        code = load.process.wait(15)
        final = [e for e in events(load.path) if e.get('event') == 'final']
        require(code == 0 and len(final) == 1 and final[0].get('status') == 'pass', '负载未完整成功，不能比较部分吞吐')
        result = final[0]
        require(result['duration_seconds'] == duration and result['errors'] == result['timeouts'] == result['mismatches'] == 0, '计时或数据校验不合格')
        load.stop()
        load = None
        if server is not None:
            server.stop()
            server = None
        echo.stop()
        echo_events = [e for e in events(echo.path) if e.get('event') == 'final']
        require(len(echo_events) == 1, '回显服务缺少最终实际工作计数')
        echo_final = echo_events[0]
        completed = result['bulk_ack_bytes'] + result['probe_ack_bytes'] + result['late_ack_bytes']
        require(echo_final['counts']['read_bytes'] >= completed and echo_final['counts']['write_bytes'] >= completed, '实际回显字节不足，不能认定负载经过目标')
        require(echo_final['counts']['errors'] == 0, '目标回显存在错误')
        require(not Path('/var/lib/mita').exists(), '全局 mita 资料目录状态发生变化')
        summary = {'status': 'pass', 'label': name, 'measurement': result, 'resources': resources.get('summary', resources), 'echo_work': echo_final['counts'], 'byte_work_confirmed': True, 'global_mita_directory_unchanged': True}
        dump(folder / 'summary.json', summary)
        print(json.dumps({'event': 'side-complete', 'label': name, 'status': 'pass', 'mbps': result['effective_one_way_mbps']}, ensure_ascii=False), flush=True)
        return summary
    finally:
        for process in [load, server, echo]:
            if process is not None:
                process.stop()


def main():
    parser = argparse.ArgumentParser(description='仅在专用 worker 执行的一分钟固定配置比较')
    parser.add_argument('--kerlico-bin', type=Path, required=True)
    parser.add_argument('--mita-bin', type=Path, required=True)
    parser.add_argument('--bench-bin', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--uid', type=int, default=65534)
    parser.add_argument('--duration', type=int, default=60)
    args = parser.parse_args()
    require(sys.platform == 'linux' and os.geteuid() == 0 and args.uid != 0, '需要授权的 Linux worker 及可降权的调度账户')
    require(1 <= args.duration <= 600, '计时区间必须为1到600秒')
    require(not Path('/var/lib/mita').exists(), '此 worker 已有全局 mita 资料，选择其他专用 worker')
    for key in ['kerlico_bin', 'mita_bin', 'bench_bin']:
        value = getattr(args, key).resolve(strict=True)
        require(value.is_file(), '二进制路径无效')
        setattr(args, key, value)
    available = sorted(os.sched_getaffinity(0))
    require(len(available) >= 8, '需要至少8个可用逻辑CPU以隔离三个角色')
    cpus = {'server': available[:4], 'client': available[4:7], 'echo': available[7:8]}
    args.output = args.output.resolve()
    require(not args.output.exists(), '输出目录必须是新的独立目录')
    args.output.mkdir(mode=0o700)
    os.chown(args.output, args.uid, args.uid)
    result = {'status': 'fail', 'network': '同机回环', 'server_cpu_count': 4, 'client_cpu_count': 3, 'echo_cpu_count': 1, 'runs_per_side': 1, 'timed_seconds_per_side': args.duration, 'order': ['kerlico', 'mita'], 'cases': []}
    try:
        print(json.dumps({'event': 'begin', 'network': 'loopback', 'duration': args.duration}), flush=True)
        for name, duration in [('baseline', 5), ('kerlico', args.duration), ('mita', args.duration)]:
            result['cases'].append(run_side(args, name, duration, cpus))
            dump(args.output / 'comparison.json', result)
        result['status'] = 'pass'
    except BaseException as error:
        result['error_type'] = type(error).__name__
        result['error'] = str(error)
        raise
    finally:
        dump(args.output / 'comparison.json', result)
    print(json.dumps({'event': 'complete', 'status': result['status']}, ensure_ascii=False), flush=True)


if __name__ == '__main__':
    main()
