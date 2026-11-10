#!/usr/bin/env python3
"""在专用 worker 剖析自己的 Rust 服务端进程，不把带剖析开销的运行计作性能结果。"""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys

from run_comparison import Process, dump, events, free_port, require, wait_port


def stop_profiler(process):
    if process is not None and process.poll() is None:
        process.send_signal(signal.SIGINT)
        try:
            process.wait(10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server-bin', type=Path, required=True)
    parser.add_argument('--bench-bin', type=Path, required=True)
    parser.add_argument('--profiler-bin', type=Path, required=True)
    parser.add_argument('--mode', choices=['cpu', 'syscalls'], required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--duration', type=int, default=10)
    args = parser.parse_args()
    require(sys.platform == 'linux' and os.geteuid() == 0, '剖析需要专用 Linux worker 的调度账户')
    require(1 <= args.duration <= 60, '剖析时长无效')
    available = sorted(os.sched_getaffinity(0))
    require(len(available) >= 8, '需要至少 8 个可用逻辑 CPU')
    for name in ('server_bin', 'bench_bin', 'profiler_bin'):
        path = getattr(args, name).resolve(strict=True)
        require(path.is_file() and os.access(path, os.X_OK), '可执行文件无效')
        setattr(args, name, path)
    folder = args.output.resolve()
    folder.mkdir(mode=0o700)
    target, proxy = free_port(), free_port()
    while target == proxy:
        proxy = free_port()
    config = folder / 'server.json'
    dump(config, {'warp': {'secretKey': 'invalid'}, 'inbounds': [{
        'tag': 'profile', 'protocol': 'mieru', 'listen': '127.0.0.1', 'port': proxy,
        'outbound': 'native-v4', 'settings': {'transport': 'TCP', 'users': [{
            'email': 'test-user', 'username': 'test-user', 'password': 'test-password'}]}}]})
    echo = server = load = profiler = None
    log = None
    try:
        echo = Process([str(args.bench_bin), 'echo', '--listen', f'127.0.0.1:{target}'],
                       folder, 'echo', available[7:8], 0, {'GOMAXPROCS': '1'})
        echo.wait_event('ready')
        server = Process([str(args.server_bin), str(config)], folder, 'server', available[:4], 0)
        wait_port(server, proxy)
        log = (folder / 'profiler.log').open('wb')
        if args.mode == 'cpu':
            command = [str(args.profiler_bin), 'record', '-e', 'cpu-clock', '-F', '199',
                       '--call-graph', 'dwarf,16384', '-o', str(folder / 'perf.data'),
                       '-p', str(server.process.pid)]
        else:
            command = [str(args.profiler_bin), '-f', '-c', '-o', str(folder / 'syscalls.txt'),
                       '-p', str(server.process.pid)]
        profiler = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
        load = Process([str(args.bench_bin), 'load', '--label', 'profile', '--peer', f'127.0.0.1:{proxy}',
                        '--target', f'127.0.0.1:{target}', '--duration', f'{args.duration}s',
                        '--warmup', '3s', '--concurrency', '8', '--block-size', '32768'],
                       folder, 'client', available[4:7], 0, {'GOMAXPROCS': '3'})
        code = load.process.wait(args.duration + 60)
        final = [e for e in events(load.path) if e.get('event') == 'final']
        require(code == 0 and len(final) == 1 and final[0]['status'] == 'pass', '剖析负载未完成')
        require(profiler.poll() is None, '剖析进程提前退出')
        stop_profiler(profiler)
        require(profiler.returncode in (0, -signal.SIGINT, 128 + signal.SIGINT),
                f'剖析器失败：{profiler.returncode}')
        if args.mode == 'cpu':
            report = subprocess.run([str(args.profiler_bin), 'script', '-i', str(folder / 'perf.data'),
                                     '-F', 'comm'], check=True, text=True, capture_output=True)
            require(bool(report.stdout.strip()), '剖析文件没有样本')
        else:
            require('total' in (folder / 'syscalls.txt').read_text(), '系统调用剖析没有汇总')
        dump(folder / 'profile.json', {'status': 'pass', 'mode': args.mode,
                                      'performance_measurement': False,
                                      'bulk_ack_bytes': final[0]['bulk_ack_bytes'],
                                      'errors': final[0]['errors'], 'mismatches': final[0]['mismatches']})
        print(json.dumps({'status': 'pass', 'mode': args.mode, 'performance_measurement': False}))
    finally:
        stop_profiler(profiler)
        for process in (load, server, echo):
            if process is not None:
                process.stop()
        if log is not None:
            log.close()


if __name__ == '__main__':
    main()
