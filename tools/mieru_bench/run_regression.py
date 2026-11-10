#!/usr/bin/env python3
"""在专用 worker 交替比较服务端，复用固定负载与独立字节核对。"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import statistics
import sys
from types import SimpleNamespace

from check_results import check
from run_comparison import dump, events, require, run_side


def validate_pair(baseline, pair, folder, duration):
    document = {'status': 'pass', 'cases': [baseline, *pair]}
    records = {side: events(folder / side / 'client.jsonl') for side in ('before', 'after')}

    def failures(data, ledger):
        return check(data, ledger, duration, sides=('before', 'after'))

    require(not failures(document, records), '独立字节或采样核对失败')
    bad = copy.deepcopy(document)
    next(c for c in bad['cases'] if c['label'] == 'before')['measurement']['bulk_ack_bytes'] += 1
    require('before:frame_total' in failures(bad, records), '错误总量对照未被拒绝')
    bad_records = copy.deepcopy(records)
    next(r for r in bad_records['after'] if r.get('event') == 'second')['counts']['bulk_ack_bytes'] += 1
    require('after:second_ledger' in failures(document, bad_records), '错误逐秒计数对照未被拒绝')
    missing = {'status': 'pass', 'cases': [baseline, pair[0]]}
    require('missing_side' in failures(missing, records), '缺失一侧对照未被拒绝')
    changed = copy.deepcopy(document)
    next(c for c in changed['cases'] if c['label'] == 'after')['measurement']['profile']['mtu'] += 1
    require('parameter_mismatch' in failures(changed, records), '参数不一致对照未被拒绝')
    changed = copy.deepcopy(document)
    next(c for c in changed['cases'] if c['label'] == 'after')['measurement']['profile'] = {}
    require('missing_profile' in failures(changed, records), '缺失参数对照未被拒绝')
    return {'status': 'pass', 'bad_total_rejected': True,
            'bad_second_ledger_rejected': True, 'missing_side_rejected': True,
            'bad_parameters_rejected': True, 'missing_profile_rejected': True}


def summarize(rounds, side):
    rows = [next(c for c in pair['cases'] if c['label'] == side) for pair in rounds]
    values = {
        'one_way_mbps': [r['measurement']['effective_one_way_mbps'] for r in rows],
        'server_cpu_seconds_per_one_way_gib': [cpu_per_gib(r) for r in rows],
        'server_rss_mib_average': [r['resources']['processes']['server']['rss_mib_average'] for r in rows],
        'probe_p99_ms_upper': [r['measurement']['probe_rtt']['p99_ms_upper'] for r in rows],
    }
    return {key: {'median': statistics.median(series), 'min': min(series), 'max': max(series)}
            for key, series in values.items()}


def cpu_per_gib(case):
    cpu = case['resources']['processes']['server']
    return (cpu['user_cpu_seconds'] + cpu['system_cpu_seconds']) / (case['measurement']['bulk_ack_bytes'] / 1024**3)


def meets_cpu_target(ratios, reduction_percent):
    return bool(ratios) and all(0 < ratio <= 1 - reduction_percent / 100 for ratio in ratios)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    reference = parser.add_mutually_exclusive_group(required=True)
    reference.add_argument('--before-bin', type=Path)
    reference.add_argument('--mita-bin', type=Path)
    parser.add_argument('--after-bin', type=Path, required=True)
    parser.add_argument('--bench-bin', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--rounds', type=int, default=5)
    parser.add_argument('--duration', type=int, default=60)
    parser.add_argument('--concurrency', type=int, default=8)
    parser.add_argument('--block-size', type=int, default=32768)
    parser.add_argument('--require-cpu-reduction', type=float, help='每组配对运行必须达到的 CPU/GiB 降幅百分比')
    parser.add_argument('--uid', type=int, default=65534)
    args = parser.parse_args()
    reference_kind = 'mita' if args.mita_bin else 'kerlico'
    if args.mita_bin:
        args.before_bin = args.mita_bin
    require(sys.platform == 'linux' and os.geteuid() == 0 and args.uid > 0,
            '需要专用 Linux worker 及可降权的调度账户')
    require(5 <= args.rounds <= 20 and 1 <= args.duration <= 600, '轮数或计时区间无效')
    require(1 <= args.concurrency <= 256 and 8 <= args.block_size <= 1024 * 1024, '负载参数无效')
    require(args.require_cpu_reduction is None or 0 < args.require_cpu_reduction < 100, 'CPU 降幅阈值无效')
    require(not Path('/var/lib/mita').exists(), '选择没有全局 mita 资料的专用 worker')
    binaries = {}
    for name in ('before', 'after', 'bench'):
        path = getattr(args, name + '_bin').resolve(strict=True)
        require(path.is_file() and os.access(path, os.X_OK), '二进制路径无效')
        setattr(args, name + '_bin', path)
        binaries[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    require(binaries['before'] != binaries['after'], '两侧二进制相同，不能验证改动')
    available = sorted(os.sched_getaffinity(0))
    require(len(available) >= 8, '需要至少 8 个可用逻辑 CPU')
    cpus = {'server': available[:4], 'client': available[4:7], 'echo': available[7:8]}
    args.output = args.output.resolve()
    args.output.mkdir(mode=0o700)
    os.chown(args.output, args.uid, args.uid)
    result = {'status': 'fail', 'binaries_sha256': binaries, 'network': 'loopback',
              'cpus': cpus, 'timed_seconds_per_side': args.duration,
              'runs_per_side': args.rounds, 'reference_kind': reference_kind,
              'concurrency': args.concurrency, 'block_size': args.block_size, 'rounds': []}
    try:
        baseline = run_side(args, 'baseline', 5, cpus)
        result['baseline'] = baseline
        for index in range(args.rounds):
            folder = args.output / f'round-{index + 1:02d}'
            folder.mkdir(mode=0o700)
            os.chown(folder, args.uid, args.uid)
            options = SimpleNamespace(output=folder, bench_bin=args.bench_bin, uid=args.uid,
                                      mita_bin=args.before_bin, concurrency=args.concurrency,
                                      block_size=args.block_size)
            pair = []
            for side in ('before', 'after'):
                binary = None if side == 'before' and reference_kind == 'mita' else getattr(args, side + '_bin')
                pair.append(run_side(options, side, args.duration, cpus, binary))
            validation = validate_pair(baseline, pair, folder, args.duration)
            result['rounds'].append({'cases': pair, 'validation': validation})
            dump(args.output / 'regression.json', result)
        result['summary'] = {side: summarize(result['rounds'], side) for side in ('before', 'after')}
        before, after = result['summary']['before'], result['summary']['after']
        result['ratios'] = {key: after[key]['median'] / before[key]['median'] for key in before}
        result['cpu_30_percent_lower'] = result['ratios']['server_cpu_seconds_per_one_way_gib'] <= 0.70
        result['paired_cpu_ratios'] = [
            cpu_per_gib(next(c for c in r['cases'] if c['label'] == 'after'))
            / cpu_per_gib(next(c for c in r['cases'] if c['label'] == 'before')) for r in result['rounds']]
        result['all_pairs_cpu_30_percent_lower'] = meets_cpu_target(result['paired_cpu_ratios'], 30)
        if args.require_cpu_reduction is not None:
            result['cpu_requirement'] = {
                'reduction_percent': args.require_cpu_reduction,
                'met': meets_cpu_target(result['paired_cpu_ratios'], args.require_cpu_reduction),
            }
        result['status'] = 'pass'
    except BaseException as error:
        result['error_type'] = type(error).__name__
        result['error'] = str(error)
        raise
    finally:
        dump(args.output / 'regression.json', result)
    print(json.dumps({'status': 'pass', 'summary': result['summary'], 'ratios': result['ratios'],
                      'cpu_30_percent_lower': result['cpu_30_percent_lower'],
                      'all_pairs_cpu_30_percent_lower': result['all_pairs_cpu_30_percent_lower'],
                      'cpu_requirement': result.get('cpu_requirement')}, ensure_ascii=False))
    if not result.get('cpu_requirement', {}).get('met', True):
        raise SystemExit(2)


if __name__ == '__main__':
    main()
