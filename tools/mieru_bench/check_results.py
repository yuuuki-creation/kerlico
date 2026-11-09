#!/usr/bin/env python3
"""独立核对完成字节、时间窗及真实目标工作，输出仅含匿名摘要。"""
import argparse
import copy
import json
import math
from pathlib import Path


def check(document, client_events, expected_seconds=60):
    failures = []
    if document.get('status') != 'pass':
        failures.append('comparison_incomplete')
    cases = {c.get('label'): c for c in document.get('cases', [])}
    if set(cases) != {'baseline', 'kerlico', 'mita'}:
        failures.append('missing_side')
    for name in ['kerlico', 'mita']:
        c = cases.get(name, {})
        m = c.get('measurement', {})
        try:
            if m['status'] != 'pass' or m['duration_seconds'] != expected_seconds:
                failures.append(name + ':window')
            if any(m[key] != 0 for key in ['errors', 'timeouts', 'mismatches']):
                failures.append(name + ':error')
            if m['bulk_ack_bytes'] != m['bulk_completions'] * m['block_size'] or m['probe_ack_bytes'] != m['probe_completions'] * m['latency_size']:
                failures.append(name + ':frame_total')
            if m['bulk_completions'] <= 0 or m['probe_completions'] <= 0:
                failures.append(name + ':no_work')
            rate = m['bulk_ack_bytes'] * 8 / expected_seconds / 1e6
            if not math.isclose(rate, m['effective_one_way_mbps'], rel_tol=1e-10) or not math.isclose(2 * rate, m['effective_bidirectional_mbps'], rel_tol=1e-10):
                failures.append(name + ':rate')
            records = client_events.get(name, [])
            seconds = [r['counts'] for r in records if r.get('event') == 'second']
            if len(seconds) != expected_seconds or sum(s['bulk_ack_bytes'] for s in seconds) != m['bulk_ack_bytes'] or sum(s['bulk_completions'] for s in seconds) != m['bulk_completions']:
                failures.append(name + ':second_ledger')
            if m['end_unix_ns'] - m['start_unix_ns'] != expected_seconds * 1000000000:
                failures.append(name + ':duration')
            resources = c['resources']
            if abs(resources['actual_duration_seconds'] - expected_seconds) > 0.2 or abs(resources['actual_start_ns'] - m['start_unix_ns']) > 100000000:
                failures.append(name + ':resource_alignment')
            processes = resources['processes']
            if set(processes) != {'client', 'server', 'echo'}:
                failures.append(name + ':missing_process')
            for role, capacity in [('server', 4), ('client', 3), ('echo', 1)]:
                p = processes[role]
                if not 0 <= p['cpu_percent_average'] <= capacity * 100 + 1 or p['rss_mib_sample_peak'] < p['rss_mib_average']:
                    failures.append(name + ':resource_limits')
            if abs(processes['client']['cpu_percent_average'] - m['client_cpu_percent_one_core_basis']) > 1.0:
                failures.append(name + ':cpu_cross_check')
            completed = m['bulk_ack_bytes'] + m['probe_ack_bytes'] + m['late_ack_bytes']
            if not c['byte_work_confirmed'] or c['echo_work']['read_bytes'] < completed or c['echo_work']['write_bytes'] < completed or c['echo_work']['errors']:
                failures.append(name + ':echo_work')
        except (KeyError, TypeError, ZeroDivisionError):
            failures.append(name + ':missing_metric')
    return failures


def main():
    parser = argparse.ArgumentParser(description='核对同一分钟负载及资源数据')
    parser.add_argument('result', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    data = json.loads(args.result.read_text())
    records = {}
    for name in ['kerlico', 'mita']:
        path = args.result.parent / name / 'client.jsonl'
        records[name] = [json.loads(line) for line in path.read_text().splitlines() if line.startswith('{')]
    failures = check(data, records)
    bad = copy.deepcopy(data)
    next(c for c in bad['cases'] if c['label'] == 'kerlico')['measurement']['bulk_ack_bytes'] += 1
    bad_total_rejected = 'kerlico:frame_total' in check(bad, records)
    bad_records = copy.deepcopy(records)
    next(r for r in bad_records['mita'] if r.get('event') == 'second')['counts']['bulk_ack_bytes'] += 1
    bad_ledger_rejected = 'mita:second_ledger' in check(data, bad_records)
    missing = copy.deepcopy(data)
    missing['cases'] = [c for c in missing['cases'] if c['label'] != 'mita']
    missing_rejected = 'missing_side' in check(missing, records)
    result = {'status': 'pass' if not failures and bad_total_rejected and bad_ledger_rejected and missing_rejected else 'fail', 'failures': failures, 'bad_total_rejected': bad_total_rejected, 'bad_second_ledger_rejected': bad_ledger_rejected, 'missing_side_rejected': missing_rejected}
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2))
    print(json.dumps(result, ensure_ascii=False))
    raise SystemExit(0 if result['status'] == 'pass' else 1)


if __name__ == '__main__':
    main()
