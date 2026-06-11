#!/usr/bin/env python3
"""logscope - Log analysis CLI for ops personnel to quickly locate service anomalies."""

import argparse
import json
import math
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path

VERSION = "1.1.0"
DEFAULT_RULES_FILE = os.path.join(str(Path.home()), ".logscope_rules.json")

TIMESTAMP_PATTERNS = [
    r'(\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}(?:\.\d+)?)',
    r'\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})\]',
    r'(\d{2}-\d{2}-\d{4}\s+\d{2}:\d{2}:\d{2})',
]

TIMESTAMP_FORMATS = [
    '%Y-%m-%d %H:%M:%S',
    '%Y-%m-%d %H:%M:%S.%f',
    '%Y-%m-%dT%H:%M:%S',
    '%Y-%m-%dT%H:%M:%S.%f',
    '%d/%b/%Y:%H:%M:%S',
    '%m-%d-%Y %H:%M:%S',
]

LEVEL_KEYWORDS = ['DEBUG', 'INFO', 'WARN', 'WARNING', 'ERROR', 'FATAL', 'CRITICAL']

LEVEL_PATTERNS = [
    r'\[(?:LEVEL\s*[:=]?\s*)?(DEBUG|INFO|WARN(?:ING)?|ERROR|FATAL|CRITICAL)\]',
    r'[\s\-\|](DEBUG|INFO|WARN(?:ING)?|ERROR|FATAL|CRITICAL)[\s\-\|:\(\[]',
    r'^(DEBUG|INFO|WARN(?:ING)?|ERROR|FATAL|CRITICAL)[\s\-\|:\(\[]',
    r'["\'\s]?level["\'\s]?[=:]["\'\s]?(DEBUG|INFO|WARN(?:ING)?|ERROR|FATAL|CRITICAL)["\'\s]?',
    r'["\'\s]?severity["\'\s]?[=:]["\'\s]?(DEBUG|INFO|WARN(?:ING)?|ERROR|FATAL|CRITICAL)["\'\s]?',
    r'["\'\s]?lvl["\'\s]?[=:]["\'\s]?(DEBUG|INFO|WARN(?:ING)?|ERROR|FATAL|CRITICAL)["\'\s]?',
]

TRACE_ID_PATTERN = (
    r'(?:trace[-_]?id|request[-_]?id|req[-_]?id|rid|txn[-_]?id)'
    r'[=:\s]+["\']?([a-zA-Z0-9\-_]+)["\']?'
)
ERROR_CODE_PATTERN = (
    r'(?:error[-_]?code|status[-_]?code|err[-_]?code|code)'
    r'[=:\s]+["\']?(\d{3,})["\']?'
)

SERVICE_PATTERN = (
    r'(?:service[-_]?name|service|svc|app[-_]?name|app)'
    r'[=:\s]+["\']?([a-zA-Z][a-zA-Z0-9\-_\.]*)["\']?'
)

HOST_PATTERN = (
    r'(?:host[-_]?name|hostname|host|server[-_]?name|server)'
    r'[=:\s]+["\']?([a-zA-Z0-9][a-zA-Z0-9\-_\.]*)["\']?'
)

SENSITIVE_KEYS = [
    'password', 'passwd', 'token', 'secret', 'api_key', 'apikey',
    'access_key', 'private_key', 'credit_card', 'ssn', 'email',
    'phone', 'mobile', 'authorization', 'cookie',
]


class LogEntry:
    __slots__ = [
        'raw', 'timestamp', 'level', 'trace_id',
        'error_code', 'service', 'host',
        'file_path', 'line_num',
    ]

    def __init__(self, raw='', timestamp=None, level='',
                 trace_id='', error_code='', service='', host='',
                 file_path='', line_num=0):
        self.raw = raw
        self.timestamp = timestamp
        self.level = level.upper() if level else ''
        self.trace_id = trace_id
        self.error_code = error_code
        self.service = service
        self.host = host
        self.file_path = file_path
        self.line_num = line_num


def parse_timestamp(text):
    for pat in TIMESTAMP_PATTERNS:
        m = re.search(pat, text)
        if m:
            ts_str = m.group(1)
            for fmt in TIMESTAMP_FORMATS:
                try:
                    return datetime.strptime(ts_str, fmt)
                except ValueError:
                    continue
    return None


def parse_level(text):
    text_upper = text
    for pat in LEVEL_PATTERNS:
        m = re.search(pat, text_upper, re.IGNORECASE)
        if m:
            lvl = m.group(1).upper()
            if lvl == 'WARNING':
                lvl = 'WARN'
            return lvl
    return ''


def parse_trace_id(text):
    m = re.search(TRACE_ID_PATTERN, text, re.IGNORECASE)
    return m.group(1) if m else ''


def parse_error_code(text):
    m = re.search(ERROR_CODE_PATTERN, text, re.IGNORECASE)
    return m.group(1) if m else ''


def parse_service(text):
    m = re.search(SERVICE_PATTERN, text, re.IGNORECASE)
    return m.group(1) if m else ''


def parse_host(text):
    m = re.search(HOST_PATTERN, text, re.IGNORECASE)
    return m.group(1) if m else ''


def parse_line(line, file_path='', line_num=0):
    return LogEntry(
        raw=line,
        timestamp=parse_timestamp(line),
        level=parse_level(line),
        trace_id=parse_trace_id(line),
        error_code=parse_error_code(line),
        service=parse_service(line),
        host=parse_host(line),
        file_path=file_path,
        line_num=line_num,
    )


def mask_sensitive(text, fields=None):
    keys = SENSITIVE_KEYS if fields is None else [k.lower() for k in fields]
    if not keys:
        return text

    def replacer(m):
        return f'{m.group(1)}{m.group(2)}****'

    pattern = (
        r'(' + '|'.join(re.escape(k) for k in keys) + r')'
        r'(=|:|=>|->)\s*["\']?[^\s,;\]}"\']+'
    )
    return re.sub(pattern, replacer, text, flags=re.IGNORECASE)


def format_table(headers, rows, max_width=60):
    if not rows:
        return ''
    col_count = len(headers)
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if i < col_count:
                display_len = min(len(str(cell)), max_width)
                widths[i] = max(widths[i], display_len)
    widths = [min(w, max_width) for w in widths]
    sep = '+' + '+'.join('-' * (w + 2) for w in widths) + '+'
    header_line = '|' + '|'.join(
        f' {h:<{widths[i]}} ' for i, h in enumerate(headers)
    ) + '|'
    lines = [sep, header_line, sep]
    for row in rows:
        cells = []
        for i in range(col_count):
            cell = str(row[i]) if i < len(row) else ''
            if len(cell) > max_width:
                cell = cell[:max_width - 3] + '...'
            cells.append(f' {cell:<{widths[i]}} ')
        lines.append('|' + '|'.join(cells) + '|')
    lines.append(sep)
    return '\n'.join(lines)


def fmt_size(size_bytes):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024:
            return f'{size_bytes:.1f}{unit}'
        size_bytes /= 1024
    return f'{size_bytes:.1f}TB'


def collect_log_files(directory, pattern='*.log'):
    p = Path(directory)
    if p.is_file():
        return [str(p)]
    if not p.is_dir():
        print(f"[ERROR] Path not found: {directory}", file=sys.stderr)
        sys.exit(1)
    files = []
    for f in sorted(p.rglob(pattern)):
        if f.is_file():
            files.append(str(f))
    return files


def read_log_entries(files, encoding='utf-8', errors='ignore'):
    entries = []
    for fp in files:
        try:
            with open(fp, encoding=encoding, errors=errors) as fh:
                for line_num, line in enumerate(fh, 1):
                    line = line.rstrip('\n\r')
                    if line.strip():
                        entries.append(
                            parse_line(line, file_path=fp, line_num=line_num)
                        )
        except (OSError, PermissionError) as exc:
            print(f"[WARN] Cannot read {fp}: {exc}", file=sys.stderr)
    return entries


def filter_entries(entries, start=None, end=None, keyword=None,
                   level=None, trace_id=None, error_code=None,
                   invert=False, include_no_ts=False):
    result = []
    for e in entries:
        match = True

        if start or end:
            if not e.timestamp:
                if not include_no_ts:
                    match = False
            else:
                if start and e.timestamp < start:
                    match = False
                if end and e.timestamp > end:
                    match = False

        if keyword and keyword.lower() not in e.raw.lower():
            match = False
        if level:
            levels = [l.upper() for l in level.split(',')]
            if e.level not in levels:
                match = False
        if trace_id and trace_id not in e.trace_id:
            match = False
        if error_code and error_code != e.error_code:
            match = False
        if invert:
            match = not match
        if match:
            result.append(e)
    return result


def parse_time_arg(time_str):
    now = datetime.now()
    if time_str == 'now':
        return now
    if time_str.startswith('-'):
        try:
            delta = time_str[1:]
            unit = delta[-1]
            value = int(delta[:-1])
            if unit == 'm':
                return now - timedelta(minutes=value)
            elif unit == 'h':
                return now - timedelta(hours=value)
            elif unit == 'd':
                return now - timedelta(days=value)
        except (ValueError, IndexError):
            pass
    for fmt in TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(time_str, fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(time_str)
    except (ValueError, TypeError):
        pass
    print(f"[ERROR] Cannot parse time: {time_str}", file=sys.stderr)
    sys.exit(1)


def load_rules(path=None):
    path = path or DEFAULT_RULES_FILE
    if os.path.exists(path):
        try:
            with open(path, encoding='utf-8') as fh:
                return json.load(fh)
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def save_rules(rules, path=None):
    path = path or DEFAULT_RULES_FILE
    with open(path, 'w', encoding='utf-8') as fh:
        json.dump(rules, fh, indent=2, ensure_ascii=False)


def apply_rule_to_args(args, rule):
    for key, val in rule.items():
        if val and not getattr(args, key, None):
            setattr(args, key, val)


def confirm_prompt(message):
    try:
        answer = input(f"{message} [y/N]: ").strip().lower()
        return answer in ('y', 'yes')
    except (EOFError, KeyboardInterrupt):
        return False


def build_alert_summary(entries, group_by='service,code', top_n=10,
                        levels=None):
    if levels is None:
        levels = ('ERROR', 'FATAL', 'CRITICAL')
    error_entries = [e for e in entries if e.level in levels]

    group_keys = [g.strip().lower() for g in group_by.split(',')]
    counter = Counter()
    for e in error_entries:
        key_parts = []
        for g in group_keys:
            if g in ('code', 'error_code', 'errcode'):
                key_parts.append(e.error_code or 'unknown')
            elif g in ('service', 'svc', 'app'):
                key_parts.append(e.service or 'unknown')
            elif g in ('host', 'hostname', 'server'):
                key_parts.append(e.host or 'unknown')
            elif g in ('level', 'lvl'):
                key_parts.append(e.level or 'UNKNOWN')
            elif g in ('trace', 'trace_id'):
                key_parts.append(e.trace_id or 'unknown')
            else:
                key_parts.append('unknown')
        counter[tuple(key_parts)] += 1

    headers = []
    for g in group_keys:
        if g in ('code', 'error_code', 'errcode'):
            headers.append('ErrorCode')
        elif g in ('service', 'svc', 'app'):
            headers.append('Service')
        elif g in ('host', 'hostname', 'server'):
            headers.append('Host')
        elif g in ('level', 'lvl'):
            headers.append('Level')
        elif g in ('trace', 'trace_id'):
            headers.append('TraceID')
        else:
            headers.append(g)
    headers.append('Count')

    rows = []
    for key, cnt in counter.most_common(top_n):
        rows.append(list(key) + [str(cnt)])

    return {
        'headers': headers,
        'rows': rows,
        'total': len(error_entries),
        'groups': len(counter),
        'group_by': group_by,
    }


def alert_summary_to_json(alert_summary, entries=None):
    data = {
        'group_by': alert_summary['group_by'],
        'total_errors': alert_summary['total'],
        'distinct_groups': alert_summary['groups'],
        'top_items': []
    }
    headers = [h.lower() for h in alert_summary['headers']]
    for row in alert_summary['rows']:
        item = {}
        for i, h in enumerate(headers[:-1]):
            item[h] = row[i]
        item['count'] = int(row[-1])
        data['top_items'].append(item)

    if entries:
        data['_meta'] = {
            'total_entries': len(entries),
            'timestamped_entries': sum(1 for e in entries if e.timestamp),
        }
    return data


def cmd_scan(args):
    files = collect_log_files(args.directory, getattr(args, 'pattern', '*.log'))
    if not files:
        print("No log files found.")
        return

    headers = ['File', 'Size', 'Modified', 'Lines', 'Errors', 'Warnings']
    rows = []
    for fp in files:
        try:
            stat = os.stat(fp)
            size = fmt_size(stat.st_size)
            mtime = datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M')
            line_count = error_count = warn_count = 0
            with open(fp, encoding='utf-8', errors='ignore') as fh:
                for line in fh:
                    line_count += 1
                    upper = line.upper()
                    if 'ERROR' in upper or 'FATAL' in upper:
                        error_count += 1
                    elif 'WARN' in upper:
                        warn_count += 1
            rows.append([
                os.path.basename(fp), size, mtime,
                str(line_count), str(error_count), str(warn_count),
            ])
        except (OSError, PermissionError):
            rows.append([os.path.basename(fp), 'N/A', 'N/A', 'N/A', 'N/A', 'N/A'])

    print(format_table(headers, rows))
    print(f"\nTotal: {len(files)} file(s)")


def cmd_filter(args):
    files = collect_log_files(args.directory, getattr(args, 'pattern', '*.log'))
    if not files:
        print("No log files found.")
        return

    entries = read_log_entries(files)

    if args.use_rule:
        rules = load_rules(args.rules)
        if args.use_rule in rules:
            apply_rule_to_args(args, rules[args.use_rule])
        else:
            print(f"[WARN] Rule '{args.use_rule}' not found.", file=sys.stderr)

    start = parse_time_arg(args.start) if args.start else None
    end = parse_time_arg(args.end) if args.end else None
    include_no_ts = getattr(args, 'include_no_ts', False)
    filtered = filter_entries(
        entries, start=start, end=end,
        keyword=args.keyword, level=args.level,
        trace_id=args.trace_id, error_code=args.error_code,
        invert=getattr(args, 'invert', False),
        include_no_ts=include_no_ts,
    )

    mask_fields = args.mask.split(',') if args.mask else None
    limit = args.limit or 50

    headers = ['Time', 'Level', 'TraceID', 'Code', 'Message']
    rows = []
    for e in filtered[:limit]:
        msg = e.raw
        if mask_fields:
            msg = mask_sensitive(msg, mask_fields)
        ts = e.timestamp.strftime('%m-%d %H:%M:%S') if e.timestamp else '-'
        rows.append([ts, e.level or '-', e.trace_id or '-', e.error_code or '-', msg])

    print(format_table(headers, rows))
    print(f"\nTotal: {len(filtered)} entries (showing {min(limit, len(filtered))})")

    if start or end:
        no_ts_count = sum(1 for e in entries if not e.timestamp)
        if not include_no_ts:
            print(f"Note: {no_ts_count} entries without timestamp were excluded by strict time filter.")
            print("      Use --include-no-ts to include them.")
        else:
            print(f"Note: {no_ts_count} entries without timestamp are included.")


def cmd_trace(args):
    files = collect_log_files(args.directory, getattr(args, 'pattern', '*.log'))
    if not files:
        print("No log files found.")
        return

    entries = read_log_entries(files)
    tid = args.trace_id

    if not tid:
        trace_counter = Counter(e.trace_id for e in entries if e.trace_id)
        if not trace_counter:
            print("No trace IDs found in logs.")
            return
        top = trace_counter.most_common(10)
        headers = ['Trace ID', 'Count', 'Level Spread']
        rows = []
        for tid_val, cnt in top:
            tid_entries = [e for e in entries if e.trace_id == tid_val]
            levels = sorted(set(e.level for e in tid_entries if e.level))
            rows.append([tid_val, str(cnt), ','.join(levels) or '-'])
        print("Top trace IDs by log count:")
        print(format_table(headers, rows))
        return

    filtered = [e for e in entries if e.trace_id == tid]
    if not filtered:
        print(f"No entries found for trace ID: {tid}")
        return

    filtered.sort(key=lambda e: e.timestamp or datetime.min)
    mask_fields = args.mask.split(',') if args.mask else None

    headers = ['#', 'Time', 'Level', 'Code', 'File', 'Message']
    rows = []
    for i, e in enumerate(filtered, 1):
        msg = e.raw
        if mask_fields:
            msg = mask_sensitive(msg, mask_fields)
        ts = e.timestamp.strftime('%H:%M:%S') if e.timestamp else '-'
        fname = os.path.basename(e.file_path)
        rows.append([str(i), ts, e.level or '-', e.error_code or '-', fname, msg])

    print(f"Trace chain for: {tid} ({len(filtered)} entries)")
    print(format_table(headers, rows))


def cmd_stat(args):
    files = collect_log_files(args.directory, getattr(args, 'pattern', '*.log'))
    if not files:
        print("No log files found.")
        return

    entries = read_log_entries(files)
    start = parse_time_arg(args.start) if args.start else None
    end = parse_time_arg(args.end) if args.end else None
    include_no_ts = getattr(args, 'include_no_ts', False)

    if start or end:
        total_no_ts = sum(1 for e in entries if not e.timestamp)
        entries = filter_entries(entries, start=start, end=end,
                                 include_no_ts=include_no_ts)
    else:
        total_no_ts = 0

    code_counter = Counter(e.error_code for e in entries if e.error_code)
    level_counter = Counter(e.level for e in entries if e.level)

    if getattr(args, 'json', False):
        data = {
            'directory': args.directory,
            'files_scanned': len(files),
            'total_entries': len(entries),
            'time_range': {
                'start': start.strftime('%Y-%m-%d %H:%M:%S') if start else None,
                'end': end.strftime('%Y-%m-%d %H:%M:%S') if end else None,
                'included_no_ts': include_no_ts if (start or end) else None,
                'excluded_no_ts_count': total_no_ts if (start or end) and not include_no_ts else 0,
            },
            'level_distribution': dict(level_counter),
            'error_code_ranking': [
                {'code': code, 'count': cnt}
                for code, cnt in code_counter.most_common(20)
            ],
        }
        if getattr(args, 'alert', False):
            alert = build_alert_summary(
                entries,
                group_by=getattr(args, 'alert_group_by', 'service,code'),
                top_n=getattr(args, 'alert_top', 10),
            )
            data['alert_summary'] = alert_summary_to_json(alert, entries)

        if getattr(args, 'spike', False):
            buckets = defaultdict(int)
            for e in entries:
                if e.timestamp and e.level in ('ERROR', 'FATAL', 'CRITICAL'):
                    bucket = e.timestamp.replace(minute=0, second=0, microsecond=0)
                    buckets[bucket] += 1
            data['spike_windows'] = [
                {'time': ts.strftime('%Y-%m-%d %H:%M'), 'count': cnt}
                for ts, cnt in sorted(buckets.items())
            ]

        if getattr(args, 'output', None):
            with open(args.output, 'w', encoding='utf-8') as fh:
                json.dump(data, fh, indent=2, ensure_ascii=False)
            print(f"JSON saved to {args.output}")
        else:
            print(json.dumps(data, indent=2, ensure_ascii=False))
        return

    print("=== Error Code Ranking ===")
    if code_counter:
        total_codes = sum(code_counter.values())
        headers = ['Rank', 'Code', 'Count', 'Percentage']
        rows = []
        for i, (code, cnt) in enumerate(code_counter.most_common(20), 1):
            pct = f'{cnt / total_codes * 100:.1f}%'
            rows.append([str(i), code, str(cnt), pct])
        print(format_table(headers, rows))
    else:
        print("No error codes found.")

    print("\n=== Level Distribution ===")
    if level_counter:
        total_levels = sum(level_counter.values())
        headers = ['Level', 'Count', 'Percentage']
        rows = []
        for lvl, cnt in level_counter.most_common():
            pct = f'{cnt / total_levels * 100:.1f}%'
            rows.append([lvl, str(cnt), pct])
        print(format_table(headers, rows))
    else:
        print("No log levels found.")

    if start or end:
        print(f"\nNote: {total_no_ts} entries without timestamp "
              f"were {'included' if include_no_ts else 'excluded'} "
              f"in this time range analysis.")
        if not include_no_ts:
            print("      Use --include-no-ts to include them.")

    if getattr(args, 'alert', False):
        print("\n=== Alert Summary ===")
        alert = build_alert_summary(
            entries,
            group_by=getattr(args, 'alert_group_by', 'service,code'),
            top_n=getattr(args, 'alert_top', 10),
        )
        if alert['rows']:
            print(f"Grouped by: {alert['group_by']}")
            print(f"Total errors: {alert['total']} (across {alert['groups']} groups)")
            print(format_table(alert['headers'], alert['rows']))
        else:
            print("No alert data available.")

    if getattr(args, 'spike', False):
        print("\n=== Spike Detection ===")
        buckets = defaultdict(int)
        for e in entries:
            if e.timestamp and e.level in ('ERROR', 'FATAL', 'CRITICAL'):
                bucket = e.timestamp.replace(minute=0, second=0, microsecond=0)
                buckets[bucket] += 1

        if not buckets:
            print("No error entries with timestamps for spike detection.")
            return

        sorted_buckets = sorted(buckets.items())
        values = [v for _, v in sorted_buckets]
        if len(values) < 2:
            print("Not enough data points for spike detection.")
            return

        mean = sum(values) / len(values)
        std = math.sqrt(sum((v - mean) ** 2 for v in values) / len(values))
        sigma = getattr(args, 'spike_sigma', 2.0)
        threshold = mean + sigma * std if std > 0 else mean + 1

        headers = ['Time Window', 'Error Count', 'Mean', 'Sigma', 'Status']
        rows = []
        spike_count = 0
        for ts, cnt in sorted_buckets:
            status = '!! SPIKE' if cnt > threshold else 'OK'
            if cnt > threshold:
                spike_count += 1
            rows.append([
                ts.strftime('%Y-%m-%d %H:%M'),
                str(cnt), f'{mean:.1f}', f'{sigma:.1f}', status,
            ])
        print(format_table(headers, rows))
        if spike_count:
            print(f"\nDetected {spike_count} spike window(s) above {sigma} sigma.")


def cmd_diff(args):
    files = collect_log_files(args.directory, getattr(args, 'pattern', '*.log'))
    if not files:
        print("No log files found.")
        return

    entries = read_log_entries(files)
    a_start = parse_time_arg(args.a_start)
    a_end = parse_time_arg(args.a_end)
    b_start = parse_time_arg(args.b_start)
    b_end = parse_time_arg(args.b_end)
    include_no_ts = getattr(args, 'include_no_ts', False)

    period_a = filter_entries(entries, start=a_start, end=a_end,
                              include_no_ts=include_no_ts)
    period_b = filter_entries(entries, start=b_start, end=b_end,
                              include_no_ts=include_no_ts)

    total_a_no_ts = sum(1 for e in entries if not e.timestamp)
    total_a_ts = len(period_a)
    total_b = len(period_b)

    codes_a = Counter(e.error_code for e in period_a if e.error_code)
    codes_b = Counter(e.error_code for e in period_b if e.error_code)
    levels_a = Counter(e.level for e in period_a if e.level)
    levels_b = Counter(e.level for e in period_b if e.level)

    print(f"Period A: {a_start} ~ {a_end} ({len(period_a)} entries)")
    print(f"Period B: {b_start} ~ {b_end} ({len(period_b)} entries)")
    if not include_no_ts:
        print(f"Note: Entries without timestamps are excluded (strict mode). "
              f"Use --include-no-ts to include them.")

    print("\n=== Level Comparison ===")
    all_levels = sorted(set(list(levels_a.keys()) + list(levels_b.keys())))
    headers = ['Level', 'Period A', 'Period B', 'Delta', 'Change']
    rows = []
    for lvl in all_levels:
        ca = levels_a.get(lvl, 0)
        cb = levels_b.get(lvl, 0)
        delta = cb - ca
        if ca > 0:
            pct = f'{(delta / ca) * 100:+.1f}%'
        elif cb > 0:
            pct = '+NEW'
        else:
            pct = '-'
        rows.append([lvl, str(ca), str(cb), str(delta), pct])
    print(format_table(headers, rows))

    print("\n=== Error Code Comparison ===")
    all_codes = sorted(set(list(codes_a.keys()) + list(codes_b.keys())))
    headers = ['Code', 'Period A', 'Period B', 'Delta', 'Change']
    rows = []
    for code in all_codes[:30]:
        ca = codes_a.get(code, 0)
        cb = codes_b.get(code, 0)
        delta = cb - ca
        if ca > 0:
            pct = f'{(delta / ca) * 100:+.1f}%'
        elif cb > 0:
            pct = '+NEW'
        else:
            pct = '-'
        rows.append([code, str(ca), str(cb), str(delta), pct])
    print(format_table(headers, rows))

    print("\n=== Summary ===")
    err_a = sum(1 for e in period_a if e.level in ('ERROR', 'FATAL', 'CRITICAL'))
    err_b = sum(1 for e in period_b if e.level in ('ERROR', 'FATAL', 'CRITICAL'))
    delta_err = err_b - err_a
    direction = 'increased' if delta_err > 0 else 'decreased' if delta_err < 0 else 'unchanged'
    print(f"Errors {direction}: {err_a} -> {err_b} ({delta_err:+d})")


def cmd_report(args):
    files = collect_log_files(args.directory, getattr(args, 'pattern', '*.log'))
    if not files:
        print("No log files found.")
        return

    rules_path = args.rules if getattr(args, 'rules', None) else DEFAULT_RULES_FILE
    rules = load_rules(rules_path)

    if getattr(args, 'use_rule', None) and args.use_rule in rules:
        apply_rule_to_args(args, rules[args.use_rule])

    entries = read_log_entries(files)
    include_no_ts = getattr(args, 'include_no_ts', False)
    start = parse_time_arg(args.start) if getattr(args, 'start', None) else None
    end = parse_time_arg(args.end) if getattr(args, 'end', None) else None

    if start or end:
        entries = filter_entries(entries, start=start, end=end,
                                 include_no_ts=include_no_ts)
    if getattr(args, 'level', None):
        entries = filter_entries(entries, level=args.level)
    if getattr(args, 'keyword', None):
        entries = filter_entries(entries, keyword=args.keyword)

    if getattr(args, 'json', False):
        data = {
            'directory': args.directory,
            'files_scanned': len(files),
            'total_entries': len(entries),
            'time_range': {
                'start': start.strftime('%Y-%m-%d %H:%M:%S') if start else None,
                'end': end.strftime('%Y-%m-%d %H:%M:%S') if end else None,
            },
            'level_distribution': dict(Counter(e.level for e in entries if e.level)),
            'error_code_ranking': [
                {'code': code, 'count': cnt}
                for code, cnt in Counter(e.error_code for e in entries if e.error_code).most_common(20)
            ],
            'top_trace_ids': [
                {'trace_id': tid, 'count': cnt}
                for tid, cnt in Counter(e.trace_id for e in entries if e.trace_id).most_common(10)
            ],
        }
        if getattr(args, 'alert', False):
            alert = build_alert_summary(
                entries,
                group_by=getattr(args, 'alert_group_by', 'service,code'),
                top_n=getattr(args, 'alert_top', 10),
            )
            data['alert_summary'] = alert_summary_to_json(alert, entries)
        if getattr(args, 'output', None):
            with open(args.output, 'w', encoding='utf-8') as fh:
                json.dump(data, fh, indent=2, ensure_ascii=False)
            print(f"JSON report saved to {args.output}")
        else:
            print(json.dumps(data, indent=2, ensure_ascii=False))
        return

    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    lines = []
    lines.append('# Log Analysis Report')
    lines.append('')
    lines.append(f'- **Generated**: {now_str}')
    lines.append(f'- **Directory**: `{args.directory}`')
    lines.append(f'- **Files Scanned**: {len(files)}')
    lines.append(f'- **Total Entries**: {len(entries)}')

    ts_min = None
    ts_max = None
    for e in entries:
        if e.timestamp:
            if ts_min is None or e.timestamp < ts_min:
                ts_min = e.timestamp
            if ts_max is None or e.timestamp > ts_max:
                ts_max = e.timestamp
    if ts_min and ts_max:
        lines.append(f'- **Time Range**: {ts_min.strftime("%Y-%m-%d %H:%M:%S")} ~ {ts_max.strftime("%Y-%m-%d %H:%M:%S")}')
    if start or end:
        mode = 'strict (no-ts excluded)' if not include_no_ts else 'lenient (no-ts included)'
        lines.append(f'- **Time Filter Mode**: {mode}')
    lines.append('')

    level_counter = Counter(e.level for e in entries if e.level)
    lines.append('## Level Distribution')
    lines.append('')
    lines.append('| Level | Count | Percentage |')
    lines.append('|-------|-------|------------|')
    total_levels = sum(level_counter.values()) if level_counter else 1
    for lvl, cnt in level_counter.most_common():
        pct = f'{cnt / total_levels * 100:.1f}%'
        lines.append(f'| {lvl} | {cnt} | {pct} |')
    lines.append('')

    code_counter = Counter(e.error_code for e in entries if e.error_code)
    lines.append('## Error Code Ranking')
    lines.append('')
    if code_counter:
        total_codes = sum(code_counter.values())
        lines.append('| Rank | Code | Count | Percentage |')
        lines.append('|------|------|-------|------------|')
        for i, (code, cnt) in enumerate(code_counter.most_common(20), 1):
            pct = f'{cnt / total_codes * 100:.1f}%'
            lines.append(f'| {i} | {code} | {cnt} | {pct} |')
    else:
        lines.append('No error codes found.')
    lines.append('')

    trace_counter = Counter(e.trace_id for e in entries if e.trace_id)
    lines.append('## Top Trace IDs')
    lines.append('')
    if trace_counter:
        lines.append('| Trace ID | Count |')
        lines.append('|----------|-------|')
        for tid, cnt in trace_counter.most_common(10):
            lines.append(f'| `{tid}` | {cnt} |')
    else:
        lines.append('No trace IDs found.')
    lines.append('')

    errors = [e for e in entries if e.level in ('ERROR', 'FATAL', 'CRITICAL')]
    errors.sort(key=lambda e: e.timestamp or datetime.min, reverse=True)
    lines.append('## Recent Errors (up to 20)')
    lines.append('')
    if errors:
        for e in errors[:20]:
            ts = e.timestamp.strftime('%Y-%m-%d %H:%M:%S') if e.timestamp else '-'
            msg = mask_sensitive(e.raw) if getattr(args, 'mask', None) else e.raw
            lines.append(f'- `[{ts}] [{e.level}] {msg}`')
    else:
        lines.append('No error entries found.')
    lines.append('')

    if getattr(args, 'alert', False):
        lines.append('## Alert Summary')
        lines.append('')
        alert = build_alert_summary(
            entries,
            group_by=getattr(args, 'alert_group_by', 'service,code'),
            top_n=getattr(args, 'alert_top', 10),
        )
        if alert['rows']:
            lines.append(f'Grouped by: `{alert["group_by"]}`')
            lines.append(f'Total errors: {alert["total"]} (across {alert["groups"]} groups)')
            lines.append('')
            lines.append('| ' + ' | '.join(alert['headers']) + ' |')
            lines.append('|' + '|'.join('---' for _ in alert['headers']) + '|')
            for row in alert['rows']:
                lines.append('| ' + ' | '.join(row) + ' |')
        else:
            lines.append('No alert data available.')
        lines.append('')

    if getattr(args, 'spike', False):
        lines.append('## Spike Detection')
        lines.append('')
        buckets = defaultdict(int)
        for e in entries:
            if e.timestamp and e.level in ('ERROR', 'FATAL', 'CRITICAL'):
                bucket = e.timestamp.replace(minute=0, second=0, microsecond=0)
                buckets[bucket] += 1
        if buckets:
            sorted_buckets = sorted(buckets.items())
            values = [v for _, v in sorted_buckets]
            mean = sum(values) / len(values)
            std = math.sqrt(sum((v - mean) ** 2 for v in values) / len(values)) if len(values) > 1 else 0
            sigma = getattr(args, 'spike_sigma', 2.0)
            threshold = mean + sigma * std if std > 0 else mean + 1
            lines.append('| Time Window | Error Count | Status |')
            lines.append('|-------------|-------------|--------|')
            for ts, cnt in sorted_buckets:
                status = '!! SPIKE' if cnt > threshold else 'OK'
                lines.append(f'| {ts.strftime("%Y-%m-%d %H:%M")} | {cnt} | {status} |')
        else:
            lines.append('No error entries with timestamps for spike detection.')
        lines.append('')

    if getattr(args, 'save_rule', None):
        rule_name = args.save_rule
        rule_data = {}
        for key in ('start', 'end', 'level', 'keyword', 'mask', 'pattern'):
            val = getattr(args, key, '')
            if val:
                rule_data[key] = val
        if rule_name in rules and not getattr(args, 'force', False):
            if not confirm_prompt(f"Rule '{rule_name}' already exists. Overwrite?"):
                print("Save cancelled.", file=sys.stderr)
            else:
                rules[rule_name] = rule_data
                save_rules(rules, rules_path)
                print(f"Rule '{rule_name}' updated.", file=sys.stderr)
        else:
            rules[rule_name] = rule_data
            save_rules(rules, rules_path)
            print(f"Rule '{rule_name}' saved.", file=sys.stderr)

    output = '\n'.join(lines)
    if getattr(args, 'output', None):
        with open(args.output, 'w', encoding='utf-8') as fh:
            fh.write(output)
        print(f"Report saved to {args.output}")
    else:
        print(output)


def cmd_list_rules(args):
    rules_path = args.rules if getattr(args, 'rules', None) else DEFAULT_RULES_FILE
    rules = load_rules(rules_path)
    if not rules:
        print(f"No rules found in {rules_path}")
        return
    print(f"Rules file: {rules_path}")
    print()
    headers = ['Rule Name', 'Fields', 'Description']
    rows = []
    for name, data in sorted(rules.items()):
        fields = ', '.join(sorted(data.keys()))
        desc = data.get('description', '')
        if not desc:
            desc_parts = []
            if data.get('level'):
                desc_parts.append(f"level={data['level']}")
            if data.get('keyword'):
                desc_parts.append(f"kw={data['keyword'][:20]}")
            if data.get('start') or data.get('end'):
                desc_parts.append("time-range")
            desc = ', '.join(desc_parts) if desc_parts else '-'
        rows.append([name, fields, desc])
    print(format_table(headers, rows))
    print(f"\nTotal: {len(rules)} rule(s)")


def cmd_show_rule(args):
    rules_path = args.rules if getattr(args, 'rules', None) else DEFAULT_RULES_FILE
    rules = load_rules(rules_path)
    name = args.name
    if name not in rules:
        print(f"[ERROR] Rule '{name}' not found in {rules_path}", file=sys.stderr)
        sys.exit(1)
    rule = rules[name]
    print(f"Rule: {name}")
    print(f"File: {rules_path}")
    print()
    headers = ['Field', 'Value']
    rows = []
    for key, val in sorted(rule.items()):
        rows.append([key, str(val)])
    print(format_table(headers, rows))


def cmd_delete_rule(args):
    rules_path = args.rules if getattr(args, 'rules', None) else DEFAULT_RULES_FILE
    rules = load_rules(rules_path)
    name = args.name
    if name not in rules:
        print(f"[ERROR] Rule '{name}' not found in {rules_path}", file=sys.stderr)
        sys.exit(1)
    if not getattr(args, 'force', False):
        if not confirm_prompt(f"Delete rule '{name}' from {rules_path}?"):
            print("Delete cancelled.")
            return
    del rules[name]
    save_rules(rules, rules_path)
    print(f"Rule '{name}' deleted.")


def build_parser():
    parser = argparse.ArgumentParser(
        prog='logscope',
        description='LogScope - Log analysis CLI for ops personnel',
    )
    parser.add_argument('--version', action='version', version=f'%(prog)s {VERSION}')

    sub = parser.add_subparsers(dest='command', help='Available commands')

    # --- scan ---
    p_scan = sub.add_parser('scan', help='Scan log directory and list files with stats')
    p_scan.add_argument('directory', help='Log directory or file path')
    p_scan.add_argument('--pattern', default='*.log', help='File glob pattern (default: *.log)')

    # --- filter ---
    p_filter = sub.add_parser('filter', help='Filter logs by time, keyword, level')
    p_filter.add_argument('directory', help='Log directory or file path')
    p_filter.add_argument('--pattern', default='*.log', help='File glob pattern')
    p_filter.add_argument('--start', help='Start time (e.g. "2024-01-01 00:00:00" or "-1h")')
    p_filter.add_argument('--end', help='End time (e.g. "2024-01-01 23:59:59" or "now")')
    p_filter.add_argument('--include-no-ts', action='store_true',
                          help='Include entries without a valid timestamp in time-range filters')
    p_filter.add_argument('--keyword', help='Keyword to search (case-insensitive)')
    p_filter.add_argument('--level', help='Log level filter (comma-separated: ERROR,WARN)')
    p_filter.add_argument('--trace-id', help='Filter by trace/request ID')
    p_filter.add_argument('--error-code', help='Filter by error code')
    p_filter.add_argument('--mask', help='Comma-separated sensitive field names to mask')
    p_filter.add_argument('--invert', action='store_true', help='Invert filter (exclude matching)')
    p_filter.add_argument('--limit', type=int, default=50, help='Max entries to display (default: 50)')
    p_filter.add_argument('--use-rule', help='Apply a saved rule by name')
    p_filter.add_argument('--rules', help='Rules file path')

    # --- trace ---
    p_trace = sub.add_parser('trace', help='Trace request chain by trace ID')
    p_trace.add_argument('directory', help='Log directory or file path')
    p_trace.add_argument('--pattern', default='*.log', help='File glob pattern')
    p_trace.add_argument('--trace-id', help='Trace/request ID to follow')
    p_trace.add_argument('--mask', help='Comma-separated sensitive field names to mask')

    # --- stat ---
    p_stat = sub.add_parser('stat', help='Error code ranking, spike detection, alert summary')
    p_stat.add_argument('directory', help='Log directory or file path')
    p_stat.add_argument('--pattern', default='*.log', help='File glob pattern')
    p_stat.add_argument('--start', help='Start time')
    p_stat.add_argument('--end', help='End time')
    p_stat.add_argument('--include-no-ts', action='store_true',
                        help='Include entries without a valid timestamp in time-range filters')
    p_stat.add_argument('--spike', action='store_true', help='Enable spike detection')
    p_stat.add_argument('--spike-sigma', type=float, default=2.0,
                        help='Spike threshold in standard deviations (default: 2.0)')
    p_stat.add_argument('--alert', action='store_true',
                        help='Enable alert summary aggregated by service/host/error code')
    p_stat.add_argument('--alert-group-by', default='service,code',
                        help='Alert aggregation keys (comma-separated: service,host,code,level,trace)')
    p_stat.add_argument('--alert-top', type=int, default=10,
                        help='Top N alert groups to show (default: 10)')
    p_stat.add_argument('--json', action='store_true', help='Output as JSON')
    p_stat.add_argument('--output', help='Save output to file (works with --json)')

    # --- diff ---
    p_diff = sub.add_parser('diff', help='Compare logs between two time periods')
    p_diff.add_argument('directory', help='Log directory or file path')
    p_diff.add_argument('--pattern', default='*.log', help='File glob pattern')
    p_diff.add_argument('--a-start', required=True, help='Period A start time')
    p_diff.add_argument('--a-end', required=True, help='Period A end time')
    p_diff.add_argument('--b-start', required=True, help='Period B start time')
    p_diff.add_argument('--b-end', required=True, help='Period B end time')
    p_diff.add_argument('--include-no-ts', action='store_true',
                        help='Include entries without a valid timestamp in time-range filters')

    # --- report ---
    p_report = sub.add_parser('report', help='Generate Markdown or JSON analysis report')
    p_report.add_argument('directory', help='Log directory or file path')
    p_report.add_argument('--pattern', default='*.log', help='File glob pattern')
    p_report.add_argument('--start', help='Start time')
    p_report.add_argument('--end', help='End time')
    p_report.add_argument('--include-no-ts', action='store_true',
                          help='Include entries without a valid timestamp in time-range filters')
    p_report.add_argument('--level', help='Log level filter')
    p_report.add_argument('--keyword', help='Keyword filter')
    p_report.add_argument('--mask', help='Comma-separated sensitive field names to mask')
    p_report.add_argument('--output', help='Output file path')
    p_report.add_argument('--json', action='store_true', help='Output report as JSON')
    p_report.add_argument('--spike', action='store_true', help='Include spike detection in report')
    p_report.add_argument('--spike-sigma', type=float, default=2.0,
                          help='Spike threshold sigma (default: 2.0)')
    p_report.add_argument('--alert', action='store_true',
                          help='Include alert summary in report')
    p_report.add_argument('--alert-group-by', default='service,code',
                          help='Alert aggregation keys (comma-separated)')
    p_report.add_argument('--alert-top', type=int, default=10,
                          help='Top N alert groups (default: 10)')
    p_report.add_argument('--rules', help='Rules file path')
    p_report.add_argument('--use-rule', help='Apply a saved rule by name')
    p_report.add_argument('--save-rule', help='Save current filters as a named rule')
    p_report.add_argument('-f', '--force', action='store_true',
                          help='Force overwrite existing rule without confirmation')

    # --- list-rules ---
    p_list_rules = sub.add_parser('list-rules', help='List all saved rules')
    p_list_rules.add_argument('--rules', help='Rules file path')

    # --- show-rule ---
    p_show_rule = sub.add_parser('show-rule', help='Show details of a saved rule')
    p_show_rule.add_argument('name', help='Rule name')
    p_show_rule.add_argument('--rules', help='Rules file path')

    # --- delete-rule ---
    p_del_rule = sub.add_parser('delete-rule', help='Delete a saved rule')
    p_del_rule.add_argument('name', help='Rule name')
    p_del_rule.add_argument('--rules', help='Rules file path')
    p_del_rule.add_argument('-f', '--force', action='store_true',
                            help='Force delete without confirmation')

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)
    cmd_map = {
        'scan': cmd_scan,
        'filter': cmd_filter,
        'trace': cmd_trace,
        'stat': cmd_stat,
        'diff': cmd_diff,
        'report': cmd_report,
        'list-rules': cmd_list_rules,
        'show-rule': cmd_show_rule,
        'delete-rule': cmd_delete_rule,
    }
    cmd_map[args.command](args)


if __name__ == '__main__':
    main()
