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

VERSION = "1.0.0"
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

LEVEL_PATTERN = (
    r'\[(?:LEVEL\s*[:=]?\s*)?'
    r'(DEBUG|INFO|WARN(?:ING)?|ERROR|FATAL|CRITICAL)'
    r'\]'
)
TRACE_ID_PATTERN = (
    r'(?:trace[-_]?id|request[-_]?id|req[-_]?id|rid|txn[-_]?id)'
    r'[=:\s]+["\']?([a-zA-Z0-9\-_]+)["\']?'
)
ERROR_CODE_PATTERN = (
    r'(?:error[-_]?code|status[-_]?code|err[-_]?code|code)'
    r'[=:\s]+["\']?(\d{3,})["\']?'
)

SENSITIVE_KEYS = [
    'password', 'passwd', 'token', 'secret', 'api_key', 'apikey',
    'access_key', 'private_key', 'credit_card', 'ssn', 'email',
    'phone', 'mobile', 'authorization', 'cookie',
]


class LogEntry:
    __slots__ = [
        'raw', 'timestamp', 'level', 'trace_id',
        'error_code', 'file_path', 'line_num',
    ]

    def __init__(self, raw='', timestamp=None, level='',
                 trace_id='', error_code='', file_path='', line_num=0):
        self.raw = raw
        self.timestamp = timestamp
        self.level = level.upper() if level else ''
        self.trace_id = trace_id
        self.error_code = error_code
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
    m = re.search(LEVEL_PATTERN, text, re.IGNORECASE)
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


def parse_line(line, file_path='', line_num=0):
    return LogEntry(
        raw=line,
        timestamp=parse_timestamp(line),
        level=parse_level(line),
        trace_id=parse_trace_id(line),
        error_code=parse_error_code(line),
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
                   level=None, trace_id=None, error_code=None, invert=False):
    result = []
    for e in entries:
        match = True
        if start and e.timestamp and e.timestamp < start:
            match = False
        if end and e.timestamp and e.timestamp > end:
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
    filtered = filter_entries(
        entries, start=start, end=end,
        keyword=args.keyword, level=args.level,
        trace_id=args.trace_id, error_code=args.error_code,
        invert=getattr(args, 'invert', False),
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
    if start or end:
        entries = filter_entries(entries, start=start, end=end)

    code_counter = Counter(e.error_code for e in entries if e.error_code)
    level_counter = Counter(e.level for e in entries if e.level)

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

    period_a = filter_entries(entries, start=a_start, end=a_end)
    period_b = filter_entries(entries, start=b_start, end=b_end)

    codes_a = Counter(e.error_code for e in period_a if e.error_code)
    codes_b = Counter(e.error_code for e in period_b if e.error_code)
    levels_a = Counter(e.level for e in period_a if e.level)
    levels_b = Counter(e.level for e in period_b if e.level)

    print(f"Period A: {a_start} ~ {a_end} ({len(period_a)} entries)")
    print(f"Period B: {b_start} ~ {b_end} ({len(period_b)} entries)")

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

    rules = {}
    if args.rules:
        rules = load_rules(args.rules)

    if args.use_rule and args.use_rule in rules:
        apply_rule_to_args(args, rules[args.use_rule])

    entries = read_log_entries(files)

    if args.start or args.end:
        start = parse_time_arg(args.start) if args.start else None
        end = parse_time_arg(args.end) if args.end else None
        entries = filter_entries(entries, start=start, end=end)
    if args.level:
        entries = filter_entries(entries, level=args.level)
    if args.keyword:
        entries = filter_entries(entries, keyword=args.keyword)

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
            msg = mask_sensitive(e.raw) if args.mask else e.raw
            lines.append(f'- `[{ts}] [{e.level}] {msg}`')
    else:
        lines.append('No error entries found.')
    lines.append('')

    if args.spike:
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

    if args.save_rule:
        rule_name = args.save_rule
        rule_data = {}
        for key in ('start', 'end', 'level', 'keyword', 'mask', 'pattern'):
            val = getattr(args, key, '')
            if val:
                rule_data[key] = val
        rules[rule_name] = rule_data
        save_rules(rules, args.rules)
        print(f"Rule '{rule_name}' saved.", file=sys.stderr)

    output = '\n'.join(lines)
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as fh:
            fh.write(output)
        print(f"Report saved to {args.output}")
    else:
        print(output)


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
    p_stat = sub.add_parser('stat', help='Error code ranking and spike detection')
    p_stat.add_argument('directory', help='Log directory or file path')
    p_stat.add_argument('--pattern', default='*.log', help='File glob pattern')
    p_stat.add_argument('--start', help='Start time')
    p_stat.add_argument('--end', help='End time')
    p_stat.add_argument('--spike', action='store_true', help='Enable spike detection')
    p_stat.add_argument('--spike-sigma', type=float, default=2.0,
                        help='Spike threshold in standard deviations (default: 2.0)')

    # --- diff ---
    p_diff = sub.add_parser('diff', help='Compare logs between two time periods')
    p_diff.add_argument('directory', help='Log directory or file path')
    p_diff.add_argument('--pattern', default='*.log', help='File glob pattern')
    p_diff.add_argument('--a-start', required=True, help='Period A start time')
    p_diff.add_argument('--a-end', required=True, help='Period A end time')
    p_diff.add_argument('--b-start', required=True, help='Period B start time')
    p_diff.add_argument('--b-end', required=True, help='Period B end time')

    # --- report ---
    p_report = sub.add_parser('report', help='Generate Markdown analysis report')
    p_report.add_argument('directory', help='Log directory or file path')
    p_report.add_argument('--pattern', default='*.log', help='File glob pattern')
    p_report.add_argument('--start', help='Start time')
    p_report.add_argument('--end', help='End time')
    p_report.add_argument('--level', help='Log level filter')
    p_report.add_argument('--keyword', help='Keyword filter')
    p_report.add_argument('--mask', help='Comma-separated sensitive field names to mask')
    p_report.add_argument('--output', help='Output Markdown file path')
    p_report.add_argument('--spike', action='store_true', help='Include spike detection in report')
    p_report.add_argument('--spike-sigma', type=float, default=2.0,
                          help='Spike threshold sigma (default: 2.0)')
    p_report.add_argument('--rules', help='Rules file path')
    p_report.add_argument('--use-rule', help='Apply a saved rule by name')
    p_report.add_argument('--save-rule', help='Save current filters as a named rule')

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
    }
    cmd_map[args.command](args)


if __name__ == '__main__':
    main()
