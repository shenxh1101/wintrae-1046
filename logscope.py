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

VERSION = "1.3.0"
DEFAULT_RULES_FILE = os.path.join(str(Path.home()), ".logscope_rules.json")
DEFAULT_HISTORY_FILE = os.path.join(str(Path.home()), ".logscope_history.json")

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
        time_match = True
        cond_match = True

        if start or end:
            if not e.timestamp:
                if not include_no_ts:
                    time_match = False
            else:
                if start and e.timestamp < start:
                    time_match = False
                if end and e.timestamp > end:
                    time_match = False

        if keyword and keyword.lower() not in e.raw.lower():
            cond_match = False
        if level:
            levels = [l.upper() for l in level.split(',')]
            if e.level not in levels:
                cond_match = False
        if trace_id and trace_id not in e.trace_id:
            cond_match = False
        if error_code and error_code != e.error_code:
            cond_match = False

        if invert:
            cond_match = not cond_match

        if time_match and cond_match:
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


def load_history(path=None):
    path = path or DEFAULT_HISTORY_FILE
    if os.path.exists(path):
        try:
            with open(path, encoding='utf-8') as fh:
                return json.load(fh)
        except (json.JSONDecodeError, OSError):
            return []
    return []


def save_history(records, path=None):
    path = path or DEFAULT_HISTORY_FILE
    with open(path, 'w', encoding='utf-8') as fh:
        json.dump(records, fh, indent=2, ensure_ascii=False)


def append_check_history(record, path=None):
    records = load_history(path)
    records.append(record)
    save_history(records, path)


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
    group_keys = [g.strip().lower() for g in alert_summary['group_by'].split(',')]
    key_name_map = {
        'code': 'code', 'error_code': 'code', 'errcode': 'code',
        'service': 'service', 'svc': 'service', 'app': 'service',
        'host': 'host', 'hostname': 'host', 'server': 'host',
        'level': 'level', 'lvl': 'level',
        'trace': 'trace_id', 'trace_id': 'trace_id',
    }
    canonical_keys = [key_name_map.get(g, g) for g in group_keys]

    data = {
        'group_by': alert_summary['group_by'],
        'total_errors': alert_summary['total'],
        'distinct_groups': alert_summary['groups'],
        'top_items': []
    }
    for row in alert_summary['rows']:
        item = {}
        for i, ck in enumerate(canonical_keys):
            item[ck] = row[i]
        item['count'] = int(row[-1])
        data['top_items'].append(item)

    if entries:
        data['_meta'] = {
            'total_entries': len(entries),
            'timestamped_entries': sum(1 for e in entries if e.timestamp),
        }
    return data


def load_baseline_report(path):
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, encoding='utf-8') as fh:
            data = json.load(fh)
        return data
    except (json.JSONDecodeError, OSError) as exc:
        print(f"[WARN] Cannot load baseline {path}: {exc}", file=sys.stderr)
        return None


def compare_alert_baseline(current_alert_json, baseline_data, top_n=10):
    if not baseline_data or 'alert_summary' not in baseline_data:
        return {
            'new_items': [],
            'disappeared_items': [],
            'top_growth': [],
            'top_decline': [],
            'baseline_available': False,
        }

    baseline = baseline_data['alert_summary']
    current = current_alert_json

    group_keys = [g.strip().lower() for g in current.get('group_by', 'service,code').split(',')]
    key_name_map = {
        'code': 'code', 'error_code': 'code', 'errcode': 'code',
        'service': 'service', 'svc': 'service', 'app': 'service',
        'host': 'host', 'hostname': 'host', 'server': 'host',
        'level': 'level', 'lvl': 'level',
        'trace': 'trace_id', 'trace_id': 'trace_id',
    }
    canonical_keys = [key_name_map.get(g, g) for g in group_keys]

    key_alias_map = {
        'code': ['code', 'error_code', 'errorcode', 'errcode'],
        'service': ['service', 'svc', 'app'],
        'host': ['host', 'hostname', 'server'],
        'level': ['level', 'lvl'],
        'trace_id': ['trace_id', 'traceid', 'trace'],
    }

    def make_key(item):
        parts = []
        for ck in canonical_keys:
            val = None
            aliases = key_alias_map.get(ck, [ck])
            for alias in aliases:
                if alias in item:
                    val = item[alias]
                    break
            parts.append(str(val if val is not None else '-'))
        return tuple(parts)

    baseline_items = {}
    for item in baseline.get('top_items', []):
        key = make_key(item)
        baseline_items[key] = item.get('count', 0)

    current_items = {}
    for item in current.get('top_items', []):
        key = make_key(item)
        current_items[key] = (item, item.get('count', 0))

    new_items = []
    for key, (item, cnt) in current_items.items():
        if key not in baseline_items:
            new_items.append((item, cnt))

    disappeared_items = []
    for key, cnt in baseline_items.items():
        if key not in current_items:
            disappeared_items.append((key, cnt))

    growth_items = []
    for key, (item, cur_cnt) in current_items.items():
        base_cnt = baseline_items.get(key, 0)
        delta = cur_cnt - base_cnt
        if delta > 0:
            rate = (delta / base_cnt * 100) if base_cnt > 0 else float('inf')
            growth_items.append((item, base_cnt, cur_cnt, delta, rate))

    growth_items.sort(key=lambda x: (-x[4], -x[3]))
    top_growth = growth_items[:top_n]

    decline_items = []
    for key, (item, cur_cnt) in current_items.items():
        base_cnt = baseline_items.get(key, 0)
        if base_cnt > 0:
            delta = cur_cnt - base_cnt
            rate = (delta / base_cnt) * 100
            if delta < 0:
                decline_items.append((item, base_cnt, cur_cnt, delta, rate))

    decline_items.sort(key=lambda x: (x[4], x[3]))
    top_decline = decline_items[:top_n]

    return {
        'new_items': new_items,
        'disappeared_items': disappeared_items,
        'top_growth': top_growth,
        'top_decline': top_decline,
        'baseline_available': True,
        'canonical_keys': canonical_keys,
    }


def _item_get(item, canonical_key):
    key_alias_map = {
        'code': ['code', 'error_code', 'errorcode', 'errcode'],
        'service': ['service', 'svc', 'app'],
        'host': ['host', 'hostname', 'server'],
        'level': ['level', 'lvl'],
        'trace_id': ['trace_id', 'traceid', 'trace'],
    }
    aliases = key_alias_map.get(canonical_key, [canonical_key])
    for alias in aliases:
        if alias in item:
            return str(item[alias])
    return '-'


def format_baseline_comparison(comparison, group_by):
    lines = []
    header_map = {
        'code': 'ErrorCode', 'error_code': 'ErrorCode', 'errcode': 'ErrorCode',
        'service': 'Service', 'svc': 'Service', 'app': 'Service',
        'host': 'Host', 'hostname': 'Host', 'server': 'Host',
        'level': 'Level', 'lvl': 'Level',
        'trace': 'TraceID', 'trace_id': 'TraceID',
    }

    canonical_keys = comparison.get('canonical_keys',
                                    [g.strip().lower() for g in group_by.split(',')])
    display_headers = [header_map.get(ck, ck) for ck in canonical_keys]

    if not comparison['baseline_available']:
        return "[Baseline comparison skipped - no valid baseline file provided]\n"

    if comparison['new_items']:
        lines.append("=== New Alert Combinations (not in baseline) ===")
        headers_t = display_headers + ['Current Count']
        rows = []
        for item, cnt in comparison['new_items']:
            row = [_item_get(item, ck) for ck in canonical_keys]
            row.append(str(cnt))
            rows.append(row)
        lines.append(format_table(headers_t, rows))
        lines.append(f"\nTotal new combinations: {len(comparison['new_items'])}")
        lines.append('')

    if comparison['top_growth']:
        lines.append("=== Top Growth Alert Combinations ===")
        headers_t = display_headers + ['Baseline', 'Current', 'Delta', 'Growth%']
        rows = []
        for item, base_cnt, cur_cnt, delta, rate in comparison['top_growth']:
            row = [_item_get(item, ck) for ck in canonical_keys]
            rate_str = 'INF%' if rate == float('inf') else f'{rate:+.1f}%'
            rows.append(row + [str(base_cnt), str(cur_cnt), f'{delta:+d}', rate_str])
        lines.append(format_table(headers_t, rows))
        lines.append('')

    if comparison['top_decline']:
        lines.append("=== Top Decline Alert Combinations ===")
        headers_t = display_headers + ['Baseline', 'Current', 'Delta', 'Decline%']
        rows = []
        for item, base_cnt, cur_cnt, delta, rate in comparison['top_decline']:
            row = [_item_get(item, ck) for ck in canonical_keys]
            rows.append(row + [str(base_cnt), str(cur_cnt), f'{delta:+d}', f'{rate:.1f}%'])
        lines.append(format_table(headers_t, rows))
        lines.append('')

    if comparison['disappeared_items']:
        lines.append(f"=== Disappeared from Baseline ({len(comparison['disappeared_items'])} items) ===")
        for key, cnt in comparison['disappeared_items'][:20]:
            lines.append(f"  {', '.join(key)}: {cnt}")
        if len(comparison['disappeared_items']) > 20:
            lines.append(f"  ... and {len(comparison['disappeared_items']) - 20} more")
        lines.append('')

    return '\n'.join(lines)


def baseline_comparison_to_json(comparison, group_by):
    canonical_keys = comparison.get('canonical_keys',
                                    [g.strip().lower() for g in group_by.split(',')])
    data = {
        'baseline_available': comparison['baseline_available'],
        'new_items': [],
        'top_growth': [],
        'top_decline': [],
        'disappeared_count': len(comparison['disappeared_items']),
    }
    for item, cnt in comparison['new_items']:
        entry = {ck: _item_get(item, ck) for ck in canonical_keys}
        entry['count'] = cnt
        data['new_items'].append(entry)

    for item, base_cnt, cur_cnt, delta, rate in comparison['top_growth']:
        entry = {ck: _item_get(item, ck) for ck in canonical_keys}
        entry.update({
            'baseline_count': base_cnt,
            'current_count': cur_cnt,
            'delta': delta,
            'growth_rate': None if rate == float('inf') else round(rate, 2),
        })
        data['top_growth'].append(entry)

    for item, base_cnt, cur_cnt, delta, rate in comparison['top_decline']:
        entry = {ck: _item_get(item, ck) for ck in canonical_keys}
        entry.update({
            'baseline_count': base_cnt,
            'current_count': cur_cnt,
            'delta': delta,
            'decline_rate': round(rate, 2),
        })
        data['top_decline'].append(entry)

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

    alert_group_by = getattr(args, 'alert_group_by', 'service,code')
    alert_top = getattr(args, 'alert_top', 10)

    baseline_path = getattr(args, 'baseline', None)
    baseline_data = load_baseline_report(baseline_path)
    comparison = None

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
                entries, group_by=alert_group_by, top_n=alert_top,
            )
            alert_json = alert_summary_to_json(alert, entries)
            data['alert_summary'] = alert_json
            if baseline_data and baseline_data.get('alert_summary'):
                comparison = compare_alert_baseline(alert_json, baseline_data, top_n=alert_top)
                data['baseline_comparison'] = baseline_comparison_to_json(comparison, alert_group_by)

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
            entries, group_by=alert_group_by, top_n=alert_top,
        )
        if alert['rows']:
            print(f"Grouped by: {alert['group_by']}")
            print(f"Total errors: {alert['total']} (across {alert['groups']} groups)")
            print(format_table(alert['headers'], alert['rows']))

            if baseline_data:
                alert_json = alert_summary_to_json(alert, entries)
                comparison = compare_alert_baseline(alert_json, baseline_data, top_n=alert_top)
                print()
                print(format_baseline_comparison(comparison, alert_group_by))
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

    alert_group_by = getattr(args, 'alert_group_by', 'service,code')
    alert_top = getattr(args, 'alert_top', 10)

    baseline_path = getattr(args, 'baseline', None)
    baseline_data = load_baseline_report(baseline_path)
    comparison = None

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
                entries, group_by=alert_group_by, top_n=alert_top,
            )
            alert_json = alert_summary_to_json(alert, entries)
            data['alert_summary'] = alert_json
            if baseline_data and baseline_data.get('alert_summary'):
                comparison = compare_alert_baseline(alert_json, baseline_data, top_n=alert_top)
                data['baseline_comparison'] = baseline_comparison_to_json(comparison, alert_group_by)
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
            entries, group_by=alert_group_by, top_n=alert_top,
        )
        if alert['rows']:
            lines.append(f'Grouped by: `{alert["group_by"]}`')
            lines.append(f'Total errors: {alert["total"]} (across {alert["groups"]} groups)')
            lines.append('')
            lines.append('| ' + ' | '.join(alert['headers']) + ' |')
            lines.append('|' + '|'.join('---' for _ in alert['headers']) + '|')
            for row in alert['rows']:
                lines.append('| ' + ' | '.join(row) + ' |')

            if baseline_data and baseline_data.get('alert_summary'):
                alert_json = alert_summary_to_json(alert, entries)
                comparison = compare_alert_baseline(alert_json, baseline_data, top_n=alert_top)
                if comparison['baseline_available']:
                    canonical_keys = comparison.get('canonical_keys',
                                                    [g.strip().lower() for g in alert_group_by.split(',')])
                    header_map = {
                        'code': 'ErrorCode', 'error_code': 'ErrorCode', 'errcode': 'ErrorCode',
                        'service': 'Service', 'svc': 'Service', 'app': 'Service',
                        'host': 'Host', 'hostname': 'Host', 'server': 'Host',
                        'level': 'Level', 'lvl': 'Level',
                        'trace': 'TraceID', 'trace_id': 'TraceID',
                    }
                    display_headers = [header_map.get(ck, ck) for ck in canonical_keys]
                    lines.append('')
                    lines.append('## Baseline Comparison')
                    lines.append('')
                    if comparison['new_items']:
                        lines.append('### New Alert Combinations (not in baseline)')
                        lines.append('')
                        headers_t = display_headers + ['Count']
                        lines.append('| ' + ' | '.join(headers_t) + ' |')
                        lines.append('|' + '|'.join('---' for _ in headers_t) + '|')
                        for item, cnt in comparison['new_items']:
                            row = [str(_item_get(item, ck)) for ck in canonical_keys]
                            row.append(str(cnt))
                            lines.append('| ' + ' | '.join(row) + ' |')
                        lines.append(f'\nTotal new combinations: **{len(comparison["new_items"])}**')
                        lines.append('')

                    if comparison['top_growth']:
                        lines.append('### Top Growth Alert Combinations')
                        lines.append('')
                        headers_t = display_headers + ['Baseline', 'Current', 'Delta', 'Growth%']
                        lines.append('| ' + ' | '.join(headers_t) + ' |')
                        lines.append('|' + '|'.join('---' for _ in headers_t) + '|')
                        for item, base_cnt, cur_cnt, delta, rate in comparison['top_growth']:
                            row = [str(_item_get(item, ck)) for ck in canonical_keys]
                            rate_str = 'INF%' if rate == float('inf') else f'{rate:+.1f}%'
                            row += [str(base_cnt), str(cur_cnt), f'{delta:+d}', rate_str]
                            lines.append('| ' + ' | '.join(row) + ' |')
                        lines.append('')

                    if comparison['top_decline']:
                        lines.append('### Top Decline Alert Combinations')
                        lines.append('')
                        headers_t = display_headers + ['Baseline', 'Current', 'Delta', 'Decline%']
                        lines.append('| ' + ' | '.join(headers_t) + ' |')
                        lines.append('|' + '|'.join('---' for _ in headers_t) + '|')
                        for item, base_cnt, cur_cnt, delta, rate in comparison['top_decline']:
                            row = [str(_item_get(item, ck)) for ck in canonical_keys]
                            row += [str(base_cnt), str(cur_cnt), f'{delta:+d}', f'{rate:.1f}%']
                            lines.append('| ' + ' | '.join(row) + ' |')
                        lines.append('')
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

    history_file_arg = getattr(args, 'history', None)
    history_n = getattr(args, 'history_n', 10) or 10
    if history_file_arg:
        hist_records = load_history(history_file_arg)
        if hist_records:
            recent = hist_records[-history_n:]
            lines.append('## Historical Check Trend')
            lines.append('')
            lines.append(f'Source: `{history_file_arg}` (last {len(recent)} checks)')
            lines.append('')
            errors_list = [r.get('error_count', 0) for r in recent]
            cur_error_count = sum(1 for e in entries if e.level in ('ERROR', 'FATAL', 'CRITICAL'))
            avg_err = sum(errors_list) / len(errors_list) if errors_list else 0
            max_err = max(errors_list) if errors_list else 0
            warning_flag = ''
            if len(errors_list) >= 3 and cur_error_count > max_err:
                warning_flag = ' ⚠️ **HIGHEST IN RECENT HISTORY**'
            elif cur_error_count > avg_err * 1.5 and avg_err > 0:
                warning_flag = ' ⚠️ **1.5x ABOVE RECENT AVERAGE**'
            elif cur_error_count > avg_err * 1.2 and avg_err > 0:
                warning_flag = ' ⚠️ Above recent average'
            lines.append(f'Current report errors: **{cur_error_count}** vs. avg {avg_err:.1f}, max {max_err}{warning_flag}')
            lines.append('')
            lines.append('| # | Timestamp | Status | Errors | Delta | New Alerts | Spikes |')
            lines.append('|---|-----------|--------|--------|-------|------------|--------|')
            for i, r in enumerate(recent, 1):
                err_c = r.get('error_count', 0)
                delta = r.get('error_delta', 0)
                new_a = r.get('new_alerts', 0)
                sp_c = r.get('spike_count', 0)
                st = r.get('status', '-')
                if st == 'WARN':
                    st_cell = '🔴 WARN'
                else:
                    st_cell = '🟢 OK'
                lines.append(f'| {i} | {r.get("timestamp", "-")} | {st_cell} | {err_c} | {delta:+d} | {new_a} | {sp_c} |')
            if len(errors_list) >= 3:
                lines.append('')
                lines.append(f"**Stats across last {len(errors_list)} checks:** avg={avg_err:.1f}, min={min(errors_list)}, max={max_err}")
                if cur_error_count > avg_err * 1.2 and avg_err > 0:
                    lines.append('')
                    lines.append('> **Anomaly Detected** : 当前报告的错误数量明显高于历史平均水平，建议立即排查。')
            lines.append('')

    if getattr(args, 'save_rule', None):
        rule_name = args.save_rule
        rule_data = {}
        for key in ('start', 'end', 'level', 'keyword', 'mask', 'pattern',
                    'baseline', 'alert_group_by'):
            val = getattr(args, key, '')
            if val:
                rule_data[key] = val
        if getattr(args, 'rule_description', None):
            rule_data['description'] = args.rule_description
        if getattr(args, 'rule_output_dir', None):
            rule_data['output_dir'] = args.rule_output_dir
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


def cmd_history(args):
    history_path = getattr(args, 'history', None) or DEFAULT_HISTORY_FILE
    records = load_history(history_path)
    if not records:
        print(f"No check history found in {history_path}")
        return

    detail_idx = getattr(args, 'detail', None)
    if detail_idx is not None:
        if detail_idx < 1 or detail_idx > len(records):
            print(f"[ERROR] --detail index out of range (1 to {len(records)})", file=sys.stderr)
            sys.exit(1)
        rec = records[detail_idx - 1]
        snapshot = rec.get('snapshot', {})
        print(f"=== Check Record #{detail_idx} Detail ===")
        print(f"  Timestamp : {rec.get('timestamp', '-')}")
        print(f"  Status    : {rec.get('status', '-')}")
        print(f"  Period    : {rec.get('period_start', '-')} ~ {rec.get('period_end', '-')}")
        print(f"  Directory : {rec.get('directory', '-')}")
        print(f"  Errors    : {rec.get('error_count', 0)} ({rec.get('error_change', '0%')}, delta={rec.get('error_delta', 0):+d})")
        print(f"  New Alerts: {rec.get('new_alerts', 0)}")
        print(f"  Services  : {', '.join(rec.get('services', [])) or '-'}")
        print(f"  ErrorCodes: {', '.join(rec.get('error_codes', [])) or '-'}")
        if rec.get('reasons'):
            print(f"  Reasons   : {', '.join(rec['reasons'])}")
        print(f"  JSON Report: {rec.get('json_report', '-')}")
        print(f"  MD Report  : {rec.get('md_report', '-')}")
        print()

        if snapshot.get('top_codes'):
            print("=== Top Error Codes ===")
            headers = ['ErrorCode', 'Count']
            rows = [[t['code'], str(t['count'])] for t in snapshot['top_codes']]
            print(format_table(headers, rows))
            print()
        if snapshot.get('top_services'):
            print("=== Top Services ===")
            headers = ['Service', 'Count']
            rows = [[t['service'], str(t['count'])] for t in snapshot['top_services']]
            print(format_table(headers, rows))
            print()
        if snapshot.get('alert_rows'):
            print("=== Top Alert Groups ===")
            ar = snapshot['alert_rows']
            keys = [k for k in ar[0].keys() if k != 'count']
            headers = keys + ['Count']
            rows = [[str(r.get(k, '-')) for k in keys] + [str(r['count'])] for r in ar]
            print(format_table(headers, rows))
            print()
        if snapshot.get('top_growth'):
            print("=== Top Growth ===")
            tg = snapshot['top_growth']
            keys = [k for k in tg[0].keys() if k not in ('baseline_count', 'current_count', 'delta', 'growth_rate')]
            headers = keys + ['Baseline', 'Current', 'Delta', 'Growth%']
            rows = []
            for g in tg:
                rate = 'INF%' if g.get('growth_rate') is None else f"{g['growth_rate']:+.1f}%"
                rows.append([str(g.get(k, '-')) for k in keys] +
                            [str(g.get('baseline_count', 0)), str(g.get('current_count', 0)),
                             f"{g.get('delta', 0):+d}", rate])
            print(format_table(headers, rows))
            print()
        if snapshot.get('new_items'):
            print("=== New Alert Combinations ===")
            ni = snapshot['new_items']
            keys = [k for k in ni[0].keys() if k != 'count']
            headers = keys + ['Count']
            rows = [[str(r.get(k, '-')) for k in keys] + [str(r['count'])] for r in ni]
            print(format_table(headers, rows))
            print()
        if not snapshot:
            print("[No snapshot data - this record was archived before v1.3.0]")
        return

    summary_mode = getattr(args, 'summary', False)
    summary_days = getattr(args, 'days', 30) or 30

    status_filter = getattr(args, 'status', None)
    service_filter = getattr(args, 'service', None)
    code_filter = getattr(args, 'error_code', None)
    last_n = getattr(args, 'last', None)
    json_output = getattr(args, 'json', False)

    filtered = records
    if status_filter:
        status_filter = status_filter.upper()
        filtered = [r for r in filtered if r.get('status', '').upper() == status_filter]
    if service_filter:
        service_lower = service_filter.lower()
        filtered = [r for r in filtered
                    if any(s.lower() == service_lower for s in r.get('services', []))]
    if code_filter:
        filtered = [r for r in filtered if code_filter in r.get('error_codes', [])]

    if last_n and last_n > 0:
        filtered = filtered[-last_n:]

    if not filtered:
        print("No matching records found.")
        return

    if summary_mode:
        pass  # summary mode processes later (uses full records), skip default list output
    elif json_output:
        data = {
            'total_records': len(filtered),
            'history_file': history_path,
            'records': filtered,
        }
        output_path = getattr(args, 'output', None)
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as fh:
                json.dump(data, fh, indent=2, ensure_ascii=False)
            print(f"History JSON saved to {output_path}")
        else:
            print(json.dumps(data, indent=2, ensure_ascii=False))
        return
    else:
        print(f"Check History ({len(filtered)} records from {history_path})")
        print()

        headers = ['#', 'Timestamp', 'Status', 'Errors', 'Delta', 'New', 'Svc', 'Codes', 'Report']
        rows = []
        for i, r in enumerate(filtered, 1):
            svc_count = len(r.get('services', []))
            codes_str = ','.join(r.get('error_codes', [])[:3])
            if len(r.get('error_codes', [])) > 3:
                codes_str += '...'
            report_name = os.path.basename(r.get('json_report', '-'))
            rows.append([
                str(i),
                r.get('timestamp', '-'),
                r.get('status', '-'),
                str(r.get('error_count', 0)),
                f"{r.get('error_delta', 0):+d}",
                str(r.get('new_alerts', 0)),
                str(svc_count),
                codes_str or '-',
                report_name,
            ])
        print(format_table(headers, rows))

        if getattr(args, 'trend', False) and len(filtered) >= 2:
            print("\n=== Error Trend ===")
            trend_headers = ['Timestamp', 'Errors', 'Delta', 'Change', 'New Alerts', 'Spikes']
            trend_rows = []
            for r in filtered:
                trend_rows.append([
                    r.get('timestamp', '-'),
                    str(r.get('error_count', 0)),
                    f"{r.get('error_delta', 0):+d}",
                    r.get('error_change', '0%'),
                    str(r.get('new_alerts', 0)),
                    str(r.get('spike_count', 0)),
                ])
            print(format_table(trend_headers, trend_rows))

            if len(filtered) >= 3:
                errors_list = [r.get('error_count', 0) for r in filtered]
                avg_err = sum(errors_list) / len(errors_list)
                max_err = max(errors_list)
                min_err = min(errors_list)
                new_alerts_list = [r.get('new_alerts', 0) for r in filtered]
                total_new = sum(new_alerts_list)
                warn_count = sum(1 for r in filtered if r.get('status', '') == 'WARN')
                ok_count = sum(1 for r in filtered if r.get('status', '') == 'OK')
                print(f"\nStats across {len(filtered)} checks:")
                print(f"  Errors   : avg={avg_err:.1f}, min={min_err}, max={max_err}")
                print(f"  Status   : {ok_count} OK, {warn_count} WARN")
                print(f"  New alerts total: {total_new}")

    if summary_mode:
        today = datetime.now().date()
        cutoff = today - timedelta(days=summary_days - 1)
        date_records = {}
        for r in records:
            r_date_str = r.get('date', '')
            try:
                r_date = datetime.strptime(r_date_str, '%Y-%m-%d').date()
            except ValueError:
                continue
            if r_date < cutoff or r_date > today:
                continue
            if r_date_str not in date_records:
                date_records[r_date_str] = []
            date_records[r_date_str].append(r)

        daily_rows = []
        total_checks = 0
        total_ok = 0
        total_warn = 0
        total_errs = 0
        total_new = 0
        for d in sorted(date_records.keys()):
            recs = date_records[d]
            checks = len(recs)
            ok_n = sum(1 for r in recs if r.get('status', '') == 'OK')
            wn_n = sum(1 for r in recs if r.get('status', '') == 'WARN')
            errs = sum(r.get('error_count', 0) for r in recs)
            new_combos = sum(r.get('new_alerts', 0) for r in recs)
            total_checks += checks
            total_ok += ok_n
            total_warn += wn_n
            total_errs += errs
            total_new += new_combos
            spike_c = sum(r.get('spike_count', 0) for r in recs)
            daily_rows.append([d, str(checks), str(ok_n), str(wn_n),
                               str(errs), str(new_combos), str(spike_c)])

        if not date_records:
            print(f"\nNo check records in the last {summary_days} days.")
            return

        summary_header = ['Date', 'Checks', 'OK', 'WARN', 'Errors', 'NewCombos', 'Spikes']

        if json_output:
            data = {
                'summary_days': summary_days,
                'cutoff_date': cutoff.strftime('%Y-%m-%d'),
                'today': today.strftime('%Y-%m-%d'),
                'totals': {
                    'total_checks': total_checks,
                    'total_ok': total_ok,
                    'total_warn': total_warn,
                    'total_errors': total_errs,
                    'total_new_combos': total_new,
                },
                'daily': [],
            }
            for row in daily_rows:
                data['daily'].append({
                    'date': row[0], 'checks': int(row[1]), 'ok': int(row[2]),
                    'warn': int(row[3]), 'errors': int(row[4]),
                    'new_combos': int(row[5]), 'spikes': int(row[6]),
                })
            output_path = getattr(args, 'output', None)
            if output_path:
                with open(output_path, 'w', encoding='utf-8') as fh:
                    json.dump(data, fh, indent=2, ensure_ascii=False)
                print(f"Summary JSON saved to {output_path}")
            else:
                print(json.dumps(data, indent=2, ensure_ascii=False))
            return

        print(f"\n=== Check Summary (last {summary_days} days, {cutoff} ~ {today}) ===")
        print()
        print(format_table(summary_header, daily_rows))
        print()
        print(f"Totals across {len(date_records)} days:")
        print(f"  Checks       : {total_checks}")
        print(f"  Status       : {total_ok} OK, {total_warn} WARN")
        print(f"  Errors       : {total_errs}")
        print(f"  New Combos   : {total_new}")


def cmd_check(args):
    directory = args.directory
    now = datetime.now()

    rules_path = args.rules if getattr(args, 'rules', None) else DEFAULT_RULES_FILE
    rules = load_rules(rules_path)

    if getattr(args, 'use_rule', None) and args.use_rule in rules:
        apply_rule_to_args(args, rules[args.use_rule])

    pattern = getattr(args, 'pattern', None) or '*.log'
    period = getattr(args, 'period', None) or '-1h'
    compare_with = getattr(args, 'compare_with', None)

    def parse_relative(rel_str, base_time):
        if rel_str.startswith('-'):
            unit = rel_str[-1]
            value = int(rel_str[1:-1])
            if unit == 'm':
                return base_time - timedelta(minutes=value)
            elif unit == 'h':
                return base_time - timedelta(hours=value)
            elif unit == 'd':
                return base_time - timedelta(days=value)
        return parse_time_arg(rel_str)

    explicit_end = getattr(args, 'end', None)
    explicit_start = getattr(args, 'start', None)

    if explicit_end:
        end_time = parse_time_arg(explicit_end)
    else:
        end_time = now

    if explicit_start:
        start_time = parse_time_arg(explicit_start)
    else:
        start_time = parse_relative(period, end_time)

    if compare_with:
        parts = compare_with.split(',')
        if len(parts) == 2:
            try:
                comp_start = parse_time_arg(parts[0])
            except SystemExit:
                comp_start = parse_relative(parts[0], now)
            try:
                comp_end = parse_time_arg(parts[1])
            except SystemExit:
                comp_end = parse_relative(parts[1], now)
        else:
            comp_duration = (end_time - start_time).total_seconds()
            comp_end = start_time
            try:
                comp_start = parse_time_arg(compare_with)
            except SystemExit:
                comp_start = comp_end - timedelta(seconds=comp_duration)
    else:
        comp_end = start_time
        comp_start = comp_end - (end_time - start_time)

    output_dir = getattr(args, 'output_dir', None)
    if not output_dir:
        output_dir = os.path.join(
            os.path.dirname(os.path.abspath(directory)) if os.path.isfile(directory) else directory,
            'logscope_reports'
        )
    os.makedirs(output_dir, exist_ok=True)

    timestamp_str = now.strftime('%Y%m%d_%H%M%S')
    json_report_path = os.path.join(output_dir, f'check_report_{timestamp_str}.json')
    md_report_path = os.path.join(output_dir, f'check_report_{timestamp_str}.md')

    files = collect_log_files(directory, pattern)
    if not files:
        print(f"[ERROR] No log files found in {directory}", file=sys.stderr)
        sys.exit(1)

    entries = read_log_entries(files)
    include_no_ts = getattr(args, 'include_no_ts', False)
    alert_group_by = getattr(args, 'alert_group_by', 'service,code')
    alert_top = getattr(args, 'alert_top', 10)

    current_entries = filter_entries(entries, start=start_time, end=end_time,
                                     include_no_ts=include_no_ts)

    if getattr(args, 'level', None):
        current_entries = filter_entries(current_entries, level=args.level)
    if getattr(args, 'keyword', None):
        current_entries = filter_entries(current_entries, keyword=args.keyword)

    baseline_path = getattr(args, 'baseline', None)
    baseline_data = load_baseline_report(baseline_path)

    total_entries = len(current_entries)
    level_counter = Counter(e.level for e in current_entries if e.level)
    code_counter = Counter(e.error_code for e in current_entries if e.error_code)

    error_count = sum(1 for e in current_entries if e.level in ('ERROR', 'FATAL', 'CRITICAL'))
    warn_count = sum(1 for e in current_entries if e.level == 'WARN')

    alert = build_alert_summary(current_entries, group_by=alert_group_by, top_n=alert_top)
    alert_json = alert_summary_to_json(alert, current_entries)

    comparison = None
    if baseline_data and baseline_data.get('alert_summary'):
        comparison = compare_alert_baseline(alert_json, baseline_data, top_n=alert_top)

    comp_entries = filter_entries(entries, start=comp_start, end=comp_end,
                                  include_no_ts=include_no_ts)
    if getattr(args, 'level', None):
        comp_entries = filter_entries(comp_entries, level=args.level)
    if getattr(args, 'keyword', None):
        comp_entries = filter_entries(comp_entries, keyword=args.keyword)

    comp_error_count = sum(1 for e in comp_entries if e.level in ('ERROR', 'FATAL', 'CRITICAL'))
    error_delta = error_count - comp_error_count
    if comp_error_count > 0:
        error_change = f'{(error_delta / comp_error_count) * 100:+.1f}%'
    elif error_count > 0:
        error_change = '+NEW'
    else:
        error_change = '0%'

    spike_windows = []
    if getattr(args, 'spike', False):
        buckets = defaultdict(int)
        for e in current_entries:
            if e.timestamp and e.level in ('ERROR', 'FATAL', 'CRITICAL'):
                bucket = e.timestamp.replace(minute=0, second=0, microsecond=0)
                buckets[bucket] += 1
        if buckets:
            values = [v for _, v in sorted(buckets.items())]
            if len(values) >= 2:
                mean = sum(values) / len(values)
                std = math.sqrt(sum((v - mean) ** 2 for v in values) / len(values))
                sigma = getattr(args, 'spike_sigma', 2.0)
                threshold = mean + sigma * std if std > 0 else mean + 1
                for ts, cnt in sorted(buckets.items()):
                    spike_windows.append({
                        'time': ts.strftime('%Y-%m-%d %H:%M'),
                        'count': cnt,
                        'is_spike': cnt > threshold,
                    })

    json_data = {
        'check_timestamp': now.strftime('%Y-%m-%d %H:%M:%S'),
        'directory': directory,
        'pattern': pattern,
        'files_scanned': len(files),
        'period': {
            'current_start': start_time.strftime('%Y-%m-%d %H:%M:%S'),
            'current_end': end_time.strftime('%Y-%m-%d %H:%M:%S'),
            'compare_start': comp_start.strftime('%Y-%m-%d %H:%M:%S'),
            'compare_end': comp_end.strftime('%Y-%m-%d %H:%M:%S'),
        },
        'summary': {
            'total_entries': total_entries,
            'error_count': error_count,
            'warning_count': warn_count,
            'compare_error_count': comp_error_count,
            'error_delta': error_delta,
            'error_change': error_change,
        },
        'level_distribution': dict(level_counter),
        'error_code_ranking': [
            {'code': code, 'count': cnt}
            for code, cnt in code_counter.most_common(20)
        ],
        'alert_summary': alert_json,
        'spike_windows': spike_windows,
    }
    if comparison:
        json_data['baseline_comparison'] = baseline_comparison_to_json(comparison, alert_group_by)

    mask_fields = getattr(args, 'mask', None)
    mask_list = mask_fields.split(',') if mask_fields else None

    with open(json_report_path, 'w', encoding='utf-8') as fh:
        json.dump(json_data, fh, indent=2, ensure_ascii=False)

    md_lines = []
    md_lines.append('# Log Inspection Report')
    md_lines.append('')
    md_lines.append(f'- **Generated**: {now.strftime("%Y-%m-%d %H:%M:%S")}')
    md_lines.append(f'- **Directory**: `{directory}`')
    md_lines.append(f'- **Files Scanned**: {len(files)}')
    md_lines.append(f'- **Current Period**: {start_time.strftime("%Y-%m-%d %H:%M:%S")} ~ {end_time.strftime("%Y-%m-%d %H:%M:%S")}')
    md_lines.append(f'- **Compare Period**: {comp_start.strftime("%Y-%m-%d %H:%M:%S")} ~ {comp_end.strftime("%Y-%m-%d %H:%M:%S")}')
    md_lines.append('')

    md_lines.append('## Inspection Summary')
    md_lines.append('')
    md_lines.append('| Metric | Current | Compare | Delta | Change |')
    md_lines.append('|--------|---------|---------|-------|--------|')
    md_lines.append(f'| Total Entries | {total_entries} | {len(comp_entries)} | {total_entries - len(comp_entries):+d} |')
    md_lines.append(f'| Errors | {error_count} | {comp_error_count} | {error_delta:+d} | {error_change} |')
    md_lines.append(f'| Warnings | {warn_count} | {sum(1 for e in comp_entries if e.level == "WARN")} | {warn_count - sum(1 for e in comp_entries if e.level == "WARN"):+d} |')
    md_lines.append('')

    status = 'OK'
    status_reasons = []
    if error_count > comp_error_count:
        status = 'WARN'
        status_reasons.append(f'Errors increased by {error_delta}')
    if comparison and comparison['new_items']:
        status = 'WARN'
        status_reasons.append(f'{len(comparison["new_items"])} new alert combinations')
    if any(s['is_spike'] for s in spike_windows):
        status = 'WARN'
        status_reasons.append('Error spikes detected')

    md_lines.append(f'**Status**: `{status}`')
    if status_reasons:
        md_lines.append(f'**Notes**: {"; ".join(status_reasons)}')
    md_lines.append('')

    md_lines.append('## Error Code Ranking')
    md_lines.append('')
    if code_counter:
        total_codes = sum(code_counter.values())
        md_lines.append('| Rank | Code | Count | Percentage |')
        md_lines.append('|------|------|-------|------------|')
        for i, (code, cnt) in enumerate(code_counter.most_common(10), 1):
            md_lines.append(f'| {i} | {code} | {cnt} | {cnt / total_codes * 100:.1f}% |')
    else:
        md_lines.append('No error codes found.')
    md_lines.append('')

    md_lines.append('## Alert Summary')
    md_lines.append('')
    if alert['rows']:
        md_lines.append(f'Grouped by: `{alert["group_by"]}`')
        md_lines.append(f'Total errors: {alert["total"]} (across {alert["groups"]} groups)')
        md_lines.append('')
        md_lines.append('| ' + ' | '.join(alert['headers']) + ' |')
        md_lines.append('|' + '|'.join('---' for _ in alert['headers']) + '|')
        for row in alert['rows']:
            md_lines.append('| ' + ' | '.join(row) + ' |')
    else:
        md_lines.append('No alert data available.')
    md_lines.append('')

    if comparison and comparison['baseline_available']:
        canonical_keys = comparison.get('canonical_keys',
                                        [g.strip().lower() for g in alert_group_by.split(',')])
        ck_header_map = {
            'code': 'ErrorCode', 'service': 'Service', 'host': 'Host',
            'level': 'Level', 'trace_id': 'TraceID',
        }
        ck_display = [ck_header_map.get(ck, ck) for ck in canonical_keys]
        md_lines.append('## Baseline Comparison')
        md_lines.append('')
        if comparison['new_items']:
            md_lines.append('### New Alert Combinations (not in baseline)')
            md_lines.append('')
            headers_t = ck_display + ['Count']
            md_lines.append('| ' + ' | '.join(headers_t) + ' |')
            md_lines.append('|' + '|'.join('---' for _ in headers_t) + '|')
            for item, cnt in comparison['new_items']:
                row = [str(_item_get(item, ck)) for ck in canonical_keys]
                row.append(str(cnt))
                md_lines.append('| ' + ' | '.join(row) + ' |')
            md_lines.append(f'\nTotal new combinations: **{len(comparison["new_items"])}**')
            md_lines.append('')

        if comparison['top_growth']:
            md_lines.append('### Top Growth Alert Combinations')
            md_lines.append('')
            headers_t = ck_display + ['Baseline', 'Current', 'Delta', 'Growth%']
            md_lines.append('| ' + ' | '.join(headers_t) + ' |')
            md_lines.append('|' + '|'.join('---' for _ in headers_t) + '|')
            for item, base_cnt, cur_cnt, delta, rate in comparison['top_growth']:
                row = [str(_item_get(item, ck)) for ck in canonical_keys]
                rate_str = 'INF%' if rate == float('inf') else f'{rate:+.1f}%'
                row += [str(base_cnt), str(cur_cnt), f'{delta:+d}', rate_str]
                md_lines.append('| ' + ' | '.join(row) + ' |')
            md_lines.append('')

    if spike_windows:
        md_lines.append('## Spike Detection')
        md_lines.append('')
        md_lines.append('| Time Window | Error Count | Status |')
        md_lines.append('|-------------|-------------|--------|')
        for s in spike_windows:
            sw_status = '!! SPIKE' if s['is_spike'] else 'OK'
            md_lines.append(f"| {s['time']} | {s['count']} | {sw_status} |")
        md_lines.append('')

    md_lines.append('## Recent Errors (up to 10)')
    md_lines.append('')
    errors = [e for e in current_entries if e.level in ('ERROR', 'FATAL', 'CRITICAL')]
    errors.sort(key=lambda e: e.timestamp or datetime.min, reverse=True)
    if errors:
        for e in errors[:10]:
            ts = e.timestamp.strftime('%Y-%m-%d %H:%M:%S') if e.timestamp else '-'
            msg = mask_sensitive(e.raw, mask_list) if mask_list else e.raw
            md_lines.append(f'- `[{ts}] [{e.level}] {msg}`')
    else:
        md_lines.append('No error entries found.')
    md_lines.append('')

    md_lines.append('## Artifacts')
    md_lines.append('')
    md_lines.append(f'- JSON Report: `{json_report_path}`')
    md_lines.append(f'- Markdown Report: `{md_report_path}`')
    md_lines.append(f'- Baseline Report: `{baseline_path}`' if baseline_path else '- Baseline Report: (none)')
    md_lines.append('')

    with open(md_report_path, 'w', encoding='utf-8') as fh:
        fh.write('\n'.join(md_lines))

    print("=" * 60)
    print("LOG INSPECTION CHECK - SUMMARY")
    print("=" * 60)
    print(f"Status          : {status}")
    if status_reasons:
        print(f"Reason(s)       : {'; '.join(status_reasons)}")
    print(f"Period          : {start_time.strftime('%Y-%m-%d %H:%M')} ~ {end_time.strftime('%Y-%m-%d %H:%M')}")
    print(f"Compare Period  : {comp_start.strftime('%Y-%m-%d %H:%M')} ~ {comp_end.strftime('%Y-%m-%d %H:%M')}")
    print(f"Total Entries   : {total_entries}")
    print(f"Errors          : {error_count} (vs {comp_error_count} compare, {error_delta:+d}, {error_change})")
    print(f"Warnings        : {warn_count}")
    print(f"Files Scanned   : {len(files)}")
    if comparison and comparison['baseline_available']:
        print(f"New Alerts      : {len(comparison['new_items'])}")
        print(f"Top Growth      : {len(comparison['top_growth'])}")
    spike_count = sum(1 for s in spike_windows if s['is_spike'])
    if spike_count:
        print(f"Spike Windows   : {spike_count}")
    print("-" * 60)
    print(f"JSON Report     : {json_report_path}")
    print(f"Markdown Report : {md_report_path}")
    print("=" * 60)

    snapshot = {}
    if alert['rows']:
        top_codes = []
        top_services = []
        for row in alert['rows'][:10]:
            key_parts = row[:-1]
            count = int(row[-1])
            if 'code' in alert_group_by.lower() or 'error_code' in alert_group_by.lower():
                for k in key_parts:
                    if k and k.startswith(('E', '5', '4', 'ERR', 'SYS')) and len(k) <= 10:
                        top_codes.append({'code': k, 'count': count})
                        break
            if 'service' in alert_group_by.lower() or 'svc' in alert_group_by.lower():
                for k in key_parts:
                    if k and ('service' in k.lower() or 'svc' in k.lower() or k and '-' in k and len(k) <= 30):
                        top_services.append({'service': k, 'count': count})
                        break
        code_counter = Counter()
        service_counter = Counter()
        for e in current_entries:
            if e.error_code:
                code_counter[e.error_code] += 1
            if e.service:
                service_counter[e.service] += 1
        top_codes = [{'code': c, 'count': n} for c, n in code_counter.most_common(10)]
        top_services = [{'service': s, 'count': n} for s, n in service_counter.most_common(10)]
        snapshot['top_codes'] = top_codes
        snapshot['top_services'] = top_services
        snapshot['alert_rows'] = [
            {ck: row[i] for i, ck in enumerate(alert['headers'][:-1])} | {'count': int(row[-1])}
            for row in alert['rows'][:10]
        ]
    if comparison and comparison.get('baseline_available'):
        canonical_keys = comparison.get('canonical_keys',
                                        [g.strip().lower() for g in alert_group_by.split(',')])
        snapshot['top_growth'] = []
        for item, base_cnt, cur_cnt, delta, rate in comparison['top_growth'][:10]:
            growth_entry = {ck: _item_get(item, ck) for ck in canonical_keys}
            growth_entry.update({
                'baseline_count': base_cnt,
                'current_count': cur_cnt,
                'delta': delta,
                'growth_rate': None if rate == float('inf') else round(rate, 2),
            })
            snapshot['top_growth'].append(growth_entry)
        snapshot['new_items'] = []
        for item, cnt in comparison['new_items'][:10]:
            entry = {ck: _item_get(item, ck) for ck in canonical_keys}
            entry['count'] = cnt
            snapshot['new_items'].append(entry)

    history_record = {
        'timestamp': now.strftime('%Y-%m-%d %H:%M:%S'),
        'date': now.strftime('%Y-%m-%d'),
        'status': status,
        'directory': directory,
        'pattern': pattern,
        'period_start': start_time.strftime('%Y-%m-%d %H:%M:%S'),
        'period_end': end_time.strftime('%Y-%m-%d %H:%M:%S'),
        'total_entries': total_entries,
        'error_count': error_count,
        'warning_count': warn_count,
        'error_delta': error_delta,
        'error_change': error_change,
        'new_alerts': len(comparison['new_items']) if comparison and comparison.get('baseline_available') else 0,
        'top_growth_count': len(comparison['top_growth']) if comparison and comparison.get('baseline_available') else 0,
        'spike_count': sum(1 for s in spike_windows if s['is_spike']),
        'services': sorted(set(e.service for e in current_entries if e.service)),
        'error_codes': sorted(set(e.error_code for e in current_entries if e.error_code)),
        'json_report': json_report_path,
        'md_report': md_report_path,
    }
    if snapshot:
        history_record['snapshot'] = snapshot
    if status_reasons:
        history_record['reasons'] = status_reasons

    history_path = getattr(args, 'history', None) or DEFAULT_HISTORY_FILE
    append_check_history(history_record, history_path)

    if status != 'OK':
        sys.exit(2)


def build_parser():
    parser = argparse.ArgumentParser(
        prog='logscope',
        description='LogScope - Log analysis CLI for ops personnel',
    )
    parser.add_argument('--version', action='version', version=f'%(prog)s {VERSION}')

    sub = parser.add_subparsers(dest='command', help='Available commands')

    # --- check ---
    p_check = sub.add_parser('check', help='Run full inspection pipeline (scan/stat/diff/report)')
    p_check.add_argument('directory', help='Log directory or file path')
    p_check.add_argument('--pattern', default=None, help='File glob pattern (default: *.log)')
    p_check.add_argument('--period', default=None,
                         help='Analysis period (e.g. -1h, -30m, -1d, default: -1h)')
    p_check.add_argument('--start', default=None, help='Start time (overrides --period)')
    p_check.add_argument('--end', default=None, help='End time (default: now, overrides --period)')
    p_check.add_argument('--compare-with', default=None,
                         help='Compare period, e.g. "-2h,-1h" or single offset for same duration as current period')
    p_check.add_argument('--include-no-ts', action='store_true',
                         help='Include entries without a valid timestamp')
    p_check.add_argument('--level', default=None, help='Log level filter')
    p_check.add_argument('--keyword', default=None, help='Keyword filter')
    p_check.add_argument('--mask', help='Comma-separated sensitive field names to mask')
    p_check.add_argument('--alert', action='store_true',
                         help='Enable alert summary (aggregated by service/host/error code)')
    p_check.add_argument('--alert-group-by', default='service,code',
                         help='Alert aggregation keys (default: service,code)')
    p_check.add_argument('--alert-top', type=int, default=10,
                         help='Top N alert groups (default: 10)')
    p_check.add_argument('--spike', action='store_true', help='Enable spike detection')
    p_check.add_argument('--spike-sigma', type=float, default=2.0,
                         help='Spike threshold sigma (default: 2.0)')
    p_check.add_argument('--baseline', help='Path to previous JSON report for baseline comparison')
    p_check.add_argument('--output-dir', help='Output directory for reports')
    p_check.add_argument('--rules', help='Rules file path')
    p_check.add_argument('--use-rule', help='Apply a saved rule by name')
    p_check.add_argument('--history', help='History archive file path (default: ~/.logscope_history.json)')

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
    p_stat.add_argument('--baseline', help='Path to previous JSON report for baseline comparison')
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
    p_report.add_argument('--baseline', help='Path to previous JSON report for baseline comparison')
    p_report.add_argument('--rules', help='Rules file path')
    p_report.add_argument('--use-rule', help='Apply a saved rule by name')
    p_report.add_argument('--save-rule', help='Save current filters as a named rule')
    p_report.add_argument('--rule-description', default=None,
                          help='Description to attach when using --save-rule')
    p_report.add_argument('--rule-output-dir', default=None,
                          help='Default output directory to attach when using --save-rule')
    p_report.add_argument('-f', '--force', action='store_true',
                          help='Force overwrite existing rule without confirmation')
    p_report.add_argument('--history', help='History archive file path for trend section')
    p_report.add_argument('--history-n', type=int, default=10,
                          help='Number of recent checks for trend section (default: 10)')

    # --- list-rules / list-rule (aliases) ---
    for cmd_name in ('list-rules', 'list-rule'):
        p = sub.add_parser(cmd_name, help='List all saved rules')
        p.add_argument('--rules', help='Rules file path')

    # --- show-rule / show-rules (aliases) ---
    for cmd_name in ('show-rule', 'show-rules'):
        p = sub.add_parser(cmd_name, help='Show details of a saved rule')
        p.add_argument('name', help='Rule name')
        p.add_argument('--rules', help='Rules file path')

    # --- delete-rule / delete-rules (aliases) ---
    for cmd_name in ('delete-rule', 'delete-rules'):
        p = sub.add_parser(cmd_name, help='Delete a saved rule')
        p.add_argument('name', help='Rule name')
        p.add_argument('--rules', help='Rules file path')
        p.add_argument('-f', '--force', action='store_true',
                       help='Force delete without confirmation')

    # --- history ---
    p_history = sub.add_parser('history', help='View check inspection history')
    p_history.add_argument('--status', help='Filter by status (OK or WARN)')
    p_history.add_argument('--service', help='Filter by service name')
    p_history.add_argument('--error-code', help='Filter by error code')
    p_history.add_argument('--last', type=int, help='Show last N records')
    p_history.add_argument('--trend', action='store_true',
                           help='Show error and new-alert trend across records')
    p_history.add_argument('--json', action='store_true', help='Output as JSON')
    p_history.add_argument('--output', help='Save JSON output to file')
    p_history.add_argument('--history', help='History archive file path (default: ~/.logscope_history.json)')
    p_history.add_argument('--summary', action='store_true',
                           help='Show aggregated summary by day (use --days to set rolling window)')
    p_history.add_argument('--days', type=int, default=30,
                           help='Rolling window for --summary in days (default: 30, common: 7, 30)')
    p_history.add_argument('--detail', type=int,
                           help='Expand snapshot of a specific record index (1-based, e.g. --detail 1)')

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)
    cmd_map = {
        'check': cmd_check,
        'scan': cmd_scan,
        'filter': cmd_filter,
        'trace': cmd_trace,
        'stat': cmd_stat,
        'diff': cmd_diff,
        'report': cmd_report,
        'history': cmd_history,
        'list-rules': cmd_list_rules,
        'list-rule': cmd_list_rules,
        'show-rule': cmd_show_rule,
        'show-rules': cmd_show_rule,
        'delete-rule': cmd_delete_rule,
        'delete-rules': cmd_delete_rule,
    }
    cmd_map[args.command](args)


if __name__ == '__main__':
    main()
