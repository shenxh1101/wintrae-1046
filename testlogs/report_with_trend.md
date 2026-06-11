# Log Analysis Report

- **Generated**: 2026-06-11 17:09:45
- **Directory**: `d:\TraeProjects\1046\testlogs`
- **Files Scanned**: 1
- **Total Entries**: 11
- **Time Range**: 2026-06-10 10:00:01 ~ 2026-06-10 11:45:00
- **Time Filter Mode**: strict (no-ts excluded)

## Level Distribution

| Level | Count | Percentage |
|-------|-------|------------|
| ERROR | 7 | 63.6% |
| INFO | 2 | 18.2% |
| WARN | 1 | 9.1% |
| FATAL | 1 | 9.1% |

## Error Code Ranking

| Rank | Code | Count | Percentage |
|------|------|-------|------------|
| 1 | 504 | 3 | 37.5% |
| 2 | 507 | 2 | 25.0% |
| 3 | 503 | 2 | 25.0% |
| 4 | 400 | 1 | 12.5% |

## Top Trace IDs

| Trace ID | Count |
|----------|-------|
| `txn-c001` | 1 |
| `txn-c002` | 1 |
| `txn-c003` | 1 |
| `txn-c004` | 1 |

## Recent Errors (up to 20)

- `[2026-06-10 11:45:00] [ERROR] 2026-06-10 11:45:00 | ERROR | service=message-service host=msg-01 Queue retry error_code=503`
- `[2026-06-10 11:30:00] [FATAL] 2026-06-10 11:30:00 lvl=FATAL service=message-service host=msg-01 Queue full error_code=503 trace_id=txn-c004`
- `[2026-06-10 11:10:00] [ERROR] 2026-06-10 11:10:00 level=ERROR service=config-service host=cfg-01 Config invalid error_code=400 trace_id=txn-c003`
- `[2026-06-10 10:30:02] [ERROR] 2026-06-10 10:30:02 severity=ERROR service=gateway-service host=gw-01 API timeout retry 2 error_code=504`
- `[2026-06-10 10:30:01] [ERROR] 2026-06-10 10:30:01 | ERROR | service=gateway-service host=gw-01 API timeout retry 1 error_code=504`
- `[2026-06-10 10:30:00] [ERROR] 2026-06-10 10:30:00 lvl=ERROR service=gateway-service host=gw-01 API timeout error_code=504 trace_id=txn-c002`
- `[2026-06-10 10:10:00] [ERROR] 2026-06-10 10:10:00 severity=error service=storage-service host=store-02 Disk I/O error error_code=507`
- `[2026-06-10 10:05:00] [ERROR] 2026-06-10 10:05:00 [ERROR] service=storage-service host=store-01 Disk full error_code=507 trace_id=txn-c001`

## Alert Summary

Grouped by: `service,host,code`
Total errors: 8 (across 5 groups)

| Service | Host | ErrorCode | Count |
|---|---|---|---|
| gateway-service | gw-01 | 504 | 3 |
| message-service | msg-01 | 503 | 2 |
| storage-service | store-01 | 507 | 1 |
| storage-service | store-02 | 507 | 1 |
| config-service | cfg-01 | 400 | 1 |

## Baseline Comparison

### New Alert Combinations (not in baseline)

| Service | Host | ErrorCode | Count |
|---|---|---|---|
| gateway-service | gw-01 | 504 | 3 |
| message-service | msg-01 | 503 | 2 |
| storage-service | store-02 | 507 | 1 |
| config-service | cfg-01 | 400 | 1 |

Total new combinations: **4**

### Top Growth Alert Combinations

| Service | Host | ErrorCode | Baseline | Current | Delta | Growth% |
|---|---|---|---|---|---|---|
| gateway-service | gw-01 | 504 | 0 | 3 | +3 | INF% |
| message-service | msg-01 | 503 | 0 | 2 | +2 | INF% |
| storage-service | store-02 | 507 | 0 | 1 | +1 | INF% |
| config-service | cfg-01 | 400 | 0 | 1 | +1 | INF% |


## Spike Detection

| Time Window | Error Count | Status |
|-------------|-------------|--------|
| 2026-06-10 10:00 | 5 | OK |
| 2026-06-10 11:00 | 3 | OK |

## Historical Check Trend

Source: `d:\TraeProjects\1046\testlogs\check_history.json` (last 2 checks)

Current report errors: **8** vs. avg 11.0, max 14

| # | Timestamp | Status | Errors | Delta | New Alerts | Spikes |
|---|-----------|--------|--------|-------|------------|--------|
| 1 | 2026-06-11 17:06:44 | 🔴 WARN | 8 | +2 | 4 | 0 |
| 2 | 2026-06-11 17:07:02 | 🔴 WARN | 14 | +14 | 0 | 0 |
