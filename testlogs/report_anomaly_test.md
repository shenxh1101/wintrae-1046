# Log Analysis Report

- **Generated**: 2026-06-11 17:10:09
- **Directory**: `d:\TraeProjects\1046\testlogs`
- **Files Scanned**: 1
- **Total Entries**: 12
- **Time Range**: 2026-06-10 08:00:01 ~ 2026-06-10 09:30:05
- **Time Filter Mode**: strict (no-ts excluded)

## Level Distribution

| Level | Count | Percentage |
|-------|-------|------------|
| ERROR | 5 | 41.7% |
| INFO | 4 | 33.3% |
| WARN | 2 | 16.7% |
| FATAL | 1 | 8.3% |

## Error Code Ranking

| Rank | Code | Count | Percentage |
|------|------|-------|------------|
| 1 | 500 | 3 | 50.0% |
| 2 | 503 | 2 | 33.3% |
| 3 | 401 | 1 | 16.7% |

## Top Trace IDs

| Trace ID | Count |
|----------|-------|
| `txn-b001` | 1 |
| `txn-b002` | 1 |
| `txn-b003` | 1 |
| `txn-b004` | 1 |

## Recent Errors (up to 20)

- `[2026-06-10 09:30:00] [ERROR] 2026-06-10 09:30:00 level=ERROR service=auth-service host=auth-01 Auth failed error_code=401 trace_id=txn-b004`
- `[2026-06-10 09:00:15] [FATAL] 2026-06-10 09:00:15 [FATAL] service=payment-service host=pay-01 Out of memory error_code=500 trace_id=txn-b003`
- `[2026-06-10 08:30:01] [ERROR] 2026-06-10 08:30:01 level=error service=payment-service host=pay-01 Gateway timeout error_code=503`
- `[2026-06-10 08:30:00] [ERROR] 2026-06-10 08:30:00 - error - service=payment-service host=pay-02 Payment failed error_code=503 trace_id=txn-b002`
- `[2026-06-10 08:10:01] [ERROR] 2026-06-10 08:10:01 severity=ERROR service=order-service host=web-01 Retry 1 error_code=500`
- `[2026-06-10 08:10:00] [ERROR] 2026-06-10 08:10:00 | ERROR | service=order-service host=web-01 Database timeout error_code=500 trace_id=txn-b001`

## Alert Summary

Grouped by: `service,host,code`
Total errors: 6 (across 5 groups)

| Service | Host | ErrorCode | Count |
|---|---|---|---|
| order-service | web-01 | 500 | 2 |
| payment-service | pay-02 | 503 | 1 |
| payment-service | pay-01 | 503 | 1 |
| payment-service | pay-01 | 500 | 1 |
| auth-service | auth-01 | 401 | 1 |

## Spike Detection

| Time Window | Error Count | Status |
|-------------|-------------|--------|
| 2026-06-10 08:00 | 4 | OK |
| 2026-06-10 09:00 | 2 | OK |

## Historical Check Trend

Source: `d:\TraeProjects\1046\testlogs\check_history.json` (last 2 checks)

Current report errors: **6** vs. avg 11.0, max 14

| # | Timestamp | Status | Errors | Delta | New Alerts | Spikes |
|---|-----------|--------|--------|-------|------------|--------|
| 1 | 2026-06-11 17:06:44 | 🔴 WARN | 8 | +2 | 4 | 0 |
| 2 | 2026-06-11 17:07:02 | 🔴 WARN | 14 | +14 | 0 | 0 |
