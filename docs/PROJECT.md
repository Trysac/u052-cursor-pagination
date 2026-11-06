# Project record: cursor-pagination

## Objective

Provide signed, expiring pagination cursors bound to a query, and a tested, parameterised keyset predicate builder for multi-column sorts. Offset pagination repeats or skips rows when data changes, and unsigned base64 cursors can be edited by clients to read outside their query. The package is for backend TypeScript developers on Node.js 20+ who expose paginated APIs.

## Scope

In scope:

- Signed cursor creation and verification (`createCursorCodec`) with secret rotation, TTL, query binding and a decode-failure event.
- `filterHash` for binding cursors to a query.
- `paginate` for trimming `limit + 1` rows and creating the next cursor.
- `buildKeysetPredicate` and `toSqlWhere` for strictly-after keyset predicates rendered as parameterised SQL.
- The `CursorError`, `InvalidCursorError` and `CursorConfigError` error classes.

Out of scope:

- Backward pages.
- Offset pagination.
- ORM adapters.
- Encryption of cursor contents (cursors are signed, not encrypted).

## Timeline

| Date | Milestone |
|---|---|
| 2026 | Repository created from the factory utility template. |

## Effort metrics

Values are recorded by the factory ledger and time log. Estimates are not recorded here.

| Metric | Value | Source |
|---|---|---|
| Tokens (input / output) | 310707 / 80491 | factory ledger |
| Hours (human) | pending measurement | time log |
| Cost (USD) | 0.5661 | factory ledger |

## Factory run u052 (measured from API usage)

| Phase | Model | Batch | Input | Output | Cache write | Cache read | Cost (USD) |
|---|---|---|---|---|---|---|---|
| generation | claude-sonnet-5-5 | yes | 2479 | 65914 | 0 | 4473 | 0.3325 |
| fix-1 | claude-sonnet-5-5 | no | 6 | 704 | 10028 | 46608 | 0.0368 |
| fix-2 | claude-sonnet-5-5 | no | 8 | 1547 | 7214 | 55248 | 0.0390 |
| audit | claude-sonnet-5-5 | no | 12 | 2242 | 26671 | 126117 | 0.1017 |
| fix-3 | claude-sonnet-5-5 | no | 6 | 2318 | 8559 | 40461 | 0.0486 |
| docs | claude-haiku-5-5 | no | 35289 | 7766 | 0 | 0 | 0.0074 |

Total: $0.5661. Prices: Anthropic list prices.
