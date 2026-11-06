# Testing

## Tools

- [Vitest](https://vitest.dev/) runs the suites in `test/`.
- Coverage is collected with V8 (`@vitest/coverage-v8`) over `src/`.

## Test files

- `test/index.test.ts`: covers the public API. It checks the acceptance literals (round trip, signature format, the two-column SQL predicate), every cursor rejection path (`malformed`, `signature`, `expired`, `filter_mismatch`), secret rotation, TTL bounds and the 300-second future skew, the `decode_failed` event (including that no message or event contains the cursor or a secret), option and input validation, `filterHash` canonicalisation and limits, `paginate`, `buildKeysetPredicate` and `toSqlWhere`, identifier and placeholder rejection, and one test per threat-model entry.
- `test/hmac-order.test.ts`: spies on `node:crypto` `createHmac` to verify that malformed cursors compute no HMAC, and that every secret is tried on verification without an early exit.

## Commands

```sh
npm test            # vitest run --coverage
npx vitest          # watch mode while developing
```

## Rules

- Coverage must stay at or above 80 % for lines, branches, functions and statements (`vitest.config.ts`). Lowering the thresholds is not allowed.
- Tests import through the public entry point (`src/index.ts`) and assert observable behavior: return values, thrown error codes and messages, and mocked HMAC calls.
- Tests are deterministic: the clock is always injected through the `now` option, and no test depends on randomness or the network.

## Reports

Coverage reports are written to `coverage/` (text summary and `lcov`). The folder is ignored by git.
