# cursor-pagination

[![npm version](https://img.shields.io/npm/v/@trysac/cursor-pagination.svg)](https://www.npmjs.com/package/@trysac/cursor-pagination)
[![license: MIT](https://img.shields.io/npm/l/@trysac/cursor-pagination.svg)](LICENSE)
[![CI](https://github.com/Trysac/u052-cursor-pagination/actions/workflows/ci.yml/badge.svg)](https://github.com/Trysac/u052-cursor-pagination/actions/workflows/ci.yml)

Opaque HMAC-signed keyset pagination cursors with expiry, key rotation, query binding and a parameterised SQL keyset predicate builder.

## Problem

Offset pagination skips or repeats rows when data changes. Plain base64 cursors, such as the unsigned offsets used by graphql-relay, let clients tamper with them to read outside their query. Multi-column keyset predicates are also easy to get wrong by hand, particularly tie-breaking. This package provides signed, expiring cursors bound to a query, plus a tested, parameterised keyset predicate builder.

Requirements for the SQL side: sort fields must be `NOT NULL` columns, the last sort field should be unique (for example the primary key) so ordering is total, and at most 8 sort fields are allowed.

Threat model: see [docs/SECURITY.md](docs/SECURITY.md).

## Install

```sh
npm install @trysac/cursor-pagination
```

Requires Node.js 20 or newer. The package ships ES modules with TypeScript declarations and has no runtime dependencies.

## Usage

```ts
import { buildKeysetPredicate, createCursorCodec, filterHash, toSqlWhere } from "@trysac/cursor-pagination";

const codec = createCursorCodec({ secrets: [process.env.CURSOR_SECRET!], ttlSeconds: 3600 });
const fh = filterHash({ tenant: "acme", status: "open" });
const cursor = codec.encode({ key: { created_at: "2024-01-01", id: 7 }, filterHash: fh });
const { key } = codec.decode(cursor, { filterHash: fh });
const sort = [{ field: "created_at", order: "desc" }, { field: "id", order: "asc" }] as const;
const { sql, params } = toSqlWhere(buildKeysetPredicate(sort, key));
console.log(sql, params);
```

## API

| Export | Signature | Description |
|---|---|---|
| `createCursorCodec` | `(options: { secrets; ttlSeconds?; now?; onEvent? }) => CursorCodec` | Creates a frozen codec with `encode` and `decode`. Throws `CursorConfigError` on invalid options. |
| `codec.encode` | `({ key, filterHash? }) => string` | Returns `v1.<payload>.<signature>`. Key values are strings, booleans or finite safe integers or non-zero finite numbers; 1 to 8 fields. |
| `codec.decode` | `(cursor, expected?: { filterHash? }) => CursorPayload` | Verifies format, signature, expiry and filter binding. Returns `key`, `filterHash` (or `null`) and `iat` in epoch seconds. |
| `filterHash` | `(filters: unknown) => string` | Lowercase hex SHA-256 of the JSON text with object keys sorted recursively. This is not RFC 8785 JCS. |
| `paginate` | `(items, { limit, keyOf, codec, filterHash? }) => Page` | Expects `limit + 1` fetched rows. Returns `items` (sliced to `limit`), `hasMore` and `nextCursor`. |
| `buildKeysetPredicate` | `(sort, key) => KeysetPredicate` | Builds the disjunctive normal form of the strictly-after predicate. |
| `toSqlWhere` | `(predicate, placeholder?) => { sql, params }` | Renders parameterised SQL. Values appear only in `params`; identifiers are checked against a strict pattern. |

### Options and limits

- `secrets`: 1 to 16 entries, each at least 32 bytes (strings are UTF-8). The first signs; all verify, which allows rotation.
- `ttlSeconds`: 1 to 31536000, default 3600. A cursor is expired when the current time is strictly after `iat + ttlSeconds`.
- `now`: returns epoch milliseconds, default `Date.now`.
- `onEvent`: receives `{ type: "decode_failed", reason }` for every rejected cursor. Errors thrown by the listener are ignored.
- Cursors are at most 4096 characters. Cursors with an `iat` more than 300 seconds in the future are rejected.
- `paginate` `limit`: integer 1 to 1000.
- `filterHash` input: plain objects, arrays, strings, booleans, finite numbers and null; nesting at most 32 levels and at most 10000 values.
- Key strings are at most 512 characters; field names at most 128 characters.

### Errors

`CursorError` is the base class with a readonly `code`. `InvalidCursorError` has code `malformed`, `signature`, `expired` or `filter_mismatch`. `CursorConfigError` has code `config`. Messages never include the cursor or any secret.

## Why not graphql-relay cursors?

The graphql-relay style cursor is an unsigned base64 offset or key. Clients can edit it, so the server cannot tell a genuine position from a forged one. This library signs the payload with HMAC-SHA256, binds it to a query hash and expires it.

## Development

Run `npm test` for the test suite with coverage. See [docs/TESTING.md](docs/TESTING.md) for the test files and rules.

## License

[MIT](LICENSE) © 2026 Miguel Gomez
