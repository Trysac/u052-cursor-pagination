# Security

This document describes the threat model of `@trysac/cursor-pagination`. To report a vulnerability, follow the process in the `SECURITY.md` file at the repository root.

## Threat model

A cursor is an opaque token the server hands to a client and later receives back. The client is untrusted: it can read, edit, forge, replay and share cursors. The library signs cursors so the server can trust what comes back.

Format: `v1.` + base64url(JSON payload `{k, fh, iat}`) + `.` + base64url(HMAC-SHA256 over the ASCII string `v1.` + payload segment). Base64url is RFC 4648 section 5 without padding; HMAC is RFC 2104 through `node:crypto`.

### Defended

| Threat | Defence |
|---|---|
| Payload tampering | The HMAC covers the version prefix and payload; any change fails with `signature`. |
| Forging without a secret | A valid HMAC needs one of the configured secrets (at least 32 bytes each). |
| Timing leaks on comparison | `crypto.timingSafeEqual` is run against every secret without early exit. |
| Reuse after the TTL | `iat` is signed; cursors past `iat + ttlSeconds` fail with `expired`. Cursors issued more than 300 s in the future are `malformed`. |
| Reuse with a different query | Bind `filterHash(filters)` into the cursor and pass it to `decode`. Put tenant and user ids in the filters. |
| Oversized input | Cursors longer than 4096 characters are rejected before any other work. |
| SQL injection through field names | Identifiers must match `^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?$`; values only appear in `params`. |
| Non-canonical encodings | Base64url must be strict and canonical (alphabet only, unused low bits zero), so one cursor has one text form. Malformed input is rejected before any HMAC is computed. |

Error messages and events never contain the cursor or a secret.

### Not defended

- Confidentiality of key values: cursors are signed, not encrypted, so a client can read the key values. Do not put secrets in keys.
- Replay within the TTL: the same cursor can be used repeatedly until it expires.
- Leaked secrets: anyone holding a secret can forge cursors. Rotate by putting the new secret first and keeping the old one until old cursors expire.

### Out of scope

Backward pages, offset pagination, ORM adapters and encryption.

## Operational guidance

- Generate secrets from a CSPRNG and load them from a secret manager, not from source code.
- Sort fields must be NOT NULL columns and the last one should be unique, otherwise rows can be skipped or repeated.
- `decode` only checks the filter hash when you pass `expected.filterHash`; always pass it for scoped queries.
- `toSqlWhere` emits no outer parentheses; wrap the fragment when combining it with other conditions.
- `filterHash` is the SHA-256 of JSON with recursively sorted keys. It is not RFC 8785 JCS.
