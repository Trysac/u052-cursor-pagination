# Sign cursors with HMAC-SHA256 and build keyset predicates as parameterised DNF

Status: accepted (generated, pending human review)

## Context

Offset pagination skips or repeats rows when data changes, and plain base64 cursors (as in graphql-relay) can be edited by clients to read outside their query. Multi-column keyset predicates are easy to get wrong when tie-breaking. The library must run on Node.js with no runtime dependencies and be safe against malformed or hostile input.

## Decision

Cursors have the format v1.<base64url payload>.<base64url HMAC-SHA256>, with the HMAC computed through node:crypto over the ASCII string 'v1.' + payload segment. Decoding applies cheap structural checks first (length, three parts, strict canonical base64url) so malformed input never reaches the HMAC, then compares the signature against every configured secret with timingSafeEqual and without early exit (enabling rotation), and only then parses JSON and checks shape, issue time, expiry and the bound filter hash. The query binding is a SHA-256 over JSON with recursively sorted keys. The keyset predicate is generated in disjunctive normal form and rendered with unquoted identifiers that are validated against a strict regex while values only travel in positional parameters. All failures use typed errors with stable codes and fixed messages that never echo input.

## Consequences

Clients cannot tamper with, forge or reuse cursors beyond their TTL or query, and rotation needs no downtime. Key values remain readable (signed, not encrypted) and cursors can be replayed within the TTL, which is documented. The DNF predicate is correct for any number of NOT NULL sort columns but needs an index that matches the sort and a unique last column. The filter hash is not RFC 8785 JCS, so it must not be compared across implementations. Limits (4096-character cursors, 8 sort fields, 32 levels of filter nesting) are enforced and raise CursorConfigError or InvalidCursorError.
