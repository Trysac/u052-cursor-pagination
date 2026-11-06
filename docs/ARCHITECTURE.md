# Architecture

## Overview

`@trysac/cursor-pagination` is a small, dependency-free TypeScript library published to npm as ES modules with type declarations. It provides HMAC-signed keyset pagination cursors with expiry, secret rotation and query binding, and a parameterised SQL keyset predicate builder. The only runtime import is `node:crypto`.

## Modules

| Module | Responsibility |
|---|---|
| `src/index.ts` | Entire public API: cursor codec, `filterHash`, `paginate`, `buildKeysetPredicate`, `toSqlWhere` and the error classes. |

The library is a single module. Internal helpers in `src/index.ts` are not exported.

## Boundaries

- No runtime dependencies. The only built-in module used is `node:crypto` (`createHash`, `createHmac`, `timingSafeEqual`).
- No I/O at import time. Functions are pure except `createCursorCodec`, which reads the injected clock when encoding or decoding.
- Errors are thrown as `CursorError` subclasses (`InvalidCursorError`, `CursorConfigError`) with a stable `code`.

## Build and distribution

`npm run build` compiles `src/` to `dist/` with `tsconfig.build.json`. Only `dist/` is published (`files` in `package.json`).

## Decisions

Architectural decisions are recorded in [decisions/](decisions/), starting with [0001](decisions/0001-record-architecture-decisions.md).
