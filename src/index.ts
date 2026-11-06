/**
 * Opaque, HMAC-signed keyset pagination cursors with expiry, secret rotation,
 * query binding and a parameterised SQL keyset predicate builder.
 *
 * ## Threat model
 *
 * Defended: payload tampering, forging a cursor without a secret, timing
 * leaks on the signature comparison, reuse after the TTL, reuse with a
 * different query (put tenant and user ids in the filters you hash), oversized
 * input and SQL injection through field names.
 *
 * Not defended: confidentiality of key values (cursors are signed, not
 * encrypted), replay within the TTL and leaked secrets.
 *
 * Out of scope: backward pages, offset pagination, ORM adapters, encryption.
 *
 * @packageDocumentation
 */

import { createHash, createHmac, timingSafeEqual } from "node:crypto";

const VERSION = "v1";
const MAX_CURSOR_LENGTH = 4096;
const MAX_FUTURE_SKEW_SECONDS = 300;
const DEFAULT_TTL_SECONDS = 3600;
const MAX_TTL_SECONDS = 31_536_000;
const MIN_SECRET_BYTES = 32;
const MAX_SECRETS = 16;
const MAX_SORT_FIELDS = 8;
const MAX_KEY_STRING_LENGTH = 512;
const MAX_FIELD_NAME_LENGTH = 128;
const MAX_FILTER_HASH_LENGTH = 256;
const MAX_PAGE_LIMIT = 1000;
const MAX_FILTER_DEPTH = 32;
const MAX_FILTER_NODES = 10_000;
const SIGNATURE_BYTES = 32;
const FIELD_RE = /^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?$/;
const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;
const PLACEHOLDER_RE = /^[A-Za-z0-9_$:?@]{1,32}$/;

/** A scalar value that may be part of a cursor key. */
export type KeyValue = string | number | boolean;

/** Sort-key values of the last row of a page, keyed by column name. */
export type CursorKey = Readonly<Record<string, KeyValue>>;

/** Why a cursor was rejected. */
export type InvalidReason = "malformed" | "signature" | "expired" | "filter_mismatch";

/** Direction of one sort column. */
export type SortOrder = "asc" | "desc";

/** Base class of every error thrown by this library. */
export class CursorError<C extends string = string> extends Error {
  /** Stable machine-readable error code. */
  readonly code: C;

  constructor(code: C, message: string) {
    super(message);
    this.name = "CursorError";
    this.code = code;
  }
}

/** Thrown by `decode` when a cursor is rejected. Never contains the cursor. */
export class InvalidCursorError extends CursorError<InvalidReason> {
  constructor(code: InvalidReason, message: string) {
    super(code, message);
    this.name = "InvalidCursorError";
  }
}

/** Thrown when options or inputs supplied by the caller are invalid. */
export class CursorConfigError extends CursorError<"config"> {
  constructor(message: string) {
    super("config", message);
    this.name = "CursorConfigError";
  }
}

const INVALID_MESSAGES: Readonly<Record<InvalidReason, string>> = {
  malformed: "cursor is malformed",
  signature: "cursor signature is invalid",
  expired: "cursor has expired",
  filter_mismatch: "cursor does not match the current query",
};

function config(message: string): CursorConfigError {
  return new CursorConfigError(message);
}

function invalid(reason: InvalidReason): InvalidCursorError {
  return new InvalidCursorError(reason, INVALID_MESSAGES[reason]);
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function isKeyValue(value: unknown): value is KeyValue {
  switch (typeof value) {
    case "string":
      return value.length <= MAX_KEY_STRING_LENGTH;
    case "boolean":
      return true;
    case "number": {
      const safe = !Number.isInteger(value) || Number.isSafeInteger(value);
      return Number.isFinite(value) && !Object.is(value, -0) && safe;
    }
    default:
      return false;
  }
}

function isIdentifier(name: string): boolean {
  return name.length <= MAX_FIELD_NAME_LENGTH && name !== "__proto__" && FIELD_RE.test(name);
}

function parseKey(raw: unknown): CursorKey | null {
  if (!isPlainObject(raw)) {
    return null;
  }
  const names = Object.keys(raw);
  if (names.length < 1 || names.length > MAX_SORT_FIELDS) {
    return null;
  }
  const out: Record<string, KeyValue> = {};
  for (const name of names) {
    const value = raw[name];
    if (!isIdentifier(name) || !isKeyValue(value)) {
      return null;
    }
    out[name] = value;
  }
  return out;
}

/** Decoded, verified contents of a cursor. */
export interface CursorPayload {
  /** The key values the cursor was created with. */
  readonly key: CursorKey;
  /** The bound filter hash, or `null` when none was bound. */
  readonly filterHash: string | null;
  /** Issue time in whole seconds since the Unix epoch. */
  readonly iat: number;
}

/** Input of `CursorCodec.encode`. */
export interface CursorEncodeInput {
  /** Sort-key values of the last row of the page (1 to 8 fields). */
  readonly key: CursorKey;
  /** Optional hash of the query filters, see {@link filterHash}. */
  readonly filterHash?: string;
}

/** Expectations checked by `CursorCodec.decode`. */
export interface CursorExpectation {
  /** When set, the cursor must have been bound to exactly this hash. */
  readonly filterHash?: string;
}

/** Event passed to `onEvent`. Never contains the cursor or any secret. */
export interface CursorEvent {
  readonly type: "decode_failed";
  readonly reason: InvalidReason;
}

/** Options of {@link createCursorCodec}. */
export interface CursorCodecOptions {
  /** Secrets of at least 32 bytes. The first signs, all of them verify. */
  readonly secrets: readonly (string | Uint8Array)[];
  /** Cursor lifetime in seconds, 1 to 31536000. Defaults to 3600. */
  readonly ttlSeconds?: number;
  /** Clock returning epoch milliseconds. Defaults to `Date.now`. */
  readonly now?: () => number;
  /** Called for every rejected cursor. Errors it throws are ignored. */
  readonly onEvent?: (event: CursorEvent) => void;
}

/** Encodes and verifies signed cursors. */
export interface CursorCodec {
  /**
   * Creates `v1.<payload>.<signature>` for `input`.
   * @throws {CursorConfigError} When the input is invalid or too large.
   */
  encode(input: CursorEncodeInput): string;
  /**
   * Verifies `cursor` and returns its payload.
   * @throws {InvalidCursorError} With code `malformed`, `signature`,
   * `expired` or `filter_mismatch`.
   * @throws {CursorConfigError} When `expected` or the clock is invalid.
   */
  decode(cursor: string, expected?: CursorExpectation): CursorPayload;
}

interface SecretSet {
  readonly primary: Buffer;
  readonly all: readonly Buffer[];
}

function toSecretBuffer(secret: unknown): Buffer {
  let bytes: Buffer;
  if (typeof secret === "string") {
    bytes = Buffer.from(secret, "utf8");
  } else if (secret instanceof Uint8Array) {
    bytes = Buffer.from(secret);
  } else {
    throw config("each secret must be a string or a Uint8Array");
  }
  if (bytes.length < MIN_SECRET_BYTES) {
    throw config("each secret must be at least 32 bytes");
  }
  return bytes;
}

function normalizeSecrets(secrets: unknown): SecretSet {
  if (!Array.isArray(secrets) || secrets.length < 1 || secrets.length > MAX_SECRETS) {
    throw config("secrets must hold between 1 and 16 entries");
  }
  const all = secrets.map((secret) => toSecretBuffer(secret));
  return { primary: all[0] as Buffer, all };
}

function hmac(secret: Buffer, input: string): Buffer {
  return createHmac("sha256", secret).update(input, "ascii").digest();
}

function decodeCanonical(segment: string): Buffer | null {
  if (!BASE64URL_RE.test(segment)) {
    return null;
  }
  const bytes = Buffer.from(segment, "base64url");
  return bytes.toString("base64url") === segment ? bytes : null;
}

function parsePayload(bytes: Buffer): CursorPayload | null {
  let raw: unknown;
  try {
    raw = JSON.parse(bytes.toString("utf8"));
  } catch {
    return null;
  }
  if (!isPlainObject(raw)) {
    return null;
  }
  const key = parseKey(raw.k);
  const hash = raw.fh;
  const iat = raw.iat;
  if (key === null) {
    return null;
  }
  let filterHash: string | null = null;
  if (typeof hash === "string" && hash.length <= MAX_FILTER_HASH_LENGTH) {
    filterHash = hash;
  } else if (hash !== null) {
    return null;
  }
  if (typeof iat !== "number" || !Number.isSafeInteger(iat) || iat < 0) {
    return null;
  }
  return Object.freeze({ key: Object.freeze(key), filterHash, iat });
}

/**
 * Creates a cursor codec.
 *
 * @param options - Secrets, TTL, clock and event hook.
 * @returns A frozen codec.
 * @throws {CursorConfigError} When an option is invalid.
 */
export function createCursorCodec(options: CursorCodecOptions): CursorCodec {
  if (typeof options !== "object" || options === null) {
    throw config("options must be an object");
  }
  const { primary, all } = normalizeSecrets(options.secrets);
  const ttlSeconds = options.ttlSeconds ?? DEFAULT_TTL_SECONDS;
  if (
    typeof ttlSeconds !== "number" ||
    !Number.isFinite(ttlSeconds) ||
    ttlSeconds < 1 ||
    ttlSeconds > MAX_TTL_SECONDS
  ) {
    throw config("ttlSeconds must be between 1 and 31536000");
  }
  const now = options.now ?? Date.now;
  if (typeof now !== "function") {
    throw config("now must be a function");
  }
  const onEvent = options.onEvent;
  if (onEvent !== undefined && typeof onEvent !== "function") {
    throw config("onEvent must be a function");
  }

  const readClock = (): number => {
    const ms = now();
    if (typeof ms !== "number" || !Number.isFinite(ms)) {
      throw config("now must return a finite number of milliseconds");
    }
    return ms;
  };

  const emit = (reason: InvalidReason): void => {
    if (onEvent === undefined) {
      return;
    }
    try {
      onEvent(Object.freeze({ type: "decode_failed" as const, reason }));
    } catch {
      // A failing listener must never change the outcome of decoding.
    }
  };

  const encode = (input: CursorEncodeInput): string => {
    const raw: unknown = input;
    if (!isPlainObject(raw)) {
      throw config("encode input must be an object");
    }
    const key = parseKey(raw.key);
    if (key === null) {
      throw config("key must hold 1 to 8 valid fields with scalar values");
    }
    const hash = raw.filterHash;
    if (hash !== undefined && (typeof hash !== "string" || hash.length > MAX_FILTER_HASH_LENGTH)) {
      throw config("filterHash must be a string of at most 256 characters");
    }
    const iat = Math.floor(readClock() / 1000);
    const json = JSON.stringify({ k: key, fh: hash ?? null, iat });
    const payload = Buffer.from(json, "utf8").toString("base64url");
    const signingInput = `${VERSION}.${payload}`;
    const signature = hmac(primary, signingInput).toString("base64url");
    const cursor = `${signingInput}.${signature}`;
    if (cursor.length > MAX_CURSOR_LENGTH) {
      throw config("cursor would exceed 4096 characters");
    }
    return cursor;
  };

  const verify = (cursor: unknown, expectedHash?: string): CursorPayload => {
    if (typeof cursor !== "string" || cursor.length > MAX_CURSOR_LENGTH) {
      throw invalid("malformed");
    }
    const parts = cursor.split(".");
    const [version, payloadSegment, signatureSegment] = parts;
    if (
      parts.length !== 3 ||
      version !== VERSION ||
      payloadSegment === undefined ||
      signatureSegment === undefined
    ) {
      throw invalid("malformed");
    }
    const payloadBytes = decodeCanonical(payloadSegment);
    const signature = decodeCanonical(signatureSegment);
    if (payloadBytes === null || signature === null || signature.length !== SIGNATURE_BYTES) {
      throw invalid("malformed");
    }
    const signingInput = `${VERSION}.${payloadSegment}`;
    let matched = false;
    for (const secret of all) {
      const equal = timingSafeEqual(hmac(secret, signingInput), signature);
      matched = equal || matched;
    }
    if (!matched) {
      throw invalid("signature");
    }
    const payload = parsePayload(payloadBytes);
    if (payload === null) {
      throw invalid("malformed");
    }
    const nowMs = readClock();
    if (payload.iat * 1000 > nowMs + MAX_FUTURE_SKEW_SECONDS * 1000) {
      throw invalid("malformed");
    }
    if (nowMs > (payload.iat + ttlSeconds) * 1000) {
      throw invalid("expired");
    }
    if (expectedHash !== undefined && expectedHash !== payload.filterHash) {
      throw invalid("filter_mismatch");
    }
    return payload;
  };

  const decode = (cursor: string, expected?: CursorExpectation): CursorPayload => {
    const rawExpected: unknown = expected;
    if (rawExpected !== undefined && !isPlainObject(rawExpected)) {
      throw config("expected must be an object");
    }
    const candidate = rawExpected?.filterHash;
    let expectedHash: string | undefined;
    if (typeof candidate === "string") {
      expectedHash = candidate;
    } else if (candidate !== undefined) {
      throw config("expected.filterHash must be a string");
    }
    try {
      return verify(cursor, expectedHash);
    } catch (error) {
      if (error instanceof InvalidCursorError) {
        emit(error.code);
      }
      throw error;
    }
  };

  return Object.freeze({ encode, decode });
}

interface WalkState {
  nodes: number;
}

function canonicalize(value: unknown, depth: number, state: WalkState): string {
  state.nodes += 1;
  if (state.nodes > MAX_FILTER_NODES) {
    throw config("filters hold more than 10000 values");
  }
  if (value === null) {
    return "null";
  }
  switch (typeof value) {
    case "string":
      return JSON.stringify(value);
    case "boolean":
      return value ? "true" : "false";
    case "number":
      if (!Number.isFinite(value)) {
        throw config("filters must not contain non-finite numbers");
      }
      return JSON.stringify(value);
    case "object":
      break;
    default:
      throw config("filters contain an unsupported value");
  }
  if (depth >= MAX_FILTER_DEPTH) {
    throw config("filters are nested deeper than 32 levels");
  }
  if (Array.isArray(value)) {
    const items: string[] = [];
    for (let i = 0; i < value.length; i += 1) {
      items.push(canonicalize(value[i], depth + 1, state));
    }
    return `[${items.join(",")}]`;
  }
  if (!isPlainObject(value)) {
    throw config("filters must contain only plain objects and arrays");
  }
  const parts = Object.keys(value)
    .sort()
    .map((name) => {
      const inner = canonicalize(value[name], depth + 1, state);
      return `${JSON.stringify(name)}:${inner}`;
    });
  return `{${parts.join(",")}}`;
}

/**
 * Hashes query filters so a cursor can be bound to one query.
 *
 * The hash is the lowercase hex SHA-256 of the JSON text of `filters` with
 * object keys sorted recursively (this is not RFC 8785 JCS). Put tenant and
 * user ids into `filters`.
 *
 * @param filters - Plain objects, arrays, strings, booleans, finite numbers
 * and null, nested at most 32 levels and holding at most 10000 values.
 * @returns 64 lowercase hex characters.
 * @throws {CursorConfigError} For any other input.
 */
export function filterHash(filters: unknown): string {
  const json = canonicalize(filters, 0, { nodes: 0 });
  return createHash("sha256").update(json, "utf8").digest("hex");
}

/** Options of {@link paginate}. */
export interface PaginateOptions<T> {
  /** Page size, 1 to 1000. The caller must have fetched `limit + 1` rows. */
  readonly limit: number;
  /** Extracts the sort-key values of an item. */
  readonly keyOf: (item: T) => CursorKey;
  /** Codec used to create the next cursor. */
  readonly codec: CursorCodec;
  /** Optional filter hash bound into the next cursor. */
  readonly filterHash?: string;
}

/** One page of results. */
export interface Page<T> {
  readonly items: readonly T[];
  readonly hasMore: boolean;
  readonly nextCursor: string | null;
}

/**
 * Trims `limit + 1` fetched rows to a page and creates the next cursor.
 *
 * @param items - Rows fetched with `LIMIT limit + 1`.
 * @param options - Page size, key extractor and codec.
 * @returns The page, whether more rows exist and the cursor for the next page.
 * @throws {CursorConfigError} When the options or the key are invalid.
 */
export function paginate<T>(items: readonly T[], options: PaginateOptions<T>): Page<T> {
  if (!Array.isArray(items)) {
    throw config("items must be an array");
  }
  const { limit, keyOf, codec } = options;
  if (!Number.isInteger(limit) || limit < 1 || limit > MAX_PAGE_LIMIT) {
    throw config("limit must be an integer between 1 and 1000");
  }
  if (typeof keyOf !== "function" || typeof codec?.encode !== "function") {
    throw config("keyOf and codec are required");
  }
  const page = items.slice(0, limit);
  if (items.length <= limit) {
    return { items: page, hasMore: false, nextCursor: null };
  }
  const key = keyOf(page[limit - 1] as T);
  const nextCursor =
    options.filterHash === undefined
      ? codec.encode({ key })
      : codec.encode({ key, filterHash: options.filterHash });
  return { items: page, hasMore: true, nextCursor };
}

/** One sort column. The last column should be unique and NOT NULL. */
export interface SortField {
  readonly field: string;
  readonly order: SortOrder;
}

/** One comparison of a keyset predicate. */
export interface KeysetCondition {
  readonly field: string;
  readonly op: "=" | ">" | "<";
  readonly value: KeyValue;
}

/** Disjunctive normal form: an OR of ANDs of conditions. */
export type KeysetPredicate = readonly (readonly KeysetCondition[])[];

/**
 * Builds the keyset predicate selecting rows strictly after `key`.
 *
 * For `i` in `0..n-1` it emits equality on the fields before `i` and a strict
 * comparison (`>` for asc, `<` for desc) on field `i`. Sort fields must be
 * NOT NULL columns and the last one should be unique.
 *
 * @param sort - 1 to 8 sort fields.
 * @param key - Key values for every sort field.
 * @returns A frozen predicate.
 * @throws {CursorConfigError} For invalid fields, orders or key values.
 */
export function buildKeysetPredicate(sort: readonly SortField[], key: CursorKey): KeysetPredicate {
  if (!Array.isArray(sort) || sort.length < 1 || sort.length > MAX_SORT_FIELDS) {
    throw config("sort must hold between 1 and 8 fields");
  }
  const rawKey: unknown = key;
  if (!isPlainObject(rawKey)) {
    throw config("key must be an object");
  }
  const seen = new Set<string>();
  const specs: { field: string; order: SortOrder; value: KeyValue }[] = [];
  for (const entry of sort as readonly unknown[]) {
    if (!isPlainObject(entry)) {
      throw config("each sort entry must be an object");
    }
    const { field, order } = entry;
    if (typeof field !== "string" || !isIdentifier(field)) {
      throw config("invalid sort field name");
    }
    if (order !== "asc" && order !== "desc") {
      throw config("sort order must be asc or desc");
    }
    if (seen.has(field)) {
      throw config("duplicate sort field");
    }
    seen.add(field);
    if (!Object.hasOwn(rawKey, field)) {
      throw config("key is missing a sort field");
    }
    const value = rawKey[field];
    if (!isKeyValue(value)) {
      throw config("key values must be finite scalars, never null or -0");
    }
    specs.push({ field, order, value });
  }
  const disjuncts: (readonly KeysetCondition[])[] = [];
  for (const [i, spec] of specs.entries()) {
    const conditions: KeysetCondition[] = [];
    for (const before of specs.slice(0, i)) {
      const { field, value } = before;
      conditions.push(Object.freeze({ field, op: "=" as const, value }));
    }
    const op = spec.order === "asc" ? (">" as const) : ("<" as const);
    const { field, value } = spec;
    conditions.push(Object.freeze({ field, op, value }));
    disjuncts.push(Object.freeze(conditions));
  }
  return Object.freeze(disjuncts);
}

/** A SQL fragment and its positional parameters. */
export interface SqlWhere {
  readonly sql: string;
  readonly params: readonly KeyValue[];
}

function defaultPlaceholder(index: number): string {
  return `$${index}`;
}

/**
 * Renders a keyset predicate as a parameterised SQL fragment.
 *
 * Conjuncts are joined with ` AND `, each disjunct is parenthesised and the
 * disjuncts are joined with ` OR `. Identifiers are emitted unquoted after
 * matching `^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?$`; values only
 * ever appear in `params`. Wrap the result in parentheses when combining it
 * with other conditions.
 *
 * @param predicate - Output of {@link buildKeysetPredicate}.
 * @param placeholder - Maps a 1-based parameter index to a placeholder.
 * @returns The SQL text and the parameters in placeholder order.
 * @throws {CursorConfigError} When the predicate or a placeholder is invalid.
 */
export function toSqlWhere(
  predicate: KeysetPredicate,
  placeholder: (index: number) => string = defaultPlaceholder,
): SqlWhere {
  if (!Array.isArray(predicate) || predicate.length < 1 || predicate.length > MAX_SORT_FIELDS) {
    throw config("predicate must hold between 1 and 8 disjuncts");
  }
  if (typeof placeholder !== "function") {
    throw config("placeholder must be a function");
  }
  const params: KeyValue[] = [];
  const clauses: string[] = [];
  for (const disjunct of predicate as readonly unknown[]) {
    if (!Array.isArray(disjunct) || disjunct.length < 1 || disjunct.length > MAX_SORT_FIELDS) {
      throw config("each disjunct must hold between 1 and 8 conditions");
    }
    const parts: string[] = [];
    for (const condition of disjunct as readonly unknown[]) {
      if (!isPlainObject(condition)) {
        throw config("each condition must be an object");
      }
      const { field, op, value } = condition;
      if (typeof field !== "string" || !isIdentifier(field)) {
        throw config("invalid field name in predicate");
      }
      if (op !== "=" && op !== ">" && op !== "<") {
        throw config("invalid operator in predicate");
      }
      if (!isKeyValue(value)) {
        throw config("invalid value in predicate");
      }
      params.push(value);
      const marker = placeholder(params.length);
      if (typeof marker !== "string" || !PLACEHOLDER_RE.test(marker)) {
        throw config("placeholder returned an invalid marker");
      }
      parts.push(`${field} ${op} ${marker}`);
    }
    clauses.push(`(${parts.join(" AND ")})`);
  }
  return Object.freeze({
    sql: clauses.join(" OR "),
    params: Object.freeze(params),
  });
}
