import { createHash, createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import * as lib from "../src/index.js";

const {
  CursorConfigError,
  CursorError,
  InvalidCursorError,
  buildKeysetPredicate,
  createCursorCodec,
  filterHash,
  paginate,
  toSqlWhere,
} = lib;

const NOW = 1_700_000_000_000;

describe("acceptance literals", () => {
  it("encode({key: {id: 7}, filterHash: 'f'}) then decode returns key {id: 7}, filterHash 'f' and iat", () => {
    const codec = createCursorCodec({ secrets: ["s".repeat(32)], now: () => NOW });
    const cursor = codec.encode({ key: { id: 7 }, filterHash: "f" });
    expect(codec.decode(cursor).key).toEqual({ id: 7 });
  });

  it("a cursor with '=' padding, a trailing '\\n' is malformed", () => {
    const codec = createCursorCodec({ secrets: ["s".repeat(32)], now: () => NOW });
    const cursor = codec.encode({ key: { id: 7 } });
    expect(() => codec.decode(`${cursor}=`)).toThrow(InvalidCursorError);
    expect(() => codec.decode(`${cursor}\n`)).toThrow(InvalidCursorError);
  });

  it("toSqlWhere(buildKeysetPredicate([{field: 'created_at', order: 'desc'}, {field: 'id', order: 'asc'}], {created_at: '2024-01-01', id: 7})) returns {sql: '(created_at < $1) OR (created_at = $2 AND id > $3)', params: ['2024-01-01', '2024-01-01', 7]}", () => {
    const out = toSqlWhere(
      buildKeysetPredicate(
        [
          { field: "created_at", order: "desc" },
          { field: "id", order: "asc" },
        ],
        { created_at: "2024-01-01", id: 7 },
      ),
    );
    expect(out).toEqual({
      sql: "(created_at < $1) OR (created_at = $2 AND id > $3)",
      params: ["2024-01-01", "2024-01-01", 7],
    });
  });
});
const SECRET = "s".repeat(32);
const OLD_SECRET = "o".repeat(32);
const NEW_SECRET = "n".repeat(32);
const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

function makeCodec(overrides: Partial<lib.CursorCodecOptions> = {}): lib.CursorCodec {
  const base = { secrets: [SECRET], now: () => NOW };
  return createCursorCodec({ ...base, ...overrides });
}

function codeOf(fn: () => unknown): string {
  try {
    fn();
  } catch (error) {
    return error instanceof CursorError ? error.code : "other";
  }
  return "none";
}

function decodeCode(cursor: string, codec = makeCodec()): string {
  return codeOf(() => codec.decode(cursor));
}

function signed(payload: string, secret = SECRET): string {
  const segment = Buffer.from(payload, "utf8").toString("base64url");
  const signature = createHmac("sha256", secret)
    .update(`v1.${segment}`, "ascii")
    .digest("base64url");
  return `v1.${segment}.${signature}`;
}

function body(k: string, fh = "null", iat = "1700000000"): string {
  return `{"k":${k},"fh":${fh},"iat":${iat}}`;
}

function segments(cursor: string): { payload: string; signature: string } {
  const [, payload = "", signature = ""] = cursor.split(".");
  return { payload, signature };
}

function swapFirst(segment: string): string {
  const first = segment.startsWith("A") ? "B" : "A";
  return first + segment.slice(1);
}

function flipLast(segment: string, mask: number): string {
  const index = ALPHABET.indexOf(segment.slice(-1));
  return segment.slice(0, -1) + ALPHABET.charAt(index ^ mask);
}

describe("createCursorCodec", () => {
  it("round-trips a cursor with an injected clock", () => {
    const codec = makeCodec();
    const cursor = codec.encode({ key: { id: 7 }, filterHash: "f" });
    expect(cursor).toMatch(/^v1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$/);
    expect(codec.decode(cursor)).toEqual({
      key: { id: 7 },
      filterHash: "f",
      iat: 1_700_000_000,
    });
  });

  it("signs 'v1.' + payload with an independent HMAC-SHA256", () => {
    const cursor = makeCodec().encode({ key: { id: 7 }, filterHash: "f" });
    expect(cursor).toBe(signed('{"k":{"id":7},"fh":"f","iat":1700000000}'));
  });

  it("reports a null filterHash when none was bound", () => {
    const codec = makeCodec();
    expect(codec.decode(codec.encode({ key: { id: 1 } })).filterHash).toBeNull();
  });

  it("preserves every accepted value type exactly", () => {
    const codec = makeCodec();
    const key = {
      a: 1.5,
      b: true,
      c: "é",
      d: -1,
      e: Number.MAX_SAFE_INTEGER,
      f: 0,
      g: "",
      h: false,
    };
    const decoded = codec.decode(codec.encode({ key })).key;
    for (const [name, value] of Object.entries(key)) {
      expect(Object.is(decoded[name], value)).toBe(true);
    }
  });

  it("rejects a changed first character of payload or signature", () => {
    const codec = makeCodec();
    const cursor = codec.encode({ key: { id: 7 } });
    const { payload, signature } = segments(cursor);
    const badPayload = `v1.${swapFirst(payload)}.${signature}`;
    const badSignature = `v1.${payload}.${swapFirst(signature)}`;
    expect(decodeCode(badPayload)).toBe("signature");
    expect(decodeCode(badSignature)).toBe("signature");
    expect(() => codec.decode(badPayload)).toThrow(InvalidCursorError);
  });

  it("decodes cursors signed with an older secret after rotation", () => {
    const oldCursor = makeCodec({ secrets: [OLD_SECRET] }).encode({
      key: { id: 1 },
    });
    const rotated = makeCodec({ secrets: [NEW_SECRET, OLD_SECRET] });
    expect(rotated.decode(oldCursor).key).toEqual({ id: 1 });
    const onlyNew = makeCodec({ secrets: [NEW_SECRET] });
    expect(decodeCode(oldCursor, onlyNew)).toBe("signature");
    const fresh = rotated.encode({ key: { id: 2 } });
    const onlyOld = makeCodec({ secrets: [OLD_SECRET] });
    expect(decodeCode(fresh, onlyOld)).toBe("signature");
    expect(onlyNew.decode(fresh).key).toEqual({ id: 2 });
  });

  it("accepts Uint8Array secrets and copies them", () => {
    const bytes = new Uint8Array(32).fill(7);
    const codec = makeCodec({ secrets: [bytes] });
    const cursor = codec.encode({ key: { id: 1 } });
    bytes.fill(0);
    expect(codec.decode(cursor).key).toEqual({ id: 1 });
  });

  const malformed: string[] = [
    "",
    "v1.a",
    "v1.a.b.c",
    "v2.a.b",
    "v1..",
    "v1.e+.x",
    "v1.a.b",
    "v1.e.",
    `v1.${"a".repeat(4094)}`,
  ];
  it.each(malformed)("rejects malformed cursor %j", (cursor) => {
    expect(decodeCode(cursor)).toBe("malformed");
  });

  it("rejects padding, trailing newline and oversized cursors", () => {
    const cursor = makeCodec().encode({ key: { id: 7 } });
    expect(decodeCode(`${cursor}=`)).toBe("malformed");
    expect(decodeCode(`${cursor}\n`)).toBe("malformed");
    expect(decodeCode(` ${cursor}`)).toBe("malformed");
    expect(decodeCode("a".repeat(4097))).toBe("malformed");
    expect(decodeCode(undefined as never)).toBe("malformed");
  });

  it("rejects non-canonical unused low bits in the signature", () => {
    const cursor = makeCodec().encode({ key: { id: 7 } });
    const { payload, signature } = segments(cursor);
    for (const mask of [1, 2, 3]) {
      const forged = `v1.${payload}.${flipLast(signature, mask)}`;
      expect(decodeCode(forged)).toBe("malformed");
    }
  });

  const shapes: [string, string][] = [
    ["not json", "not json"],
    ["array", "[]"],
    ["null", "null"],
    ["missing k", '{"fh":null,"iat":1700000000}'],
    ["missing fh", '{"k":{"id":1},"iat":1700000000}'],
    ["k array", body("[]")],
    ["k empty", body("{}")],
    ["k null value", body('{"id":null}')],
    ["k nested value", body('{"id":[1]}')],
    ["k proto", body('{"__proto__":1}')],
    ["k bad name", body('{"a b":1}')],
    [
      "k nine fields",
      body(
        JSON.stringify(
          Object.fromEntries(Array.from({ length: 9 }, (_, i) => [`f${i}`, i] as const)),
        ),
      ),
    ],
    ["fh number", body('{"id":1}', "5")],
    ["fh too long", body('{"id":1}', JSON.stringify("x".repeat(257)))],
    ["iat string", body('{"id":1}', "null", '"1"')],
    ["iat float", body('{"id":1}', "null", "1.5")],
    ["iat negative", body('{"id":1}', "null", "-1")],
  ];
  it.each(shapes)("rejects validly signed bad payload: %s", (_name, text) => {
    expect(decodeCode(signed(text))).toBe("malformed");
  });

  it("accepts a hand-signed well-formed payload", () => {
    const payload = makeCodec().decode(signed(body('{"id":1}')));
    expect(payload).toEqual({ key: { id: 1 }, filterHash: null, iat: 1.7e9 });
  });

  it("rejects an iat more than 300 seconds in the future", () => {
    const ahead = (ms: number) => makeCodec({ now: () => NOW + ms });
    const late = ahead(301_000).encode({ key: { id: 1 } });
    expect(decodeCode(late)).toBe("malformed");
    const edge = ahead(300_000).encode({ key: { id: 1 } });
    expect(makeCodec().decode(edge).key).toEqual({ id: 1 });
  });

  it("expires cursors strictly after the ttl", () => {
    let now = NOW;
    const codec = makeCodec({ ttlSeconds: 60, now: () => now });
    const cursor = codec.encode({ key: { id: 1 } });
    now = 1_700_000_060_000;
    expect(codec.decode(cursor).key).toEqual({ id: 1 });
    now = 1_700_000_060_001;
    expect(decodeCode(cursor, codec)).toBe("expired");
  });

  it("defaults the ttl to one hour", () => {
    let now = NOW;
    const codec = makeCodec({ now: () => now });
    const cursor = codec.encode({ key: { id: 1 } });
    now = NOW + 3_600_000;
    expect(codec.decode(cursor).key).toEqual({ id: 1 });
    now = NOW + 3_600_001;
    expect(decodeCode(cursor, codec)).toBe("expired");
  });

  it("binds cursors to a filter hash", () => {
    const codec = makeCodec();
    const bound = codec.encode({ key: { id: 1 }, filterHash: "abc" });
    expect(codec.decode(bound, { filterHash: "abc" }).iat).toBe(1_700_000_000);
    expect(codeOf(() => codec.decode(bound, { filterHash: "x" }))).toBe("filter_mismatch");
    const unbound = codec.encode({ key: { id: 1 } });
    expect(codeOf(() => codec.decode(unbound, { filterHash: "abc" }))).toBe("filter_mismatch");
    expect(codec.decode(unbound, {}).key).toEqual({ id: 1 });
  });

  it("rejects invalid expectations as configuration errors", () => {
    const codec = makeCodec();
    const cursor = codec.encode({ key: { id: 1 } });
    const badHash = { filterHash: 5 } as never;
    expect(codeOf(() => codec.decode(cursor, badHash))).toBe("config");
    expect(codeOf(() => codec.decode(cursor, "x" as never))).toBe("config");
  });

  const badOptions: [string, unknown][] = [
    ["no secrets", { secrets: [] }],
    ["secrets not array", { secrets: "x" }],
    ["31-byte secret", { secrets: ["a".repeat(31)] }],
    ["30-byte multibyte secret", { secrets: ["€".repeat(10)] }],
    ["secret of wrong type", { secrets: [123] }],
    ["short Uint8Array", { secrets: [new Uint8Array(31)] }],
    ["too many secrets", { secrets: Array.from({ length: 17 }, () => SECRET) }],
    ["ttl zero", { secrets: [SECRET], ttlSeconds: 0 }],
    ["ttl too large", { secrets: [SECRET], ttlSeconds: 31_536_001 }],
    ["ttl NaN", { secrets: [SECRET], ttlSeconds: Number.NaN }],
    ["now not a function", { secrets: [SECRET], now: 5 }],
    ["onEvent not a function", { secrets: [SECRET], onEvent: 5 }],
    ["options null", null],
  ];
  it.each(badOptions)("rejects invalid options: %s", (_name, options) => {
    const make = () => createCursorCodec(options as never);
    expect(codeOf(make)).toBe("config");
  });

  it("accepts the ttl bounds and a 32-byte secret", () => {
    expect(() => makeCodec({ ttlSeconds: 1 })).not.toThrow();
    expect(() => makeCodec({ ttlSeconds: 31_536_000 })).not.toThrow();
    expect(() => makeCodec({ secrets: ["€".repeat(11)] })).not.toThrow();
  });

  const badInputs: [string, unknown][] = [
    ["null value", { key: { id: null } }],
    ["negative zero", { key: { id: -0 } }],
    ["NaN", { key: { id: Number.NaN } }],
    ["Infinity", { key: { id: Number.POSITIVE_INFINITY } }],
    ["2 ** 53", { key: { id: 2 ** 53 } }],
    ["huge integer", { key: { id: 1e300 } }],
    ["undefined value", { key: { id: undefined } }],
    ["object value", { key: { id: {} } }],
    ["long string", { key: { id: "x".repeat(513) } }],
    ["empty key", { key: {} }],
    ["array key", { key: [1] }],
    ["missing key", {}],
    ["null input", null],
    ["injection name", { key: { "id; DROP TABLE x": 1 } }],
    ["proto name", { key: JSON.parse('{"__proto__":1}') }],
    ["nine fields", { key: Object.fromEntries("abcdefghi".split("").map((c) => [c, 1])) }],
    ["filterHash number", { key: { id: 1 }, filterHash: 5 }],
    ["filterHash too long", { key: { id: 1 }, filterHash: "x".repeat(257) }],
    [
      "cursor too large",
      {
        key: Object.fromEntries(
          Array.from({ length: 8 }, (_, i) => [`f${i}`, "x".repeat(512)] as const),
        ),
      },
    ],
  ];
  it.each(badInputs)("encode rejects %s", (_name, input) => {
    expect(codeOf(() => makeCodec().encode(input as never))).toBe("config");
  });

  it("rejects a clock that does not return a finite number", () => {
    const broken = makeCodec({ now: () => Number.NaN });
    expect(codeOf(() => broken.encode({ key: { id: 1 } }))).toBe("config");
    const cursor = makeCodec().encode({ key: { id: 1 } });
    expect(decodeCode(cursor, broken)).toBe("config");
  });

  it("emits decode_failed events without leaking the cursor or secret", () => {
    const events: lib.CursorEvent[] = [];
    const codec = makeCodec({ onEvent: (event) => events.push(event) });
    const cursor = codec.encode({ key: { id: 7 } });
    const { payload, signature } = segments(cursor);
    const forged = `v1.${swapFirst(payload)}.${signature}`;
    let message = "";
    let serialized = "";
    try {
      codec.decode(forged);
    } catch (error) {
      message = (error as Error).message;
      serialized = JSON.stringify(error) + String(error);
    }
    expect(events).toEqual([{ type: "decode_failed", reason: "signature" }]);
    const everything = JSON.stringify(events) + message + serialized;
    expect(everything).not.toContain(forged);
    expect(everything).not.toContain(payload.slice(1));
    expect(everything).not.toContain(SECRET);
    expect(codec.decode(cursor).key).toEqual({ id: 7 });
    expect(events).toHaveLength(1);
  });

  it("emits one event per failure reason", () => {
    const reasons: string[] = [];
    let now = NOW;
    const codec = makeCodec({
      ttlSeconds: 1,
      now: () => now,
      onEvent: (event) => reasons.push(event.reason),
    });
    const cursor = codec.encode({ key: { id: 1 }, filterHash: "a" });
    decodeCode("", codec);
    codeOf(() => codec.decode(cursor, { filterHash: "b" }));
    now = NOW + 5000;
    decodeCode(cursor, codec);
    decodeCode(signed(body("{}")), codec);
    expect(reasons).toEqual(["malformed", "filter_mismatch", "expired", "malformed"]);
    decodeCode(signed("x", OLD_SECRET), codec);
    expect(reasons.at(-1)).toBe("signature");
  });

  it("ignores errors thrown by the event listener", () => {
    const codec = makeCodec({
      onEvent: () => {
        throw new Error("listener failure");
      },
    });
    expect(decodeCode("", codec)).toBe("malformed");
  });
});

describe("error classes", () => {
  it("exposes stable codes and names", () => {
    const invalid = new InvalidCursorError("expired", "m");
    expect(invalid).toBeInstanceOf(CursorError);
    expect(invalid).toBeInstanceOf(Error);
    expect(invalid.code).toBe("expired");
    expect(invalid.name).toBe("InvalidCursorError");
    const cfg = new CursorConfigError("m");
    expect(cfg).toBeInstanceOf(CursorError);
    expect(cfg.code).toBe("config");
    expect(cfg.name).toBe("CursorConfigError");
    expect(new CursorError("x", "m").name).toBe("CursorError");
  });
});

describe("filterHash", () => {
  const sha = (text: string) => createHash("sha256").update(text, "utf8").digest("hex");

  it("ignores object key order", () => {
    expect(filterHash({ b: 1, a: 2 })).toBe(filterHash({ a: 2, b: 1 }));
    expect(filterHash({ b: 1, a: 2 })).toBe(sha('{"a":2,"b":1}'));
    expect(filterHash({ b: 1, a: 2 })).toMatch(/^[0-9a-f]{64}$/);
  });

  it("sorts nested keys recursively and keeps array order", () => {
    const value = { b: [1, { d: 1, c: 2 }], a: null, s: "x", t: true, f: false };
    const expected = '{"a":null,"b":[1,{"c":2,"d":1}],"f":false,"s":"x","t":true}';
    expect(filterHash(value)).toBe(sha(expected));
    expect(filterHash([1, 2])).not.toBe(filterHash([2, 1]));
    expect(filterHash({ a: 1 })).not.toBe(filterHash({ a: 2 }));
    expect(filterHash({ a: "1" })).not.toBe(filterHash({ a: 1 }));
  });

  it("hashes scalars and null", () => {
    expect(filterHash(null)).toBe(sha("null"));
    expect(filterHash("a")).toBe(sha('"a"'));
  });

  const nest = (levels: number): unknown => {
    let value: unknown = 0;
    for (let i = 0; i < levels; i += 1) {
      value = [value];
    }
    return value;
  };

  it("allows 32 levels of nesting and rejects 33", () => {
    expect(() => filterHash(nest(32))).not.toThrow();
    expect(codeOf(() => filterHash(nest(33)))).toBe("config");
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    expect(codeOf(() => filterHash(cyclic))).toBe("config");
  });

  class Custom {}
  const unsupported: [string, unknown][] = [
    ["NaN", Number.NaN],
    ["Infinity", Number.NEGATIVE_INFINITY],
    ["undefined", undefined],
    ["nested undefined", { a: undefined }],
    ["array undefined", [1, undefined]],
    ["function", () => 1],
    ["bigint", 1n],
    ["symbol", Symbol("s")],
    ["Date", new Date(0)],
    ["Map", new Map()],
    ["class instance", new Custom()],
  ];
  it.each(unsupported)("rejects %s", (_name, value) => {
    expect(codeOf(() => filterHash(value))).toBe("config");
  });

  it("caps the number of values", () => {
    expect(() => filterHash(new Array(9_999).fill(0))).not.toThrow();
    expect(codeOf(() => filterHash(new Array(10_001).fill(0)))).toBe("config");
  });
});

describe("paginate", () => {
  const codec = makeCodec();
  const keyOf = (row: { id: number }) => ({ id: row.id });

  it("returns a page and a cursor for the last item when more rows exist", () => {
    const rows = [{ id: 1 }, { id: 2 }, { id: 3 }];
    const page = paginate(rows, { limit: 2, keyOf, codec });
    expect(page.items).toEqual([{ id: 1 }, { id: 2 }]);
    expect(page.hasMore).toBe(true);
    expect(codec.decode(page.nextCursor ?? "").key).toEqual({ id: 2 });
  });

  it("returns no cursor on the last page", () => {
    const page = paginate([{ id: 1 }, { id: 2 }], { limit: 2, keyOf, codec });
    expect(page.items).toHaveLength(2);
    expect(page.hasMore).toBe(false);
    expect(page.nextCursor).toBeNull();
    const empty = paginate([], { limit: 5, keyOf, codec });
    expect(empty).toEqual({ items: [], hasMore: false, nextCursor: null });
  });

  it("binds the filter hash into the next cursor", () => {
    const rows = [{ id: 1 }, { id: 2 }];
    const options = { limit: 1, keyOf, codec, filterHash: "h" };
    const page = paginate(rows, options);
    const cursor = page.nextCursor ?? "";
    expect(codec.decode(cursor, { filterHash: "h" }).filterHash).toBe("h");
  });

  it("slices to the limit even when more rows were fetched", () => {
    const rows = [{ id: 1 }, { id: 2 }, { id: 3 }, { id: 4 }];
    const page = paginate(rows, { limit: 1, keyOf, codec });
    expect(page.items).toEqual([{ id: 1 }]);
    expect(codec.decode(page.nextCursor ?? "").key).toEqual({ id: 1 });
  });

  it.each([0, 1001, 1.5, Number.NaN, -1])("rejects limit %s", (limit) => {
    expect(codeOf(() => paginate([], { limit, keyOf, codec }))).toBe("config");
  });

  it("accepts the limit bounds", () => {
    expect(() => paginate([], { limit: 1, keyOf, codec })).not.toThrow();
    expect(() => paginate([], { limit: 1000, keyOf, codec })).not.toThrow();
  });

  it("rejects invalid arguments and invalid keys", () => {
    const run = (items: unknown, options: unknown) =>
      codeOf(() => paginate(items as never, options as never));
    expect(run("x", { limit: 1, keyOf, codec })).toBe("config");
    expect(run([], { limit: 1, codec })).toBe("config");
    expect(run([], { limit: 1, keyOf })).toBe("config");
    const badKey = () => ({ id: Number.NaN });
    const options = { limit: 1, keyOf: badKey, codec };
    expect(run([{ id: 1 }, { id: 2 }], options)).toBe("config");
  });
});

describe("buildKeysetPredicate and toSqlWhere", () => {
  const mixed: lib.SortField[] = [
    { field: "created_at", order: "desc" },
    { field: "id", order: "asc" },
  ];

  it("builds the documented two-column predicate", () => {
    const key = { created_at: "2024-01-01", id: 7 };
    const result = toSqlWhere(buildKeysetPredicate(mixed, key));
    expect(result).toEqual({
      sql: "(created_at < $1) OR (created_at = $2 AND id > $3)",
      params: ["2024-01-01", "2024-01-01", 7],
    });
  });

  it("builds the disjunctive normal form for three columns", () => {
    const sort: lib.SortField[] = [
      { field: "a", order: "asc" },
      { field: "b", order: "desc" },
      { field: "c", order: "asc" },
    ];
    const predicate = buildKeysetPredicate(sort, { a: 1, b: 2, c: 3 });
    expect(predicate).toHaveLength(3);
    expect(predicate[1]).toEqual([
      { field: "a", op: "=", value: 1 },
      { field: "b", op: "<", value: 2 },
    ]);
    const { sql, params } = toSqlWhere(predicate);
    expect(sql).toBe("(a > $1) OR (a = $2 AND b < $3) OR (a = $4 AND b = $5 AND c > $6)");
    expect(params).toEqual([1, 1, 2, 1, 2, 3]);
  });

  it("supports a single field, dotted names and custom placeholders", () => {
    const sort: lib.SortField[] = [{ field: "users.id", order: "asc" }];
    const predicate = buildKeysetPredicate(sort, { "users.id": 5 });
    expect(toSqlWhere(predicate).sql).toBe("(users.id > $1)");
    expect(toSqlWhere(predicate, () => "?").sql).toBe("(users.id > ?)");
    expect(toSqlWhere(predicate, (i) => `:p${i}`).sql).toBe("(users.id > :p1)");
  });

  it("keeps values out of the SQL text", () => {
    const sort: lib.SortField[] = [{ field: "name", order: "asc" }];
    const evil = "'; DROP TABLE x; --";
    const result = toSqlWhere(buildKeysetPredicate(sort, { name: evil }));
    expect(result.sql).toBe("(name > $1)");
    expect(result.params).toEqual([evil]);
  });

  it("accepts boolean key values and ignores extra key fields", () => {
    const sort: lib.SortField[] = [{ field: "flag", order: "desc" }];
    const predicate = buildKeysetPredicate(sort, { flag: true, extra: 1 });
    expect(toSqlWhere(predicate).params).toEqual([true]);
  });

  it.each([
    "id; DROP TABLE x",
    "a.b.c",
    "1a",
    "a b",
    "id\n",
    "",
    "é",
    "a-b",
    "a;b",
    "a'",
    'a"',
    "a.",
    "__proto__",
    "a".repeat(129),
  ])("rejects field name %j", (field) => {
    const sort: lib.SortField[] = [{ field, order: "asc" }];
    const key = Object.fromEntries([[field, 1]]);
    expect(codeOf(() => buildKeysetPredicate(sort, key))).toBe("config");
  });

  const asc = (field: string) => ({ field, order: "asc" });
  const badBuilds: [string, unknown, unknown][] = [
    ["injection field", [asc("id; DROP TABLE x")], { id: 1 }],
    ["empty sort", [], { id: 1 }],
    ["sort not an array", "id", { id: 1 }],
    ["nine fields", "abcdefghi".split("").map(asc), { a: 1 }],
    ["bad order", [{ field: "id", order: "up" }], { id: 1 }],
    ["duplicate field", [asc("id"), asc("id")], { id: 1 }],
    ["missing key field", [asc("a"), asc("id")], { a: "x" }],
    ["inherited key field", [asc("toString")], {}],
    ["null value", [asc("id")], { id: null }],
    ["negative zero", [asc("id")], { id: -0 }],
    ["NaN", [asc("id")], { id: Number.NaN }],
    ["2 ** 53", [asc("id")], { id: 2 ** 53 }],
    ["entry not an object", [null], { id: 1 }],
    ["field not a string", [{ field: 5, order: "asc" }], { id: 1 }],
    ["key null", [asc("id")], null],
  ];
  it.each(badBuilds)("rejects %s", (_name, sort, key) => {
    const run = () => buildKeysetPredicate(sort as never, key as never);
    expect(codeOf(run)).toBe("config");
  });

  it("returns frozen results", () => {
    const predicate = buildKeysetPredicate(mixed, { created_at: "x", id: 1 });
    expect(Object.isFrozen(predicate)).toBe(true);
    expect(Object.isFrozen(toSqlWhere(predicate).params)).toBe(true);
  });

  const condition = { field: "id", op: "=", value: 1 };
  const badPredicates: [string, unknown][] = [
    ["not an array", "x"],
    ["empty", []],
    ["empty disjunct", [[]]],
    ["disjunct not an array", ["x"]],
    ["condition not an object", [[null]]],
    ["injection field", [[{ ...condition, field: "id; DROP TABLE x" }]]],
    ["field not a string", [[{ ...condition, field: 5 }]]],
    ["bad operator", [[{ ...condition, op: "!=" }]]],
    ["null value", [[{ ...condition, value: null }]]],
    ["NaN value", [[{ ...condition, value: Number.NaN }]]],
    ["nine disjuncts", Array.from({ length: 9 }, () => [condition])],
    ["nine conditions", [Array.from({ length: 9 }, () => condition)]],
  ];
  it.each(badPredicates)("toSqlWhere rejects %s", (_name, predicate) => {
    expect(codeOf(() => toSqlWhere(predicate as never))).toBe("config");
  });

  it("toSqlWhere rejects invalid placeholders", () => {
    const predicate = buildKeysetPredicate([asc("id") as lib.SortField], {
      id: 1,
    });
    const run = (placeholder: unknown) => codeOf(() => toSqlWhere(predicate, placeholder as never));
    expect(run("x")).toBe("config");
    expect(run(() => 5)).toBe("config");
    expect(run(() => "$1; DROP TABLE x")).toBe("config");
    expect(run(() => "")).toBe("config");
  });
});

describe("threat model", () => {
  it("defends against payload tampering", () => {
    const codec = makeCodec();
    const cursor = codec.encode({ key: { id: 7 } });
    const { payload, signature } = segments(cursor);
    const forgedPayload = Buffer.from('{"k":{"id":1},"fh":null,"iat":1700000000}').toString(
      "base64url",
    );
    expect(decodeCode(`v1.${forgedPayload}.${signature}`)).toBe("signature");
    expect(decodeCode(`v1.${swapFirst(payload)}.${signature}`)).toBe("signature");
  });

  it("defends against forging without a secret", () => {
    const forged = signed(body('{"id":1}'), "x".repeat(32));
    expect(decodeCode(forged)).toBe("signature");
    expect(decodeCode(`v1.${segments(forged).payload}.${"A".repeat(43)}`)).toBe("signature");
  });

  it("defends against reuse after the ttl", () => {
    let now = NOW;
    const codec = makeCodec({ ttlSeconds: 10, now: () => now });
    const cursor = codec.encode({ key: { id: 1 } });
    now = NOW + 11_000;
    expect(decodeCode(cursor, codec)).toBe("expired");
  });

  it("defends against reuse with a different query", () => {
    const codec = makeCodec();
    const tenantA = filterHash({ tenant: "a", user: 1 });
    const tenantB = filterHash({ tenant: "b", user: 1 });
    const cursor = codec.encode({ key: { id: 1 }, filterHash: tenantA });
    expect(codeOf(() => codec.decode(cursor, { filterHash: tenantB }))).toBe("filter_mismatch");
  });

  it("defends against oversized input", () => {
    expect(decodeCode(`v1.${"a".repeat(4094)}`)).toBe("malformed");
    expect(decodeCode("v1.".concat("a".repeat(5000)))).toBe("malformed");
  });

  it("defends against SQL injection through field names", () => {
    const sort: lib.SortField[] = [{ field: "id; DROP TABLE x", order: "asc" }];
    const key = { "id; DROP TABLE x": 1 };
    expect(codeOf(() => buildKeysetPredicate(sort, key))).toBe("config");
  });

  it("does not defend the confidentiality of key values", () => {
    const cursor = makeCodec().encode({ key: { id: 7 } });
    const text = Buffer.from(segments(cursor).payload, "base64url").toString();
    expect(text).toContain('"id":7');
  });

  it("does not defend against replay within the ttl", () => {
    const codec = makeCodec();
    const cursor = codec.encode({ key: { id: 7 } });
    expect(codec.decode(cursor).key).toEqual({ id: 7 });
    expect(codec.decode(cursor).key).toEqual({ id: 7 });
  });
});
