import { createHmac } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { createCursorCodec, InvalidCursorError } from "../src/index.js";

vi.mock("node:crypto", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:crypto")>();
  return { ...actual, createHmac: vi.fn(actual.createHmac) };
});

const NOW = 1_700_000_000_000;
const FIRST = "a".repeat(32);
const SECOND = "b".repeat(32);
const THIRD = "c".repeat(32);
const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

function codecWith(secrets: string[]) {
  return createCursorCodec({ secrets, now: () => NOW });
}

describe("HMAC ordering", () => {
  it("computes no HMAC for malformed cursors", () => {
    const codec = codecWith([FIRST, SECOND, THIRD]);
    const cursor = codec.encode({ key: { id: 1 } });
    const [, payload = "", signature = ""] = cursor.split(".");
    const last = signature.slice(-1);
    const flipped = signature.slice(0, -1) + ALPHABET.charAt(ALPHABET.indexOf(last) ^ 1);
    const bad = [
      "",
      "v1.a",
      "v1.a.b.c",
      `${cursor}=`,
      `${cursor}\n`,
      `v1.${"a".repeat(4094)}`,
      `v1.${payload}.${flipped}`,
    ];
    vi.mocked(createHmac).mockClear();
    for (const candidate of bad) {
      expect(() => codec.decode(candidate)).toThrow(InvalidCursorError);
    }
    expect(createHmac).not.toHaveBeenCalled();
  });

  it("tries every secret without an early exit", () => {
    const codec = codecWith([FIRST, SECOND, THIRD]);
    const first = codec.encode({ key: { id: 1 } });
    const last = codecWith([THIRD]).encode({ key: { id: 1 } });
    vi.mocked(createHmac).mockClear();
    codec.decode(first);
    expect(createHmac).toHaveBeenCalledTimes(3);
    vi.mocked(createHmac).mockClear();
    codec.decode(last);
    expect(createHmac).toHaveBeenCalledTimes(3);
    const stranger = codecWith(["z".repeat(32)]).encode({ key: { id: 1 } });
    vi.mocked(createHmac).mockClear();
    expect(() => codec.decode(stranger)).toThrow(InvalidCursorError);
    expect(createHmac).toHaveBeenCalledTimes(3);
  });
});
