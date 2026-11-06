# Demo

A complete round trip: sign a cursor, bind it to a query, verify it and build the next SQL predicate.

```ts
import {
  buildKeysetPredicate,
  createCursorCodec,
  filterHash,
  paginate,
  toSqlWhere,
} from "@trysac/cursor-pagination";

const codec = createCursorCodec({
  secrets: ["replace-with-a-random-secret-of-32+bytes"],
  ttlSeconds: 600,
});

const filters = { tenant: "acme", user: 42 };
const bound = filterHash(filters);
const sort = [
  { field: "created_at", order: "desc" },
  { field: "id", order: "asc" },
] as const;

// Rows fetched with LIMIT 3 (limit + 1).
const rows = [
  { id: 1, created_at: "2024-03-01" },
  { id: 2, created_at: "2024-02-01" },
  { id: 3, created_at: "2024-01-01" },
];
const page = paginate(rows, {
  limit: 2,
  keyOf: (row) => ({ created_at: row.created_at, id: row.id }),
  codec,
  filterHash: bound,
});

// On the next request the client sends page.nextCursor back.
const payload = codec.decode(page.nextCursor ?? "", { filterHash: bound });
const { sql, params } = toSqlWhere(buildKeysetPredicate(sort, payload.key));
console.log(sql);
// (created_at < $1) OR (created_at = $2 AND id > $3)
console.log(params);
// ["2024-02-01", "2024-02-01", 2]
```

A cursor that was edited, expired, signed with an unknown secret or created for another query throws `InvalidCursorError` with the code `signature`, `expired` or `filter_mismatch`.
