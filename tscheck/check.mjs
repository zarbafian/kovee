#!/usr/bin/env node
// @ts-check
/**
 * Independent TypeScript-family rederiver for the golden vectors under
 * spec/vectors/ (K0). JSDoc-typed plain ES modules; zero runtime
 * dependencies; Node >= 20.
 *
 * Checks, in order:
 *
 * 1. every file under spec/schemas/ (recursively, so the per-operation
 *    suite in spec/schemas/ops/ is included) parses as strict I-JSON and
 *    follows the spec conventions (draft 2020-12, $id present, closed
 *    objects, no remote $ref, resolvable internal $refs, compilable
 *    patterns);
 * 2. the K0 registry bundles delivered so far (spec/registry.json,
 *    COVERED_BUNDLES) are fully covered: every covered entry's operation
 *    has a closed `<op>-request` / `<op>-result` schema pair under
 *    spec/schemas/ops/, the request pins the exact op const, reads carry
 *    no meta member at all, and mutations require meta (§11.2
 *    read/mutation rule, R0 KENV-01);
 * 3. every vector under spec/vectors/ (one `family/name.json` per case, an
 *    object whose `name` matches its path and which carries `description`,
 *    `input`, and `expected`) passes its family checker: schema vectors
 *    match their expected verdict against this file's minimal draft
 *    2020-12 validator (including semantic RFC 3339 date-time via
 *    `format`), raw/synthetic vectors match the full family acceptance
 *    order (PROFILE section 1: size cap, UTF-8, order-3 token classes in
 *    token order, surrogates, depth 64, 65 536 nodes) plus the kovee
 *    §11.8 contextual caps (1 MiB response, 256 list items per request,
 *    64 KiB inline event payload), digest vectors re-derive the
 *    family-PROFILE canonical bytes (RFC 8785 JCS with the reserved
 *    $domain member injected at top level) and their SHA-256, plus the
 *    §11.8 framed typed-bytes digests; `ops` vectors are pure schema
 *    vectors against the per-operation request/result schemas.
 *
 * The derivations are implemented from spec/schemas/README.md, DESIGN.md
 * §11.8, and the family profile (byom/family-vectors/PROFILE.md) — not
 * ported from xcheck/run.py (the Python rederiver) or the Rust workspace.
 * Exits nonzero on any mismatch and on an empty vector tree.
 *
 * Run: node tscheck/check.mjs [vectors-root]
 */

import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { basename, dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const DRAFT = "https://json-schema.org/draft/2020-12/schema";
const SAFE_MAX = 9007199254740991; // 2^53 - 1 (I-JSON safe range)
const SAFE_MAX_BIG = 9007199254740991n;

// DESIGN.md §11.8 + family PROFILE section 1 acceptance caps.
const MAX_REQUEST_BYTES = 262144; // request body: 256 KiB
const MAX_RESPONSE_BYTES = 1048576; // reply: 1 MiB (PROFILE: same rules, 1 MiB cap)
const DEPTH_CAP = 64; // container nesting depth (profile-pinned)
const NODE_CAP = 65536; // JSON values per document (profile-pinned)
const LIST_CAP = 256; // §11.8: a request contains at most 256 list items
const INLINE_CONTENT_CAP = 65536; // §11.8: inline event payload content, 64 KiB

// Per-operation schema suite: the three K1 bundles (plan/sheets/K0.md;
// slice 1 = core_v1 + developer_assistant_v1, slice 2 = shared_space_v1)
// plus K2 slice 1's governed_work_binding_v1 greenfield-binding rows. The
// suite is complete for every registry entry of every covered bundle.
const COVERED_BUNDLES = [
  "core_v1",
  "shared_space_v1",
  "developer_assistant_v1",
  "governed_work_binding_v1",
];

// §11.2 read/mutation split over the covered operations: reads never mutate
// authoritative or user-visible state and never carry meta (R0 KENV-01);
// everything else requires meta. Reads here are the pre-auth negotiation
// pair (hello, public protocol_info — §11.6.1 pre-auth row), diagnose
// (diagnostics read; §11.2 lets reads append security/audit access records
// — spec/schemas/ops/README.md gap note KG3), and the generated
// *_show/*_list read family (§11.6.1). Frozen independently of the schema
// files so a mis-shaped schema cannot reclassify its own operation.
const COVERED_READS = new Set([
  "hello",
  "protocol_info",
  "diagnose",
  "assistant_show",
  "assistant_list",
  "assistant_revision_show",
  "assistant_revision_list",
  "deployment_show",
  "deployment_list",
  "assistant_alias_show",
  "assistant_alias_list",
  "invocation_show",
  "invocation_list",
  // shared_space_v1 (slice 2): the generated *_show/*_list rows plus the
  // named §11.6.1 read-family operations lens_read, events_read,
  // events_wait, event_payload, snapshot_read, and the spelled
  // non-mutating credential query artifact_upload_credential (§10.10;
  // ops README gap notes KG28/KG29).
  "realm_show",
  "project_show",
  "project_list",
  "project_access_policy_change_show",
  "project_access_policy_change_list",
  "space_show",
  "space_list",
  "space_access_widen_show",
  "space_access_widen_list",
  "space_participant_list",
  "space_access_grant_list",
  "contribution_show",
  "contribution_list",
  "frontier_show",
  "lens_show",
  "lens_list",
  "lens_read",
  "context_assembly_show",
  "events_read",
  "events_wait",
  "event_payload",
  "snapshot_read",
  "artifact_upload_show",
  "artifact_upload_credential",
  "artifact_show",
  "disclosure_manifest_show",
  // governed_work_binding_v1 (K2 slice 1): the query-first restore read
  // of the greenfield saga (greenfield-saga §5).
  "governance_show",
]);

/** @type {string[]} */
const FAILURES = [];

/**
 * @param {string} name
 * @param {string} message
 */
function fail(name, message) {
  FAILURES.push(`${name}: ${message}`);
}

/**
 * Structural equality over the JSON value space (objects compare by key
 * set, not key order).
 * @param {unknown} a
 * @param {unknown} b
 * @returns {boolean}
 */
function jsonEqual(a, b) {
  if (a === b) return true;
  if (a === null || b === null || typeof a !== "object" || typeof b !== "object") return false;
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false;
    return a.every((x, i) => jsonEqual(x, b[i]));
  }
  const ao = /** @type {Record<string, unknown>} */ (a);
  const bo = /** @type {Record<string, unknown>} */ (b);
  const keys = Object.keys(ao);
  if (keys.length !== Object.keys(bo).length) return false;
  return keys.every((k) => Object.hasOwn(bo, k) && jsonEqual(ao[k], bo[k]));
}

/** @param {unknown} v */
function isPlainObject(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

// ---------------------------------------------------------------------------
// Strict I-JSON acceptance (DESIGN.md §11.8)
// ---------------------------------------------------------------------------

/** A strict-acceptance rejection carrying its PROFILE error class. */
class AcceptError extends Error {
  /** @param {string} cls */
  constructor(cls) {
    super(cls);
    this.cls = cls;
  }
}

/**
 * Validating scanner for exactly one strict I-JSON text. Iterative (an
 * explicit container stack, no recursion), so nesting bounded only by the
 * byte cap can never overflow the call stack. Values are never
 * materialized. The family PROFILE section 1 order: the order-3 classes
 * (`syntax`/`trailing-data`, `duplicate` at any depth after escape
 * decoding, `unsafe-integer` checked exactly on the token via BigInt,
 * `non-finite` literals, `unsafe-number` for non-finite or unsafe
 * integer-valued floats) surface in token order and abort the scan;
 * surrogates (order 4), container depth, node count, the largest list, and
 * the byte span of a root-level `payload` member (the one §11.3 envelope
 * member carrying inline content) are collected for the later-order
 * checks, so an order-3 error anywhere in the text always wins over them.
 * @param {string} text
 * @returns {{ maxDepth: number, nodes: number, maxListItems: number,
 *             payloadBytes: number | null, surrogate: boolean }}
 */
function scanStrictText(text) {
  let i = 0;
  const n = text.length;
  /** @type {(Set<string> | { items: number })[]} open containers: key sets for objects, item counters for arrays */
  const stack = [];
  const scan = { maxDepth: 0, nodes: 0, maxListItems: 0, payloadBytes: /** @type {number | null} */ (null), surrogate: false };
  let payloadPending = false;
  let payloadActive = false;
  let payloadStart = 0;

  /** @param {string} cls @returns {never} */
  const reject = (cls) => {
    throw new AcceptError(cls);
  };
  const skipWs = () => {
    for (; i < n; i++) {
      const c = text[i];
      if (c !== " " && c !== "\t" && c !== "\n" && c !== "\r") break;
    }
  };
  /** @param {string | undefined} c */
  const isDigit = (c) => c !== undefined && c >= "0" && c <= "9";

  /** Consume the string token whose opening quote is at `i`; return its decoded value. */
  const readString = () => {
    let s = "";
    for (i++; ; ) {
      if (i >= n) reject("syntax");
      const u = text.charCodeAt(i);
      if (u === 0x22) {
        i++;
        break;
      }
      if (u < 0x20) reject("syntax");
      if (u === 0x5c) {
        const e = text[i + 1];
        i += 2;
        if (e === '"' || e === "\\" || e === "/") s += e;
        else if (e === "b") s += "\b";
        else if (e === "f") s += "\f";
        else if (e === "n") s += "\n";
        else if (e === "r") s += "\r";
        else if (e === "t") s += "\t";
        else if (e === "u") {
          const hex = text.slice(i, i + 4);
          if (!/^[0-9A-Fa-f]{4}$/.test(hex)) reject("syntax");
          s += String.fromCharCode(parseInt(hex, 16));
          i += 4;
        } else reject("syntax");
      } else {
        s += text[i];
        i++;
      }
    }
    // I-JSON order 4: unpaired surrogates once escapes are decoded (raw
    // text from a strict UTF-8 decode cannot carry them; \uXXXX can).
    // Flagged, not thrown: order-3 classes later in the text still win.
    for (let k = 0; k < s.length; k++) {
      const u = s.charCodeAt(k);
      if (u >= 0xd800 && u <= 0xdbff) {
        const next = k + 1 < s.length ? s.charCodeAt(k + 1) : 0;
        if (next >= 0xdc00 && next <= 0xdfff) k++;
        else scan.surrogate = true;
      } else if (u >= 0xdc00 && u <= 0xdfff) scan.surrogate = true;
    }
    return s;
  };

  /** Consume the number token starting at `i` and classify it. */
  const readNumber = () => {
    const start = i;
    if (text[i] === "-") {
      i++;
      if (text.startsWith("Infinity", i)) reject("non-finite");
    }
    if (text[i] === "0") i++;
    else if (isDigit(text[i])) while (isDigit(text[i])) i++;
    else reject("syntax");
    let integral = true;
    if (text[i] === ".") {
      integral = false;
      i++;
      if (!isDigit(text[i])) reject("syntax");
      while (isDigit(text[i])) i++;
    }
    if (text[i] === "e" || text[i] === "E") {
      integral = false;
      i++;
      if (text[i] === "+" || text[i] === "-") i++;
      if (!isDigit(text[i])) reject("syntax");
      while (isDigit(text[i])) i++;
    }
    const token = text.slice(start, i);
    if (integral) {
      const v = BigInt(token); // exact, immune to double rounding
      if (v > SAFE_MAX_BIG || v < -SAFE_MAX_BIG) reject("unsafe-integer");
    } else {
      const v = Number(token);
      if (!Number.isFinite(v)) reject("unsafe-number");
      if (Number.isInteger(v) && Math.abs(v) > SAFE_MAX) reject("unsafe-number");
    }
  };

  // States of the token-level machine.
  const WANT_VALUE = 0;
  const WANT_VALUE_OR_ARRAY_END = 1;
  const WANT_KEY_OR_OBJECT_END = 2;
  const WANT_KEY = 3;
  const WANT_COLON = 4;
  const WANT_COMMA_OR_END = 5;
  let state = WANT_VALUE;
  let complete = false;

  /** @param {number} end index one past the completed value's last char */
  const valueDone = (end) => {
    const top = stack[stack.length - 1];
    if (top !== undefined && !(top instanceof Set)) {
      top.items += 1;
      if (top.items > scan.maxListItems) scan.maxListItems = top.items;
    }
    if (payloadActive && stack.length === 1) {
      scan.payloadBytes = Buffer.byteLength(text.slice(payloadStart, end), "utf8");
      payloadActive = false;
    }
    if (stack.length === 0) complete = true;
    else state = WANT_COMMA_OR_END;
  };

  while (!complete) {
    skipWs();
    if (i >= n) reject("syntax");
    const c = text[i];
    if (state === WANT_VALUE || state === WANT_VALUE_OR_ARRAY_END) {
      if (payloadPending && c !== "]") {
        payloadStart = i;
        payloadActive = true;
        payloadPending = false;
      }
      if (state === WANT_VALUE_OR_ARRAY_END && c === "]") {
        i++;
        stack.pop();
        valueDone(i);
      } else if (c === "{") {
        i++;
        stack.push(new Set());
        scan.nodes += 1;
        if (stack.length > scan.maxDepth) scan.maxDepth = stack.length;
        state = WANT_KEY_OR_OBJECT_END;
      } else if (c === "[") {
        i++;
        stack.push({ items: 0 });
        scan.nodes += 1;
        if (stack.length > scan.maxDepth) scan.maxDepth = stack.length;
        state = WANT_VALUE_OR_ARRAY_END;
      } else if (c === '"') {
        readString();
        scan.nodes += 1;
        valueDone(i);
      } else if (c === "-" || isDigit(c)) {
        readNumber();
        scan.nodes += 1;
        valueDone(i);
      } else if (text.startsWith("true", i)) {
        i += 4;
        scan.nodes += 1;
        valueDone(i);
      } else if (text.startsWith("false", i)) {
        i += 5;
        scan.nodes += 1;
        valueDone(i);
      } else if (text.startsWith("null", i)) {
        i += 4;
        scan.nodes += 1;
        valueDone(i);
      } else if (text.startsWith("NaN", i) || text.startsWith("Infinity", i)) {
        reject("non-finite");
      } else reject("syntax");
    } else if (state === WANT_KEY_OR_OBJECT_END || state === WANT_KEY) {
      if (state === WANT_KEY_OR_OBJECT_END && c === "}") {
        i++;
        stack.pop();
        valueDone(i);
      } else if (c === '"') {
        const key = readString();
        const keys = /** @type {Set<string>} */ (stack[stack.length - 1]);
        if (keys.has(key)) reject("duplicate");
        keys.add(key);
        if (stack.length === 1 && key === "payload") payloadPending = true;
        state = WANT_COLON;
      } else reject("syntax");
    } else if (state === WANT_COLON) {
      if (c !== ":") reject("syntax");
      i++;
      state = WANT_VALUE;
    } else {
      // WANT_COMMA_OR_END
      const inObject = stack[stack.length - 1] instanceof Set;
      if (c === ",") {
        i++;
        state = inObject ? WANT_KEY : WANT_VALUE;
      } else if (c === (inObject ? "}" : "]")) {
        i++;
        stack.pop();
        valueDone(i);
      } else reject("syntax");
    }
  }
  skipWs();
  if (i < n) reject("trailing-data");
  return scan;
}

// ignoreBOM keeps a leading U+FEFF in the decoded text (instead of the
// decoder silently discarding it), so the scanner rejects BOM-prefixed
// bodies as a syntax error — RFC 8259 §8.1 forbids adding a BOM, and
// strict acceptance fails closed rather than "MAY ignore".
const STRICT_UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/**
 * Full acceptance of one envelope's exact bytes; returns without throwing
 * when accepted, else throws AcceptError with the first-failing class in
 * the pinned order (family PROFILE section 1, then the kovee §11.8
 * contextual caps): oversize, invalid-utf8, the order-3 token classes in
 * token order, unpaired-surrogate, over-depth, over-nodes, over-list-items
 * (request context only — pages may carry up to 512 events),
 * over-inline-content (a root-level `payload` member over 64 KiB).
 * @param {Buffer} raw
 * @param {"request" | "response"} capContext
 */
function acceptEnvelopeBytes(raw, capContext = "request") {
  const cap = capContext === "response" ? MAX_RESPONSE_BYTES : MAX_REQUEST_BYTES;
  if (raw.length > cap) throw new AcceptError("oversize");
  let text;
  try {
    text = STRICT_UTF8.decode(raw);
  } catch {
    throw new AcceptError("invalid-utf8");
  }
  const scan = scanStrictText(text);
  if (scan.surrogate) throw new AcceptError("unpaired-surrogate");
  if (scan.maxDepth > DEPTH_CAP) throw new AcceptError("over-depth");
  if (scan.nodes > NODE_CAP) throw new AcceptError("over-nodes");
  if (capContext === "request" && scan.maxListItems > LIST_CAP) throw new AcceptError("over-list-items");
  if (scan.payloadBytes !== null && scan.payloadBytes > INLINE_CONTENT_CAP) {
    throw new AcceptError("over-inline-content");
  }
}

/**
 * Strict I-JSON parse for spec files (schemas and vector files): the
 * family token rules and structural caps (no contextual request/response
 * caps), then JSON.parse materializes the value.
 * @param {string} text
 * @returns {unknown}
 */
function strictParse(text) {
  const scan = scanStrictText(text);
  if (scan.surrogate) throw new AcceptError("unpaired-surrogate");
  if (scan.maxDepth > DEPTH_CAP) throw new AcceptError("over-depth");
  if (scan.nodes > NODE_CAP) throw new AcceptError("over-nodes");
  return JSON.parse(text);
}

// ---------------------------------------------------------------------------
// Semantic RFC 3339 date-time (R0 KENV-05)
// ---------------------------------------------------------------------------

const RFC3339_RE =
  /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.[0-9]+)?(Z|[+-]([0-9]{2}):([0-9]{2}))$/;

const MONTH_DAYS = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

/**
 * Semantic RFC 3339 date-time: real calendar dates (month lengths, leap
 * years) and real time/offset ranges; second 60 admitted per the RFC 3339
 * leap-second grammar.
 * @param {string} value
 */
function isRfc3339DateTime(value) {
  const m = RFC3339_RE.exec(value);
  if (m === null) return false;
  const year = Number(m[1]);
  const month = Number(m[2]);
  const day = Number(m[3]);
  const hour = Number(m[4]);
  const minute = Number(m[5]);
  const second = Number(m[6]);
  if (month < 1 || month > 12) return false;
  let days = MONTH_DAYS[month - 1];
  if (month === 2 && year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0)) days = 29;
  if (day < 1 || day > days) return false;
  if (hour > 23 || minute > 59 || second > 60) return false;
  if (m[7] !== "Z" && (Number(m[8]) > 23 || Number(m[9]) > 59)) return false;
  return true;
}

// ---------------------------------------------------------------------------
// RFC 8785 JCS and the $domain type tag (family PROFILE section 2)
// ---------------------------------------------------------------------------

/** @type {Record<number, string>} */
const JCS_SHORT_ESCAPES = {
  0x08: "\\b",
  0x09: "\\t",
  0x0a: "\\n",
  0x0c: "\\f",
  0x0d: "\\r",
  0x22: '\\"',
  0x5c: "\\\\",
};

/**
 * JCS string form: short escapes plus \u00xx for the remaining C0
 * controls, everything else literal (UTF-8 once encoded).
 * @param {string} s
 */
function jcsString(s) {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const u = s.charCodeAt(i);
    const short = JCS_SHORT_ESCAPES[u];
    if (short !== undefined) out += short;
    else if (u < 0x20) out += "\\u" + u.toString(16).padStart(4, "0");
    else out += s[i];
  }
  return out + '"';
}

/**
 * RFC 8785 serialization over the I-JSON value space. RFC 8785 is defined
 * against ECMAScript, so two obligations are native here: `String(number)`
 * IS Number::toString(10) minimal form (10.0 -> "10", -0 -> "0",
 * 1e-7 -> "1e-7", 1e21 -> "1e+21"), and the default Array.prototype.sort()
 * compares UTF-16 code units — exactly the required member order (an
 * astral key sorts as its surrogate pair).
 * @param {unknown} v
 * @returns {string}
 */
function jcsSerialize(v) {
  if (v === null) return "null";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "string") return jcsString(v);
  if (typeof v === "number") {
    if (!Number.isFinite(v)) throw new Error("non-finite number in JCS input");
    if (Number.isInteger(v) && Math.abs(v) > SAFE_MAX) throw new Error("unsafe integer in JCS input");
    return String(v);
  }
  if (Array.isArray(v)) return "[" + v.map(jcsSerialize).join(",") + "]";
  if (typeof v === "object") {
    const o = /** @type {Record<string, unknown>} */ (v);
    return (
      "{" +
      Object.keys(o)
        .sort()
        .map((k) => jcsString(k) + ":" + jcsSerialize(o[k]))
        .join(",") +
      "}"
    );
  }
  throw new Error(`unsupported value of type ${typeof v} in JCS input`);
}

/**
 * @param {unknown} value
 * @returns {Buffer} canonical UTF-8 bytes
 */
function jcs(value) {
  return Buffer.from(jcsSerialize(value), "utf8");
}

/** @param {Buffer} data */
function sha256Hex(data) {
  return createHash("sha256").update(data).digest("hex");
}

// ---------------------------------------------------------------------------
// Kovee digest derivations (DESIGN.md §11.8, family PROFILE section 4)
// ---------------------------------------------------------------------------

const COD_DOMAIN = "dev.kovee.canonical-object-digest.v1";
const TBD_DOMAIN = "dev.kovee.typed-bytes-digest.v1";

/**
 * CanonicalObjectDigest input bytes: JCS of {protocol_major: 0,
 * object_kind, schema_ref, projection} with the reserved $domain member
 * injected at top level per the family PROFILE type-tag rule. An object
 * already carrying $domain fails closed.
 * @param {string} objectKind
 * @param {string} schemaRef
 * @param {unknown} projection
 * @returns {Buffer}
 */
function koveeCanonicalObject(objectKind, schemaRef, projection) {
  const base = {
    protocol_major: 0,
    object_kind: objectKind,
    schema_ref: schemaRef,
    projection,
  };
  if (Object.hasOwn(base, "$domain")) throw new Error("object already carries a $domain member");
  return jcs({ ...base, $domain: COD_DOMAIN });
}

/**
 * frame(x) = uint64_be(len(x)) || x
 * @param {Buffer} b
 */
function frame(b) {
  const len = Buffer.alloc(8);
  len.writeBigUInt64BE(BigInt(b.length));
  return Buffer.concat([len, b]);
}

/**
 * TypedByteDigest: SHA-256 over the uint64_be length-framed sequence
 * (domain-const, domain, protocol major "0", media_or_schema_ref, bytes).
 * @param {string} domain
 * @param {string} mediaOrSchemaRef
 * @param {Buffer} data
 * @returns {string}
 */
function koveeTypedBytesDigest(domain, mediaOrSchemaRef, data) {
  return sha256Hex(
    Buffer.concat([
      frame(Buffer.from(TBD_DOMAIN, "utf8")),
      frame(Buffer.from(domain, "utf8")),
      frame(Buffer.from("0", "utf8")),
      frame(Buffer.from(mediaOrSchemaRef, "utf8")),
      frame(data),
    ]),
  );
}

/**
 * One `input.derivations[]` entry; `kind` selects the construction
 * (family PROFILE section 5 table, kovee rows).
 * @param {Record<string, any>} d
 * @returns {Record<string, unknown>}
 */
function deriveDigest(d) {
  switch (d.kind) {
    case "dev.kovee.canonical-object-digest.v1": {
      const canonical = koveeCanonicalObject(d.object_kind, d.schema_ref, d.projection);
      return { canonical: canonical.toString("utf8"), sha256_hex: sha256Hex(canonical) };
    }
    case "kcp-command-idempotency": {
      // §11.2/§11.6: the projection is given directly or as the ordered
      // field list over the raw command; absent optional fields are
      // simply not projected. request_id, traceparent, and causation
      // telemetry are never in the field list.
      /** @type {Record<string, unknown>} */
      let projection;
      if (Object.hasOwn(d, "projection")) projection = d.projection;
      else {
        projection = {};
        for (const field of d.projection_fields) {
          if (Object.hasOwn(d.raw_command, field)) projection[field] = d.raw_command[field];
        }
      }
      const canonical = koveeCanonicalObject("kcp-command-idempotency", d.schema_ref, projection);
      return { canonical: canonical.toString("utf8"), sha256_hex: sha256Hex(canonical) };
    }
    case "dev.kovee.typed-bytes-digest.v1":
      return {
        digest_hex: koveeTypedBytesDigest(d.domain, d.media_or_schema_ref, Buffer.from(d.bytes_utf8, "utf8")),
      };
    default:
      throw new Error(`unknown derivation kind ${JSON.stringify(d.kind)}`);
  }
}

/**
 * @param {Record<string, any>} result
 * @returns {string}
 */
function primaryHex(result) {
  return result.sha256_hex ?? result.digest_hex;
}

// ---------------------------------------------------------------------------
// Minimal draft 2020-12 validator — just enough for the five KCP schemas
// ---------------------------------------------------------------------------
//
// Supported keywords (the exact set the schemas use, listed in the
// summary): boolean schemas, internal $ref (with sibling keywords, 2020-12
// semantics), type, const, enum, pattern, minLength, maxLength, minimum,
// maximum, required, properties, additionalProperties, propertyNames,
// items, minItems, maxItems, uniqueItems, allOf, oneOf, if/then/else.

/**
 * Resolve an internal JSON-pointer $ref against the schema root.
 * @param {any} root
 * @param {string} ref
 * @returns {any}
 */
function resolvePointer(root, ref) {
  if (!ref.startsWith("#")) throw new Error(`remote $ref: ${ref}`);
  let node = root;
  for (const raw of ref.slice(1).split("/")) {
    if (raw === "") continue;
    const part = raw.replaceAll("~1", "/").replaceAll("~0", "~");
    if (node === null || typeof node !== "object" || !(part in node)) {
      throw new Error(`unresolvable $ref: ${ref}`);
    }
    node = node[part];
  }
  return node;
}

/** @type {Map<string, RegExp>} */
const PATTERN_CACHE = new Map();

/**
 * JSON Schema `pattern` is an unanchored ECMA-262 regex search.
 * @param {string} pattern
 * @returns {RegExp}
 */
function compilePattern(pattern) {
  let re = PATTERN_CACHE.get(pattern);
  if (re === undefined) {
    try {
      re = new RegExp(pattern, "u");
    } catch {
      re = new RegExp(pattern);
    }
    PATTERN_CACHE.set(pattern, re);
  }
  return re;
}

/** @param {string} s length in Unicode code points (draft 2020-12 string lengths) */
function codePointLength(s) {
  let n = 0;
  for (const _ of s) n++;
  return n;
}

/**
 * @param {unknown} instance
 * @param {string} name
 */
function typeMatches(instance, name) {
  switch (name) {
    case "object":
      return isPlainObject(instance);
    case "array":
      return Array.isArray(instance);
    case "string":
      return typeof instance === "string";
    case "boolean":
      return typeof instance === "boolean";
    case "null":
      return instance === null;
    case "number":
      return typeof instance === "number";
    case "integer":
      return typeof instance === "number" && Number.isInteger(instance);
    default:
      return false;
  }
}

/**
 * @param {any} root the schema document $refs resolve against
 * @param {any} schema
 * @param {unknown} instance
 * @returns {boolean}
 */
function schemaValid(root, schema, instance) {
  if (schema === true) return true;
  if (schema === false) return false;

  if (typeof schema.$ref === "string") {
    if (!schemaValid(root, resolvePointer(root, schema.$ref), instance)) return false;
  }

  if (schema.type !== undefined) {
    const names = Array.isArray(schema.type) ? schema.type : [schema.type];
    if (!names.some((/** @type {string} */ n) => typeMatches(instance, n))) return false;
  }
  if (Object.hasOwn(schema, "const") && !jsonEqual(instance, schema.const)) return false;
  if (schema.enum !== undefined && !schema.enum.some((/** @type {unknown} */ e) => jsonEqual(instance, e))) {
    return false;
  }

  for (const sub of schema.allOf ?? []) {
    if (!schemaValid(root, sub, instance)) return false;
  }
  if (schema.oneOf !== undefined) {
    let matches = 0;
    for (const sub of schema.oneOf) if (schemaValid(root, sub, instance)) matches++;
    if (matches !== 1) return false;
  }
  if (schema.if !== undefined) {
    if (schemaValid(root, schema.if, instance)) {
      if (schema.then !== undefined && !schemaValid(root, schema.then, instance)) return false;
    } else if (schema.else !== undefined && !schemaValid(root, schema.else, instance)) return false;
  }

  if (typeof instance === "string") {
    if (schema.pattern !== undefined && !compilePattern(schema.pattern).test(instance)) return false;
    if (schema.minLength !== undefined || schema.maxLength !== undefined) {
      const len = codePointLength(instance);
      if (schema.minLength !== undefined && len < schema.minLength) return false;
      if (schema.maxLength !== undefined && len > schema.maxLength) return false;
    }
    if (schema.format === "date-time" && !isRfc3339DateTime(instance)) return false;
  }

  if (typeof instance === "number") {
    if (schema.minimum !== undefined && instance < schema.minimum) return false;
    if (schema.maximum !== undefined && instance > schema.maximum) return false;
  }

  if (isPlainObject(instance)) {
    const obj = /** @type {Record<string, unknown>} */ (instance);
    for (const key of schema.required ?? []) {
      if (!Object.hasOwn(obj, key)) return false;
    }
    const props = schema.properties ?? {};
    for (const [key, sub] of Object.entries(props)) {
      if (Object.hasOwn(obj, key) && !schemaValid(root, sub, obj[key])) return false;
    }
    if (schema.propertyNames !== undefined) {
      for (const key of Object.keys(obj)) {
        if (!schemaValid(root, schema.propertyNames, key)) return false;
      }
    }
    const addl = schema.additionalProperties;
    if (addl !== undefined && addl !== true) {
      for (const [key, value] of Object.entries(obj)) {
        if (Object.hasOwn(props, key)) continue;
        if (addl === false || !schemaValid(root, addl, value)) return false;
      }
    }
  }

  if (Array.isArray(instance)) {
    if (schema.minItems !== undefined && instance.length < schema.minItems) return false;
    if (schema.maxItems !== undefined && instance.length > schema.maxItems) return false;
    if (schema.uniqueItems === true) {
      const seen = new Set(instance.map((item) => jcsSerialize(item)));
      if (seen.size !== instance.length) return false;
    }
    if (schema.items !== undefined) {
      for (const item of instance) if (!schemaValid(root, schema.items, item)) return false;
    }
  }

  return true;
}

// ---------------------------------------------------------------------------
// Schema conventions (spec/schemas/README.md)
// ---------------------------------------------------------------------------

/**
 * Yield [node, exempt] over every object node; exempt marks if/then/else
 * subtrees, whose property lists refine an already-closed parent object
 * and deliberately do not repeat additionalProperties false.
 * @param {unknown} node
 * @param {boolean} exempt
 * @returns {Generator<[Record<string, any>, boolean]>}
 */
function* walkObjects(node, exempt = false) {
  if (Array.isArray(node)) {
    for (const item of node) yield* walkObjects(item, exempt);
  } else if (isPlainObject(node)) {
    const obj = /** @type {Record<string, any>} */ (node);
    yield [obj, exempt];
    for (const [key, value] of Object.entries(obj)) {
      yield* walkObjects(value, exempt || key === "if" || key === "then" || key === "else");
    }
  }
}

/**
 * @param {Record<string, any>} schema
 * @returns {string[]}
 */
function conventionErrors(schema) {
  const errs = [];
  if (schema.$schema !== DRAFT) errs.push(`$schema must be ${DRAFT}`);
  if (!schema.$id) errs.push("$id is required");
  for (const [node, exempt] of walkObjects(schema)) {
    if (typeof node.$ref === "string") {
      if (!node.$ref.startsWith("#")) errs.push(`remote $ref forbidden: ${node.$ref}`);
      else {
        try {
          resolvePointer(schema, node.$ref);
        } catch {
          errs.push(`unresolvable $ref: ${node.$ref}`);
        }
      }
    }
    if (!exempt && isPlainObject(node.properties) && node.additionalProperties !== false) {
      errs.push(
        `object schema with properties must set additionalProperties false (near ${Object.keys(node.properties).sort().slice(0, 3).join(", ")})`,
      );
    }
    if (typeof node.pattern === "string") {
      try {
        compilePattern(node.pattern);
      } catch (e) {
        errs.push(`invalid pattern ${JSON.stringify(node.pattern)}: ${/** @type {Error} */ (e).message}`);
      }
    }
  }
  return errs;
}

// ---------------------------------------------------------------------------
// Envelope family checkers
// ---------------------------------------------------------------------------

const COUNT_KINDS = /** @type {const} */ (["schema-valid", "schema-invalid", "acceptance", "digest"]);
/** @type {Record<string, number>} */
const COUNTS = Object.fromEntries(COUNT_KINDS.map((k) => [k, 0]));

/** @type {Map<string, Record<string, any>>} */
const SCHEMAS = new Map();

/**
 * @param {string} name
 * @param {Record<string, any>} inp
 * @param {Record<string, any>} expected
 */
function checkSchemaVector(name, inp, expected) {
  const schema = SCHEMAS.get(inp.schema);
  if (schema === undefined) {
    fail(name, `references unknown schema ${JSON.stringify(inp.schema)}`);
    return;
  }
  let verdict;
  try {
    const target = inp.ref === undefined ? schema : resolvePointer(schema, inp.ref);
    verdict = schemaValid(schema, target, inp.value);
  } catch (e) {
    fail(name, `validation failed: ${/** @type {Error} */ (e).message}`);
    return;
  }
  if (verdict !== expected.valid) {
    fail(name, `expected valid=${expected.valid}, got ${verdict}`);
    return;
  }
  COUNTS[verdict ? "schema-valid" : "schema-invalid"] += 1;
}

/**
 * @param {string} name
 * @param {Record<string, any>} inp
 * @param {Record<string, any>} expected
 */
function checkAcceptanceVector(name, inp, expected) {
  const capContext = inp.cap ?? "request";
  if (capContext !== "request" && capContext !== "response") {
    fail(name, `unknown cap context ${JSON.stringify(capContext)}`);
    return;
  }
  /** @type {Buffer} */
  let raw;
  if (Object.hasOwn(inp, "raw")) {
    raw = Buffer.from(inp.raw, "utf8");
  } else if (inp.synthetic === "oversized_request") {
    const prefix = '{"version":"0.1","op":"diagnose","realm_id":"realm-0001","args":{"pad":"';
    const suffix = '"}}';
    const pad = inp.target_bytes - prefix.length - suffix.length;
    if (pad < 0) {
      fail(name, "target_bytes too small to synthesize");
      return;
    }
    raw = Buffer.from(prefix + "a".repeat(pad) + suffix, "utf8");
    if (raw.length !== inp.target_bytes) {
      fail(name, `synthesized ${raw.length} bytes, wanted ${inp.target_bytes}`);
      return;
    }
  } else if (inp.synthetic === "json_synth") {
    // Family PROFILE section 8 synthesized repetition for cap cases.
    raw = Buffer.from((inp.prefix ?? "") + (inp.repeat ?? "").repeat(inp.count ?? 0) + (inp.suffix ?? ""), "utf8");
  } else {
    fail(name, `unknown synthetic kind ${JSON.stringify(inp.synthetic)}`);
    return;
  }
  /** @type {string | null} */
  let cls = null;
  try {
    acceptEnvelopeBytes(raw, capContext);
  } catch (e) {
    if (!(e instanceof AcceptError)) throw e;
    cls = e.cls;
  }
  const verdict = cls === null;
  if (verdict !== expected.valid) {
    fail(name, `expected valid=${expected.valid}, got ${verdict} (class ${JSON.stringify(cls)})`);
    return;
  }
  if (Object.hasOwn(expected, "error_class") && cls !== expected.error_class) {
    fail(name, `expected error class ${JSON.stringify(expected.error_class)}, got ${JSON.stringify(cls)}`);
    return;
  }
  COUNTS.acceptance += 1;
}

/**
 * @param {string} name
 * @param {Record<string, any>} inp
 * @param {Record<string, any>} expected
 */
function checkDigestVector(name, inp, expected) {
  /** @type {Record<string, unknown>[]} */
  let results;
  try {
    results = inp.derivations.map(deriveDigest);
  } catch (e) {
    fail(name, `derivation failed: ${/** @type {Error} */ (e).message}`);
    return;
  }
  let ok = true;
  if (!jsonEqual(results, expected.results)) {
    fail(
      name,
      "derived results differ\n" +
        `      derived:  ${JSON.stringify(results)}\n` +
        `      expected: ${JSON.stringify(expected.results)}`,
    );
    ok = false;
  }
  const relation = expected.relation;
  if (relation !== undefined) {
    const hexes = results.map(primaryHex);
    const unique = new Set(hexes).size;
    if (relation === "equal") {
      if (unique !== 1) {
        fail(name, `expected equal digests, got ${JSON.stringify(hexes)}`);
        ok = false;
      }
    } else if (relation === "distinct") {
      if (unique !== hexes.length) {
        fail(name, `expected pairwise-distinct digests, got ${JSON.stringify(hexes)}`);
        ok = false;
      }
    } else {
      fail(name, `unknown relation ${JSON.stringify(relation)}`);
      ok = false;
    }
  }
  if (ok) COUNTS.digest += 1;
}

/**
 * @param {string} name
 * @param {{ input: Record<string, any>, expected: Record<string, any> }} kase
 */
function checkEnvelope(name, kase) {
  const inp = kase.input;
  if (Object.hasOwn(inp, "schema")) checkSchemaVector(name, inp, kase.expected);
  else if (Object.hasOwn(inp, "raw") || Object.hasOwn(inp, "synthetic")) {
    checkAcceptanceVector(name, inp, kase.expected);
  } else if (Object.hasOwn(inp, "derivations")) checkDigestVector(name, inp, kase.expected);
  else fail(name, `unknown vector kind (input keys ${JSON.stringify(Object.keys(inp).sort())})`);
}

/**
 * The `ops` family holds pure schema vectors against the per-operation
 * request/result schemas under spec/schemas/ops/.
 * @param {string} name
 * @param {{ input: Record<string, any>, expected: Record<string, any> }} kase
 */
function checkOps(name, kase) {
  if (!Object.hasOwn(kase.input, "schema")) {
    fail(name, "ops vectors are schema vectors and require input.schema");
    return;
  }
  checkSchemaVector(name, kase.input, kase.expected);
}

/** @type {Record<string, (name: string, kase: any) => void>} */
const CHECKERS = { envelope: checkEnvelope, ops: checkOps };

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

/**
 * All *.schema.json files under root, recursively, in sorted path order.
 * @param {string} dir
 * @returns {string[]}
 */
function schemaFilesUnder(dir) {
  /** @type {string[]} */
  const out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true }).sort((a, b) =>
    a.name < b.name ? -1 : a.name > b.name ? 1 : 0,
  )) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...schemaFilesUnder(path));
    else if (entry.isFile() && entry.name.endsWith(".schema.json")) out.push(path);
  }
  return out;
}

/**
 * @param {string} schemasDir
 * @returns {number} number of schema files seen
 */
function loadSchemas(schemasDir) {
  const files = schemaFilesUnder(schemasDir);
  if (files.length === 0) {
    fail(schemasDir, "no schemas found");
    return 0;
  }
  for (const path of files) {
    const fname = basename(path);
    const name = fname.slice(0, -".schema.json".length);
    if (SCHEMAS.has(name)) {
      fail(fname, "duplicate schema basename (schema names are referenced by basename across the whole tree)");
      continue;
    }
    let schema;
    try {
      schema = strictParse(readFileSync(path, "utf8"));
    } catch (e) {
      fail(fname, `not strict I-JSON: ${/** @type {Error} */ (e).message}`);
      continue;
    }
    if (!isPlainObject(schema)) {
      fail(fname, "schema root must be a JSON object");
      continue;
    }
    for (const err of conventionErrors(/** @type {Record<string, any>} */ (schema))) fail(fname, err);
    SCHEMAS.set(name, /** @type {Record<string, any>} */ (schema));
  }
  return files.length;
}

/**
 * Bundle coverage: the K0-frozen registry, not prose, decides schema
 * membership (byom conformance/run.py bundle rule). Every covered registry
 * entry's operation must have a closed `<op>-request` / `<op>-result`
 * schema pair under spec/schemas/ops/; the request pins the exact op
 * const; reads carry no meta member at all; mutations require meta (§11.2,
 * R0 KENV-01). Dual-surface operations share one pair keyed by operation
 * (registry key is (operation, surface); schema names key by operation —
 * ops README gap note KG14).
 * @param {string} registryPath
 * @returns {{ covered: number, total: number, entriesCovered: number, entriesTotal: number }}
 */
function checkBundleCoverage(registryPath) {
  /** @type {any} */
  let registry;
  try {
    registry = strictParse(readFileSync(registryPath, "utf8"));
  } catch (e) {
    fail(registryPath, `cannot load registry: ${/** @type {Error} */ (e).message}`);
    return { covered: 0, total: 0, entriesCovered: 0, entriesTotal: 0 };
  }
  const entries = (registry.entries ?? []).filter((/** @type {any} */ e) =>
    COVERED_BUNDLES.includes(e.bundle),
  );
  const ops = [...new Set(entries.map((/** @type {any} */ e) => e.operation))].sort();
  if (ops.length === 0) {
    fail(registryPath, `no registry entries for bundles ${COVERED_BUNDLES.join(", ")}`);
    return { covered: 0, total: 0, entriesCovered: 0, entriesTotal: 0 };
  }
  for (const op of [...COVERED_READS].filter((r) => !ops.includes(r)).sort()) {
    fail("bundle", `read list names ${op}, which is not a covered registry operation`);
  }
  let covered = 0;
  /** @type {Set<string>} */
  const passedOps = new Set();
  for (const op of ops) {
    const base = op.replaceAll("_", "-");
    const request = SCHEMAS.get(`${base}-request`);
    const result = SCHEMAS.get(`${base}-result`);
    let ok = true;
    if (request === undefined) {
      fail("bundle", `op ${op} has no ${base}-request schema`);
      ok = false;
    }
    if (result === undefined) {
      fail("bundle", `op ${op} has no ${base}-result schema`);
      ok = false;
    }
    if (request !== undefined) {
      const opConst = request.properties?.op?.const;
      if (opConst !== op) {
        fail("bundle", `${base}-request op const is ${JSON.stringify(opConst)}, expected ${JSON.stringify(op)}`);
        ok = false;
      }
      const hasMeta = Object.hasOwn(request.properties ?? {}, "meta");
      if (COVERED_READS.has(op)) {
        if (hasMeta) {
          fail("bundle", `read ${op} declares meta (reads never carry an idempotency key, §11.2 / R0 KENV-01)`);
          ok = false;
        }
      } else if (!hasMeta || !(request.required ?? []).includes("meta")) {
        fail("bundle", `mutation ${op} does not require meta (§11.2: every state-changing operation requires meta)`);
        ok = false;
      }
    }
    if (ok) {
      covered += 1;
      passedOps.add(op);
    }
  }
  // Dual-surface operations share one schema pair keyed by operation, so
  // coverage is also accounted per registry entry: with the per-operation
  // suite complete every (operation, surface) entry must be schema-covered.
  const entriesCovered = entries.filter((/** @type {any} */ e) => passedOps.has(e.operation)).length;
  if (entriesCovered !== entries.length) {
    fail(
      "bundle",
      `only ${entriesCovered}/${entries.length} registry entries schema-covered ` +
        "(every entry of every covered bundle must be)",
    );
  }
  return { covered, total: ops.length, entriesCovered, entriesTotal: entries.length };
}

/**
 * All *.json files under root, recursively, in sorted path order.
 * @param {string} dir
 * @returns {string[]}
 */
function jsonFilesUnder(dir) {
  /** @type {string[]} */
  const out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true }).sort((a, b) =>
    a.name < b.name ? -1 : a.name > b.name ? 1 : 0,
  )) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...jsonFilesUnder(path));
    else if (entry.isFile() && entry.name.endsWith(".json")) out.push(path);
  }
  return out;
}

/**
 * Validate the vector-file envelope; return the parsed case or null.
 * @param {string} path
 * @param {string} vectorsRoot
 * @returns {{ name?: string, input: Record<string, any>, expected: Record<string, any> } | null}
 */
function checkShape(path, vectorsRoot) {
  let case_;
  try {
    case_ = strictParse(readFileSync(path, "utf8"));
  } catch (e) {
    fail(path, `not strict I-JSON: ${/** @type {Error} */ (e).message}`);
    return null;
  }
  if (!isPlainObject(case_)) {
    fail(path, "vector root must be a JSON object");
    return null;
  }
  const kase = /** @type {Record<string, any>} */ (case_);
  const family = relative(vectorsRoot, path).split(sep)[0];
  const expectedName = `${family}/${basename(path, ".json")}`;
  if (kase.name !== expectedName) {
    fail(path, `vector name ${JSON.stringify(kase.name)} != ${JSON.stringify(expectedName)}`);
  }
  if (typeof kase.description !== "string") fail(path, "missing or non-string 'description'");
  for (const key of ["input", "expected"]) {
    if (!isPlainObject(kase[key])) {
      fail(path, `missing or non-object ${JSON.stringify(key)}`);
      return null;
    }
  }
  return /** @type {any} */ (kase);
}

function main() {
  const here = dirname(fileURLToPath(import.meta.url));
  const vectorsRoot = process.argv[2] !== undefined ? resolve(process.argv[2]) : join(dirname(here), "spec", "vectors");
  const nSchemas = loadSchemas(join(dirname(vectorsRoot), "schemas"));
  const coverage = checkBundleCoverage(join(dirname(vectorsRoot), "registry.json"));

  let count = 0;
  for (const path of jsonFilesUnder(vectorsRoot)) {
    if (dirname(path) === vectorsRoot) {
      fail(path, "vectors live under a family directory, not the root");
      continue;
    }
    const kase = checkShape(path, vectorsRoot);
    if (kase === null) continue;
    const family = relative(vectorsRoot, path).split(sep)[0];
    const checker = CHECKERS[family];
    if (checker === undefined) {
      fail(path, `no checker registered for family ${JSON.stringify(family)}`);
      continue;
    }
    try {
      checker(kase.name ?? path, kase);
    } catch (e) {
      // a malformed vector is a failure, not a crash
      const err = /** @type {Error} */ (e);
      fail(kase.name ?? path, `checker raised ${err.constructor.name}: ${err.message}`);
    }
    count += 1;
  }

  console.log(`tscheck: schemas ${SCHEMAS.size}/${nSchemas} loaded (minimal draft 2020-12 validator)`);
  console.log(
    `tscheck: bundle coverage ${coverage.covered}/${coverage.total} ops, ` +
      `${coverage.entriesCovered}/${coverage.entriesTotal} registry entries ` +
      `(${COVERED_BUNDLES.join(", ")}) — request+result pair, op const, read/mutation meta rule`,
  );
  if (FAILURES.length > 0) {
    console.log(`tscheck: ${FAILURES.length} failure(s) across ${count} vector(s)`);
    for (const f of FAILURES) console.log(`  FAIL ${f}`);
    return 1;
  }
  if (count === 0) {
    // Fail closed on an empty tree (akson behavior).
    console.log(`tscheck: no vectors under ${vectorsRoot} — FAIL`);
    return 1;
  }
  console.log(
    `tscheck: ${count} vectors OK — ` +
      COUNT_KINDS.map((k) => `${COUNTS[k]} ${k}`).join(", "),
  );
  return 0;
}

process.exit(main());
