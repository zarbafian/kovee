#!/usr/bin/env node
// @ts-check
/**
 * Independent TypeScript-family rederiver for the golden vectors under
 * spec/vectors/ (K0). JSDoc-typed plain ES modules; zero runtime
 * dependencies; Node >= 20.
 *
 * Checks, in order:
 *
 * 1. every file in spec/schemas/ parses as strict I-JSON, follows the spec
 *    conventions (draft 2020-12, $id present, closed objects, no remote
 *    $ref, resolvable internal $refs, compilable patterns);
 * 2. every vector under spec/vectors/ (one `family/name.json` per case, an
 *    object whose `name` matches its path and which carries `description`,
 *    `input`, and `expected`) passes its family checker: schema vectors
 *    match their expected verdict against this file's minimal draft
 *    2020-12 validator, raw/synthetic vectors match strict I-JSON + §11.8
 *    limit acceptance, digest vectors re-derive the family-PROFILE
 *    canonical bytes (RFC 8785 JCS with the reserved $domain member
 *    injected at top level) and their SHA-256, plus the §11.8 framed
 *    typed-bytes digests.
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
const MAX_REQUEST_BYTES = 262144; // DESIGN.md §11.8: request body at most 256 KiB
const SAFE_MAX = 9007199254740991; // 2^53 - 1 (I-JSON safe range)
const SAFE_MAX_BIG = 9007199254740991n;

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

/** A strict-acceptance rejection carrying its reason. */
class AcceptError extends Error {}

/**
 * Validating scanner for exactly one strict I-JSON text. Iterative (an
 * explicit container stack, no recursion), so nesting bounded only by the
 * byte cap can never overflow the call stack. Values are never
 * materialized; the scanner enforces, in token order: well-formed single
 * JSON text, no duplicate member names at any depth (compared after escape
 * decoding, RFC 7493), integers within ±(2^53 − 1) checked exactly on the
 * token via BigInt, finite floats, no NaN/Infinity literals, no unpaired
 * surrogates after escape decoding.
 * @param {string} text
 */
function scanStrictText(text) {
  let i = 0;
  const n = text.length;
  /** @type {(Set<string> | null)[]} member-name sets of open containers; null for arrays */
  const stack = [];

  /** @param {string} reason @returns {never} */
  const reject = (reason) => {
    throw new AcceptError(reason);
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
      if (i >= n) reject("syntax error: unterminated string");
      const u = text.charCodeAt(i);
      if (u === 0x22) {
        i++;
        break;
      }
      if (u < 0x20) reject("syntax error: raw control character in string");
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
          if (!/^[0-9A-Fa-f]{4}$/.test(hex)) reject("syntax error: bad \\u escape");
          s += String.fromCharCode(parseInt(hex, 16));
          i += 4;
        } else reject("syntax error: bad escape");
      } else {
        s += text[i];
        i++;
      }
    }
    // I-JSON: no unpaired surrogates once escapes are decoded (raw text
    // from a strict UTF-8 decode cannot carry them; \uXXXX can).
    for (let k = 0; k < s.length; k++) {
      const u = s.charCodeAt(k);
      if (u >= 0xd800 && u <= 0xdbff) {
        const next = k + 1 < s.length ? s.charCodeAt(k + 1) : 0;
        if (next >= 0xdc00 && next <= 0xdfff) k++;
        else reject("unpaired surrogate");
      } else if (u >= 0xdc00 && u <= 0xdfff) reject("unpaired surrogate");
    }
    return s;
  };

  /** Consume the number token starting at `i` and classify it. */
  const readNumber = () => {
    const start = i;
    if (text[i] === "-") {
      i++;
      if (text.startsWith("Infinity", i)) reject("non-finite number");
    }
    if (text[i] === "0") i++;
    else if (isDigit(text[i])) while (isDigit(text[i])) i++;
    else reject("syntax error: bad number");
    let integral = true;
    if (text[i] === ".") {
      integral = false;
      i++;
      if (!isDigit(text[i])) reject("syntax error: bad number");
      while (isDigit(text[i])) i++;
    }
    if (text[i] === "e" || text[i] === "E") {
      integral = false;
      i++;
      if (text[i] === "+" || text[i] === "-") i++;
      if (!isDigit(text[i])) reject("syntax error: bad number");
      while (isDigit(text[i])) i++;
    }
    const token = text.slice(start, i);
    if (integral) {
      const v = BigInt(token); // exact, immune to double rounding
      if (v > SAFE_MAX_BIG || v < -SAFE_MAX_BIG) reject(`unsafe integer: ${token}`);
    } else if (!Number.isFinite(Number(token))) {
      reject("non-finite number");
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

  const valueDone = () => {
    if (stack.length === 0) complete = true;
    else state = WANT_COMMA_OR_END;
  };

  while (!complete) {
    skipWs();
    if (i >= n) reject("syntax error: unexpected end of input");
    const c = text[i];
    if (state === WANT_VALUE || state === WANT_VALUE_OR_ARRAY_END) {
      if (state === WANT_VALUE_OR_ARRAY_END && c === "]") {
        i++;
        stack.pop();
        valueDone();
      } else if (c === "{") {
        i++;
        stack.push(new Set());
        state = WANT_KEY_OR_OBJECT_END;
      } else if (c === "[") {
        i++;
        stack.push(null);
        state = WANT_VALUE_OR_ARRAY_END;
      } else if (c === '"') {
        readString();
        valueDone();
      } else if (c === "-" || isDigit(c)) {
        readNumber();
        valueDone();
      } else if (text.startsWith("true", i)) {
        i += 4;
        valueDone();
      } else if (text.startsWith("false", i)) {
        i += 5;
        valueDone();
      } else if (text.startsWith("null", i)) {
        i += 4;
        valueDone();
      } else if (text.startsWith("NaN", i) || text.startsWith("Infinity", i)) {
        reject("non-finite number");
      } else reject("syntax error: bad value");
    } else if (state === WANT_KEY_OR_OBJECT_END || state === WANT_KEY) {
      if (state === WANT_KEY_OR_OBJECT_END && c === "}") {
        i++;
        stack.pop();
        valueDone();
      } else if (c === '"') {
        const key = readString();
        const keys = /** @type {Set<string>} */ (stack[stack.length - 1]);
        if (keys.has(key)) reject(`duplicate object key: ${JSON.stringify(key)}`);
        keys.add(key);
        state = WANT_COLON;
      } else reject("syntax error: expected object key");
    } else if (state === WANT_COLON) {
      if (c !== ":") reject("syntax error: expected ':'");
      i++;
      state = WANT_VALUE;
    } else {
      // WANT_COMMA_OR_END
      const inObject = stack[stack.length - 1] !== null;
      if (c === ",") {
        i++;
        state = inObject ? WANT_KEY : WANT_VALUE;
      } else if (c === (inObject ? "}" : "]")) {
        i++;
        stack.pop();
        valueDone();
      } else reject("syntax error: expected ',' or close");
    }
  }
  skipWs();
  if (i < n) reject("trailing data after the JSON text");
}

const STRICT_UTF8 = new TextDecoder("utf-8", { fatal: true });

/**
 * Pre-schema acceptance of one request envelope's exact bytes (§11.8):
 * size cap first, then a strict UTF-8 decode, then the strict scan.
 * @param {Buffer} raw
 */
function acceptRequestBytes(raw) {
  if (raw.length > MAX_REQUEST_BYTES) throw new AcceptError(`request over 256 KiB: ${raw.length} bytes`);
  let text;
  try {
    text = STRICT_UTF8.decode(raw);
  } catch {
    throw new AcceptError("invalid UTF-8");
  }
  scanStrictText(text);
}

/**
 * Strict I-JSON parse for spec files (schemas and vector files): the
 * scanner enforces I-JSON, then JSON.parse materializes the value.
 * @param {string} text
 * @returns {unknown}
 */
function strictParse(text) {
  scanStrictText(text);
  return JSON.parse(text);
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
  /** @type {Buffer} */
  let raw;
  if (Object.hasOwn(inp, "raw")) {
    raw = Buffer.from(inp.raw, "utf8");
  } else {
    if (inp.synthetic !== "oversized_request") {
      fail(name, `unknown synthetic kind ${JSON.stringify(inp.synthetic)}`);
      return;
    }
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
  }
  let verdict = true;
  try {
    acceptRequestBytes(raw);
  } catch (e) {
    if (!(e instanceof AcceptError)) throw e;
    verdict = false;
  }
  if (verdict !== expected.valid) {
    fail(name, `expected valid=${expected.valid}, got ${verdict}`);
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

/** @type {Record<string, (name: string, kase: any) => void>} */
const CHECKERS = { envelope: checkEnvelope };

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

/**
 * @param {string} schemasDir
 * @returns {number} number of schema files seen
 */
function loadSchemas(schemasDir) {
  const files = readdirSync(schemasDir)
    .filter((f) => f.endsWith(".schema.json"))
    .sort();
  if (files.length === 0) {
    fail(schemasDir, "no schemas found");
    return 0;
  }
  for (const fname of files) {
    const name = fname.slice(0, -".schema.json".length);
    let schema;
    try {
      schema = strictParse(readFileSync(join(schemasDir, fname), "utf8"));
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
