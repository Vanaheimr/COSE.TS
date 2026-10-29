# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Until 1.0.0 the public API may change in minor releases.

## [Unreleased]

### Changed

- **The licence file is `LICENSE` again, without an extension.** The Apache
  2.0 text is plain text, not Markdown, and rendered as Markdown its indented
  paragraphs turn into code blocks. `LICENSE` is also what the Apache
  Software Foundation and MetrologicalCBOR.TS use. The text is unchanged, and
  npm includes a `LICENSE` file in a package whatever `files` says.

## [0.10.0] — 2026-10-25

A minor without a single changed line of library code, and deliberately so.
The CBOR codec underneath moves from `^0.10.0` to `^0.11.1`, and under 0.x
npm treats that as a major step: a range of `^0.10.0` will never admit 0.11.
The codec is part of this package's public surface — `cbor` and `CborValue`
are re-exported from it, and the `CborError` it throws on malformed input
passes through `parse` unchanged — so a patch release would have reached
every `^0.9.0` installer automatically and could have left one who also
depends on the codec directly holding two copies of it. Errors thrown by one
copy are not `instanceof` the other's `CborError`, and that is exactly the
check a careful caller writes around `parse`. A minor makes that step a
choice rather than a surprise. There was nothing for a patch to deliver
instead: no defect in the library was fixed.

### Changed

- **The codec is `@vanaheimr/metrological-cbor` 0.11.1.** Its CBOR layer is
  unchanged between 0.10.0 and 0.11.1, so every message, key and structure
  this library writes is byte for byte what 0.9.0 wrote, and every signature
  0.9.0 made still verifies. The codec's own breaking change in 0.11.0 — JSON
  conversion no longer guesses which strings are readings — concerns an API
  this package does not re-export. **If you depend on the codec directly as
  well, move that dependency to `^0.11.1` alongside this upgrade**, so that
  npm installs one copy and `CborError` stays one class.
- **The cryptography floor rises**: `@noble/hashes`, `@noble/ciphers` and
  `@noble/curves` to 2.4.0, `@noble/post-quantum` to 0.7.1. Fresh installs
  of 0.9.0 already resolved these through their caret ranges; the new floor
  says what this release was tested against.

### Development

None of this reaches an installer: the published package has the same
files, the same build shape and no new runtime dependency.

- **The browser-bundle test runs in one realm.** It used to hand its `vm`
  sandbox the host's `Object`, `Uint8Array` and two dozen other intrinsics,
  which shadowed the sandbox's own with foreign twins; `@noble/hashes` 2.4
  checks its option defaults for being plain objects and refused to load
  there. A browser has one realm, and the sandbox now does too — which also
  makes the test a truer stand-in for a browser than it was.
- **Two advisories in the development toolchain are closed**: `source-map-js`
  to 1.2.2 (GHSA-68fv-2mgg-jv7q, reached through tsup and the coverage
  provider) and `markdown-it` to 14.3.3 (GHSA-vfgh-jcmw-g37q and
  GHSA-gfr2-rv44-r23c, reached through typedoc).
- **The toolchain moves to current majors**: tsup 9, vitest and its coverage
  provider 5.0.5, with eslint, typescript-eslint, globals and tsx in minors.
  TypeScript stays at 6.0 until typedoc supports 7.
- **The workflows run on actions that run on Node 24** — checkout, setup-node
  and upload-artifact at v7 — instead of being force-migrated with an
  annotation on every run.
- `update.sh` scripts the dependency sweep, and `*.tgz` is ignored, since the
  release rehearsal in `docs/releasing.md` leaves one behind every time.

## [0.9.0] — 2026-08-22

**The first version published to npm**, on 2026-08-22 — by hand, with
multi-factor authentication and a maintainer at the keyboard, as every release
of this package will be; see
[docs/releasing.md](https://github.com/Vanaheimr/COSE.TS/blob/master/docs/releasing.md)
for why that is not a workflow's to do.

### Added

- **`COSE_Sign1` and `COSE_Sign`** (RFC 9052), with detached payloads,
  external additional authenticated data, and the `crit` header parameter
  throughout.
- **CBOR payloads are signed and authenticated in their deterministic
  spelling** (RFC 8949 §4.2.1): a payload that is one well-formed CBOR item is
  rewritten into that encoding before `CoseSign1`, `CoseSign`, `CoseMac0` or
  `CoseMac` covers it, unless `canonicalizePayload: false` asks for the bytes
  as given. A MAC dies the same death as a signature when a hop re-encodes. Forwarding is the reason — every hop that parses and
  re-encodes a record writes the deterministic form, and a signature over any
  other spelling arrives unaltered in meaning and broken in fact. A payload
  that is not CBOR passes through untouched, since text, JSON or an image has
  no canonical CBOR form to be rewritten into.
- **`COSE_Mac0` and `COSE_Mac`** with HMAC, including the truncated
  `HMAC 256/64`.
- **`COSE_Encrypt0` and `COSE_Encrypt`** with AES-GCM, and recipient
  structures carrying the content key by `direct` or AES key wrap (RFC 3394).
- **The version 2 countersignatures** of RFC 9338.
- **COSE keys** of key type EC2, OKP, AKP and Symmetric, with the key
  thumbprints of RFC 9679.
- **Three signature families, kept apart by the API**: the ECDSA algorithms of
  RFC 9053 and RFC 9864 — including all four brainpool curves, with
  brainpoolP320r1 defined from its RFC 5639 domain parameters — EdDSA of
  RFC 8032, and ML-DSA of RFC 9964.
- **X.509 chains** (RFC 9360): DER read by its own reader, chains walked to a
  trust anchor and bound to the key that signed — so a certificate on a
  brainpool curve or an ML-DSA key verifies through the same path as every
  other signature here.
- **Runs under Node and in browsers alike**: the cryptography is the `@noble`
  family end to end, nothing touches `node:crypto` or WebCrypto, and
  `tests/bundle.test.ts` proves it by running the bundled library in a V8
  context with no Node globals at all.
- **Published as ESM** with one bundled `dist/index.js` and per-module
  declaration files. Deliberately no `.cjs` twin: every runtime dependency
  ships as ESM only, so a CommonJS build would promise a compatibility its
  own imports cannot honour. Node that can `require(esm)` — 20.19 and later —
  loads the ESM build fine.
- **A fuzz suite** (`tests/fuzz`): every parser against damaged messages,
  damaged certificates and arbitrary bytes — a value or a typed refusal,
  never a third thing; whatever is accepted re-encodes to a fixed point; a
  `COSE_Sign1` signature with any single byte damaged never verifies. Two
  thousand cases per property on every test run, two hundred thousand in the
  nightly.
- **The toolchain the codec has**: ESLint with the typed rule sets, coverage,
  an API reference that validates as it renders, and a nightly dependency
  audit — with `npm run verify` running the lot.

### Fixed

- **Two untyped escapes in the DER string reader**, both found by the fuzz
  suite's first run: a certificate name holding invalid UTF-8 escaped as the
  platform's own `TypeError`, and a UniversalString character beyond U+10FFFF
  would have escaped as a `RangeError`. Both are `CoseError` refusals now,
  and the wide-string decoder builds its result a character at a time, so a
  large enough hostile string is no longer a stack overflow.

### Verified against

- RFC 9052 C.1.1, C.1.2 and C.2.1, RFC 9338 A.2.1, RFC 6979 A.2.5 and
  RFC 4231 — published vectors, byte for byte.
- The worked signed record of the Metrological CBOR specification, produced
  by the C# reference implementation and never seen being made.
- Certificates minted by Bouncy Castle rather than by this package's own
  writer, so the DER reader cannot agree with itself about a misreading.
