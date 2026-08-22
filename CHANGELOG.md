# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Until 1.0.0 the public API may change in minor releases.

## [Unreleased]

The first version to be published to npm — by hand, with a maintainer at the
keyboard, as every release of this package will be.

### Added

- **`COSE_Sign1` and `COSE_Sign`** (RFC 9052), with detached payloads,
  external additional authenticated data, and the `crit` header parameter
  throughout.
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

### Verified against

- RFC 9052 C.1.1, C.1.2 and C.2.1, RFC 9338 A.2.1, RFC 6979 A.2.5 and
  RFC 4231 — published vectors, byte for byte.
- The worked signed record of the Metrological CBOR specification, produced
  by the C# reference implementation and never seen being made.
- Certificates minted by Bouncy Castle rather than by this package's own
  writer, so the DER reader cannot agree with itself about a misreading.
