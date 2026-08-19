# Vanaheimr COSE (TypeScript)

[![CI](https://github.com/Vanaheimr/COSE.TS/actions/workflows/ci.yml/badge.svg)](https://github.com/Vanaheimr/COSE.TS/actions/workflows/ci.yml)
[![Nightly](https://github.com/Vanaheimr/COSE.TS/actions/workflows/nightly.yml/badge.svg)](https://github.com/Vanaheimr/COSE.TS/actions/workflows/nightly.yml)
[![Cross-signing](https://img.shields.io/github/actions/workflow/status/Vanaheimr/MCBORConformanceTests/ci.yml?branch=master&label=cross-signing%20vs.%20Styx)](https://github.com/Vanaheimr/MCBORConformanceTests/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE.md)

**CBOR Object Signing and Encryption** ([RFC 9052](https://www.rfc-editor.org/rfc/rfc9052))
in TypeScript, built on the CBOR codec of
[MetrologicalCBOR.TS](https://github.com/Vanaheimr/MetrologicalCBOR.TS) — the
counterpart of [Vanaheimr Styx](https://github.com/Vanaheimr/Styx)'s
[`Illias/COSE`](https://github.com/Vanaheimr/Styx/blob/master/Styx/Illias/COSE/README.md),
and the second implementation the
[COSE cross-signing conformance suite](https://github.com/Vanaheimr/MCBORConformanceTests)
needs in order to have anything to compare.

Signing is what turns the [metrological value extension](https://github.com/OpenChargingTechnology/Whitepapers/blob/master/MetrologicalCBOR/README.md)
into something a third party can check: the encoding of a reading is a pure
function of its value, scale, unit, prefix and uncertainty, so the same reading
always produces the same bytes — and therefore the same signature. Two codecs
that disagree about one byte of one reading produce signatures that fail at the
other, which is a conformance failure worth catching before a meter ships.

## Why it is a repository of its own

`@vanaheimr/metrological-cbor` has zero runtime dependencies and a documented
rule that it will never do cryptography: a data format that also carried a
crypto stack would be unusable as the leaf of somebody else's schema. That rule
stays intact by keeping the two apart — exactly as Styx keeps `Illias/COSE`
beside `Illias/CBOR` rather than inside it. Whoever wants the format gets no
crypto; whoever wants signatures adds this and gets `@noble/curves` with it.

## Getting the CBOR codec

[`src/cbor.ts`](src/cbor.ts) is the only module that knows where the codec
comes from, and it currently reaches into a **sibling checkout** of
[MetrologicalCBOR.TS](https://github.com/Vanaheimr/MetrologicalCBOR.TS) rather
than into `node_modules`, because that package is not published yet:

```
some-directory/
├── MetrologicalCBOR.TS/
└── COSE.TS/            ← expects ../MetrologicalCBOR.TS
```

which is the layout the conformance suite checks out anyway, as two sibling
submodules. Building against source rather than against a release is also what
that suite needs: what it signs has to be what the codec produces *today*.

When `@vanaheimr/metrological-cbor` ships, that one line becomes an ordinary
import and `package.json` gains a dependency. Nothing else changes.

## What is implemented

- **`CoseSign1`** — a payload signed by a single signer (CBOR tag 18): sign,
  verify, detached payloads, external additional authenticated data, and the
  `crit` header parameter.
- **`CoseSign` / `CoseSignature`** — one payload, several signers (CBOR tag
  98). Each signature carries its own header buckets, so every party signs with
  its own algorithm and its own key.
- **Countersignatures** ([RFC 9338](https://www.rfc-editor.org/rfc/rfc9338),
  header parameter 11) on a `CoseSign1` — a signature *of a signature*, in the
  version 2 form that actually covers the signature it countersigns.
- **`CoseKey`** — COSE keys of key type EC2 ([RFC 9052 §7](https://www.rfc-editor.org/rfc/rfc9052#section-7),
  including compressed `y`), OKP, and AKP
  ([RFC 9964](https://www.rfc-editor.org/rfc/rfc9964)), with the COSE Key
  Thumbprints of [RFC 9679](https://www.rfc-editor.org/rfc/rfc9679).
- **The algorithm and curve registries**, including the fully-specified
  algorithms of [RFC 9864](https://www.rfc-editor.org/rfc/rfc9864) and the
  brainpool curves registered by ISO/IEC 18013-5.

| Algorithm | Id | Curve | Digest |
|-----------|---:|-------|--------|
| `ES256` / `ES384` / `ES512` | −7 / −35 / −36 | any (deprecated by RFC 9864) | SHA-256 / 384 / 512 |
| `ESP256` / `ESP384` / `ESP512` | −9 / −51 / −52 | P-256 / P-384 / P-521 | SHA-256 / 384 / 512 |
| `ESB256` / `ESB320` / `ESB384` / `ESB512` | −265 / −266 / −267 / −268 | brainpoolP256r1 / P320r1 / P384r1 / P512r1 | SHA-256 / 384 / 384 / 512 |
| `ES256K` | −47 | secp256k1 | SHA-256 |
| `Ed25519` / `Ed448` | −19 / −53 | Ed25519 / Ed448 | *(none — pure)* |
| `ML-DSA-44` / `-65` / `-87` | −48 / −49 / −50 | *(none — an algorithm key pair)* | *(none — pure)* |

**Two of those three families are pure**: EdDSA ([RFC 8032](https://www.rfc-editor.org/rfc/rfc8032))
and ML-DSA ([FIPS 204](https://doi.org/10.6028/NIST.FIPS.204), registered for
COSE by [RFC 9964](https://www.rfc-editor.org/rfc/rfc9964)) sign the
`Sig_structure` itself rather than a digest of it. Handing a pure signer a hash
yields a signature that is valid for the hash and that nobody else accepts —
which is why the family is a property of the algorithm here and not an
afterthought.

They also bring two more key types. EdDSA uses **OKP**, where the public key is
the whole of `x` and there is no `y`. ML-DSA uses **AKP**, a key pair belonging
to an algorithm rather than to a curve — and there the labels shift underfoot:
`−1` is the public key and `−2` the private one, where an EC2 or OKP key has
the curve and the x coordinate. Parsing therefore establishes the key type
before it reads anything else. Two further RFC 9964 particulars: `priv` is the
**32-byte seed**, not the expanded secret key, and the thumbprint covers `alg`,
because an ML-DSA public key does not say which parameter set produced it.

EdDSA is deterministic by construction; ML-DSA is not, and RFC 9964 does not
choose. This library always takes the deterministic variant of FIPS 204, where
the per-signature randomness is 32 zero bytes — the choice that decides whether
two implementations can be compared byte for byte or only asked whether each
accepts the other.

Every EC2 curve in the COSE registry is computable here. **brainpoolP320r1 is
the one this package defines itself**, in [`src/ecdsa.ts`](src/ecdsa.ts), from
the domain parameters of [RFC 5639 §3.4](https://www.rfc-editor.org/rfc/rfc5639#section-3.4):
the underlying library ships the three other brainpool curves and not that one.
Transcribing 320-bit constants is the kind of task that fails silently, so they
are checked three times over — the curve constructor refuses a generator that
is not on the curve, [`tests/brainpool.test.ts`](tests/brainpool.test.ts)
checks that the order really is the order, and the conformance suite signs with
them and compares the bytes against Bouncy Castle's own brainpoolP320r1. A
single wrong digit survives none of the three.

Not implemented: `COSE_Countersignature0`, MAC, encryption, and the
X.509 header parameters of [RFC 9360](https://www.rfc-editor.org/rfc/rfc9360)
beyond carrying them — a chain that travels is read back unchanged, but nothing
here validates one against a trust anchor. Styx does; this does not, and a
`crit` that demands `x5chain` is consequently refused.

## Signing and verifying

```typescript
import { CoseAlgorithms, CoseCurves, CoseKey, CoseSign1 } from './src/index.ts';

const key      = CoseKey.fromPrivateScalar(CoseCurves.P256, privateScalar,
                                           { algorithm: CoseAlgorithms.ES256 });

const signed   = CoseSign1.sign(payload, key);
const bytes    = signed.toBytes();

const message  = CoseSign1.parse(bytes);
const result   = message.verify(key.publicKey());

if (!result.verified)
    console.log(result.reason);
```

A failed verification is not an exception — it is the expected outcome of
checking untrusted data — so it comes back as a result carrying the reason.
Malformed input, which is a different kind of wrong, throws `CoseError`.

Signing is **deterministic** ([RFC 6979](https://www.rfc-editor.org/rfc/rfc6979)):
the nonce is derived from the private key and the message rather than drawn at
random. Signing the same data twice yields the same bytes, which makes a
published example recomputable — and it matters rather more for a device with
no dependable source of randomness, since a repeated nonce hands over the
private key.

Whenever the signing key does not live in this process, `toBeSigned()` hands
out exactly the byte string that has to be signed.

## Five things that are easy to get wrong

1. **The signature never covers the message.** It covers the `Sig_structure`
   `["Signature1", protected, external_aad, payload]` (RFC 9052 §4.4). The CBOR
   tag is therefore *not* signed: the same message with and without tag 18
   carries the very same signature bytes.
2. **The protected bucket is kept verbatim.** A re-serialization differing in a
   single byte — a non-preferred integer head, a different map order —
   invalidates every signature made over the original bytes. Nothing here
   re-encodes it, and the CBOR codec is driven in `preserve` mode throughout
   for the same reason.
3. **An empty protected bucket is `h''`, not `h'A0'`.** A zero-length byte
   string, not an encoded empty map, and the parser never "repairs" it.
4. **ECDSA signatures are `r ‖ s`, not DER**, each component zero-padded to the
   width of the group order (RFC 9053 §2.1) — 64 bytes on P-256, 132 on P-521.
   A DER signature produces an error message that says so.
5. **Low-S normalization is a policy, not a rule.** `@noble/curves` normalizes
   `s` by default; COSE does not, and RFC 6979 publishes the un-normalized
   values. Signing here passes `lowS: false` so that the bytes match the C#
   reference implementation, and verification passes it too so that a meter
   which signs without normalizing is not refused.

Key material has its own version of the same trap: coordinates and private keys
are fixed-width byte strings whose **leading zeroes must be preserved**
(RFC 9053 §7.1.1). A plain big-integer serialization shortens them roughly one
time in 256, and the resulting keys are rejected elsewhere. `CoseKey` always
pads, and checks the width whenever a key is actually used.

## Golden vectors

```bash
npm install && npm test
```

The tests are pinned against the same published vectors the C# implementation
uses — same RFCs, same appendices, same transcription:

- **RFC 9052 C.2.1** — `COSE_Sign1`, including the external-AAD variant and the
  untagged form.
- **RFC 9052 C.1.1 / C.1.2** — `COSE_Sign` with one and with two signatures,
  the latter on P-256 and P-521 at once.
- **RFC 9338 A.2.1** — the countersignature the RFC prints in diagnostic
  notation only, assembled here from its documented parts. That both its body
  signature and its countersignature then verify is what proves the assembly.
- **RFC 6979 A.2.5** — the deterministic P-256 signatures, reproduced exactly.
- **RFC 8032 §7.1 and §7.4** — Ed25519 and Ed448, also reproduced exactly, and
  that is a stronger check than any ECDSA vector allows: EdDSA has no nonce to
  draw, so a published signature is not merely verifiable but *recomputable*.
- **The worked signed record of the specification** — 713 bytes produced by the
  C# implementation: the station's signature verifies *and is reproduced byte
  for byte*, both meter readings verify and are reproduced, the operator's
  countersignature verifies, the two metrological readings decode to the values
  the document prints, and all three key identifiers recompute as RFC 9679
  thumbprints.

ECDSA is randomized, so published signature bytes generally cannot be
reproduced by signing — but they can be *verified*, which is the stronger
statement: a single wrong byte anywhere in the `Sig_structure`, the header
buckets or the key would make the verification fail. Where the signer used
RFC 6979, reproduction is available too, and the tests take it.

RFC 5639 publishes brainpoolP320r1's domain parameters and no ECDSA vector for
them, so that curve is checked by arithmetic identity instead — the generator
lies on the curve, and the order really is the order of the generator — and
then, decisively, by the conformance suite comparing its signatures against a
second implementation of the same curve. ML-DSA is checked the same way, by the
properties RFC 9964 pins down (the sizes, the seed-derived key pair, the
label-shifting AKP parameters) and then by that same comparison.

## Continuous integration

`ci.yml` runs the vectors above on Node 20, 22 and 24 on Linux, and on Node 22
on Windows and macOS. Both checkouts land as siblings, since that is the layout
[`src/cbor.ts`](src/cbor.ts) expects; the codec is checked out and not
installed, because it has no runtime dependencies to install.

`nightly.yml` is a real drift detector rather than the same run on a timer.
Two foundations move without a commit landing here: the CBOR codec, taken from
another repository's master, and `@noble/curves`, which pull requests install
from the lock file and the nightly installs without one. Either can break these
tests overnight — the curve library in particular has already done it once, by
normalising ECDSA's `s` where COSE does not.

The third badge is the one that matters most and belongs to another repository:
[MCBORConformanceTests](https://github.com/Vanaheimr/MCBORConformanceTests)
signs every case with **both** this implementation and the C# one and hands
each message to the other to verify. Nothing in this repository can catch two
implementations that quietly disagree about a byte; that suite is what does.

## A note on German calibration law

COSE does not make a data format legally usable in the regulated part of the
charging infrastructure. That follows from the type approval of the measuring
instrument and from the data being checkable with the verification software the
conformity assessment covers — in practice OCMF or a signed meter format today,
not a free-form CBOR structure.

What this is for is the integrity of measurement data along the rest of the
chain, and for the conversation about what a digital, signed SI quantity should
look like.

## License

[Apache License 2.0](LICENSE.md), matching both reference implementations.
