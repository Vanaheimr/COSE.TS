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
- **`CoseMac0` / `CoseMac`** — a payload authenticated with a shared key
  (CBOR tags 17 and 97), with the HMAC algorithms of
  [RFC 9053 §3.1](https://www.rfc-editor.org/rfc/rfc9053#section-3.1). Not a
  small signature. See below.
- **`CoseEncrypt0` / `CoseEncrypt`** — content encrypted with AES-GCM (CBOR
  tags 16 and 96).
- **`CoseRecipient`** — how a content key reaches a party: `direct` and AES key
  wrap ([RFC 3394](https://www.rfc-editor.org/rfc/rfc3394)). This is what the
  enveloped forms have and the bare ones do not.
- **X.509 certificate chains** ([RFC 9360](https://www.rfc-editor.org/rfc/rfc9360),
  header parameters `x5chain` and `x5t`) — parsed, walked to a trust anchor,
  and bound to the key that signed. See below.

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

### Message authentication is not signing

`CoseMac0` is the structural twin of `CoseSign1`: four elements in the same
order, CBOR tag 17 against 18, and a MAC_structure differing from the
Sig_structure in one string — `"MAC0"` where the other says `"Signature1"`.
Everything the signature code learned applies unchanged: the protected bucket
kept verbatim, the CBOR tag not covered, detached payloads, external additional
authenticated data.

**What is not the same is what a verified message means**, and that difference
is the whole reason this section exists rather than a line in the table above.

A signature says *"the holder of that private key produced this"*, to anybody
who cares to check. A tag says *"someone holding the shared key produced this"*
— and it says it only to someone who holds that key too, because verifying one
requires the very key that creates one. Between two parties that is still
useful: each knows the other made it, having not made it themselves. Towards a
third party it is worth nothing, and a party who later denies having produced a
message cannot be contradicted with a tag.

That is why a metrological record is **signed**. The customer, the operator and
the regulator all have to be able to check a reading, and none of them may be
able to manufacture one. What a MAC buys instead is size and speed: eight bytes
and one pass of a hash, against sixty-four bytes and a curve multiplication for
the smallest signature here — or 4627 bytes post-quantum. It belongs where the
two ends of a link already share a secret and want cheap tamper detection, with
the durable evidence carried by a signature underneath. COSE nests, so both can
travel at once.

The API keeps them apart deliberately: `signWith` refuses an HMAC algorithm and
`macWith` refuses a signature one, so neither can stand in for the other by
accident.

#### Only HMAC, and why

[RFC 9053 §3.2](https://www.rfc-editor.org/rfc/rfc9053#section-3.2) also
registers AES-CBC-MAC (algorithms 14, 15, 25, 26). It is deliberately absent
here. Raw CBC-MAC is secure only for messages of a **fixed** length: given the
tag `T` of a one-block message `M`, the two-block message `M ‖ (T ⊕ M)` has the
very same tag, which is a forgery constructed without the key. §3.2.1 says so
itself, and names what saves it inside COSE — *"the current structure mitigates
this problem, as a specific encoding structure that includes lengths is built
and signed"*. Its safety there rests on the MAC_structure, not on the
primitive. HMAC needs no such argument, and it is what a device without an AES
accelerator would reach for anyway.

Worth knowing if you ever read the two RFCs side by side: RFC 9052's own
Appendix C.6.1 describes algorithm 15 as *"AES-CMAC"*, while RFC 9053 §3.2
states outright that AES-CBC-MAC **is not** AES-CMAC ([RFC 4493](https://www.rfc-editor.org/rfc/rfc4493)),
which is a different construction that fixes exactly the length problem above.
The identifier is CBC-MAC; the prose of the other RFC is wrong.

#### Three details that are easy to get backwards

- **Truncation applies to the output, never to the key.** `HMAC 256/64` is the
  leftmost eight bytes of the full HMAC-SHA-256. An implementation that
  shortened the key instead would produce tags nobody else accepts, and would
  verify its own perfectly.
- **The comparison is constant time.** A byte-by-byte compare returning early
  tells an attacker how many leading bytes of a guessed tag were right, which
  turns forging a 32-byte tag from 2^256 work into 32 × 256. Signature
  verification has no equivalent exposure, because everything it compares is
  public — this is a requirement a MAC has and a signature does not.
- **A key issued for one algorithm is not talked into another.** Using an
  `HMAC 256/256` key to produce a 64-bit tag is a downgrade its holder never
  agreed to, so `CoseMac0` refuses it — one of the key checks RFC 9053 §3.1
  asks for.

#### Recipient structures, and what they cost

`CoseMac` (tag 97) and `CoseEncrypt` (tag 96) differ from their bare
counterparts in one element: a list of **recipient structures**, each
delivering the one content key to one party by a route only that party can
walk. `CoseMac0` and `CoseEncrypt0` assume both sides already hold the key;
these solve the distribution problem inside the message.

Two routes are implemented, and they are the two reachable from a pre-shared
secret. **`direct`** transports nothing — the recipient's key *is* the content
key, and the structure carries an empty protected bucket, an empty ciphertext
and a key identifier. That makes a one-`direct`-recipient `CoseMac` a
`CoseMac0` with ceremony, which is exactly why the bare forms exist. **AES key
wrap** carries the content key encrypted under a key-encryption key; note that
the algorithm follows the width of the *key-encryption* key, so `A256KW` wraps
a 128-bit content key perfectly well. Key wrap is deterministic — no nonce, no
salt — which is safe only because what it wraps is a uniformly random key
rather than a message.

**A recipient list costs more than bytes.** Every recipient holds the same
content key afterwards, so with more than one of them the tag stops
distinguishing them at all: any recipient can produce a message the others will
accept as coming from the sender. A `CoseMac0` between two parties at least
tells each of them that the other made it, on the grounds that they did not
make it themselves; a `CoseMac` to three parties tells nobody that. RFC 9052
§8.2 is blunt about it — a MAC *"cannot be used to prove the identity of the
sender to a third party"*.

Not implemented: ECDH key agreement and the HKDF-based key derivations. Both
need `COSE_KDF_Context` ([RFC 9053 §5.2](https://www.rfc-editor.org/rfc/rfc9053#section-5.2)),
a structure of its own carrying PartyU and PartyV information and the
supplementary public info — and one whose fields, got subtly wrong, derive a
key that agrees only with an implementation making the same mistake. It is a
piece of work in its own right rather than a variation on this one.

### Encryption

`CoseEncrypt0.encrypt(plaintext, key, { iv })` and
`CoseEncrypt.encrypt(plaintext, contentKey, recipients, { iv })`, with AES-GCM
in all three key widths. Three things here differ from everything else in this
package, and all three catch people out.

**The `Enc_structure` has three elements, not four.** It is
`[context, protected, external_aad]` — no payload. The payload is what is being
*encrypted*; the `Enc_structure` is what is merely *authenticated* alongside
it, as the AEAD's additional data, and the recipient rebuilds it from the
message rather than receiving it.

**The authentication tag is not a field.** AES-GCM's 16-byte tag is appended to
the ciphertext and travels inside the same byte string.

**The nonce is public and must never repeat.** It travels in the `iv` header
parameter in the clear, and that is fine; using one twice with the same key is
not. GCM fails catastrophically on nonce reuse — two messages under one nonce
leak the XOR of their plaintexts *and* the authentication subkey, which lets an
attacker forge afterwards. `iv` is therefore a required option with no default:
only the caller knows which nonces it has spent.

And the point to keep in view: an encrypted message says nothing about *who*
sent it. AEAD integrity means "whoever holds this key wrote this". RFC 9052
§8.3 calls it *"either no or very limited data origination"*. A signed payload
inside an encrypted envelope is how one gets both — and COSE nests, so both can
travel at once.

Not implemented: AES-CCM, ChaCha20/Poly1305, and the `COSE_Encrypt` recipient
routes listed above.

#### The symmetric key

Key type 4 [[RFC 9053 §7.3](https://www.rfc-editor.org/rfc/rfc9053#section-7.3)],
carrying its value under label `−1`. That label now means a **third** thing:
the curve on an EC2 or OKP key, the public key on an algorithm key pair, and
the shared secret here — which is why the key type is established in a pass of
its own before anything else is read.

`publicKey()` throws on one rather than returning it unchanged. RFC 9053 states
outright that the structure *"does not have a form that contains only public
members"*, so stripping the private fields would hand a caller the shared
secret under a name promising the opposite.

Its thumbprint [[RFC 9679 §4.4](https://www.rfc-editor.org/rfc/rfc9679#section-4.4)]
covers `kty` and `k` — and is a hash **of the secret**. §7 of the same RFC warns
about it plainly: a low-entropy key can simply be looked up in a precomputed
table, so thumbprints MUST NOT be used with passwords or anything resembling
one.

No key length is enforced. RFC 9053 says a key SHOULD be as wide as the hash
output, which is advice about key management rather than a rule about the
primitive — RFC 2104 accepts any width, and the published vectors of RFC 4231
include a four-byte key. What a caller must not do is derive one from a
password, and no length check would catch that.

### Certificate chains

`CoseSign1.verifyWithCertificateChain(trustAnchors, { at })` verifies a message
against the chain it carries rather than against a public key somebody handed
over: the chain is walked to one of the given anchors, and the key of its
end-entity certificate is then the key the signature has to verify with. The
two are never answered apart from one another, because a chain that validates
beautifully says nothing about the message it arrived with unless the key it
ends in is the key that signed — and that is a failure no chain check alone
catches.

Checked: the validity periods (at an instant the caller may name, which an
archived message needs), that each certificate was signed by the next, that
every issuer is actually a certification authority allowed to sign
certificates, that the chain ends at an anchor or at something an anchor
issued, and that the end-entity certificate is allowed to create signatures at
all. `x5t`, when present, must name the certificate that travelled.

Not checked, and the same list as Styx so that the two agree about what a pass
means: revocation, name constraints, certificate policies, and path length
beyond the CA flag itself.

The DER is read here rather than by a library, in
[`src/asn1.ts`](src/asn1.ts) and [`src/x509.ts`](src/x509.ts), and the reason
is the same one that made brainpoolP320r1 a local definition. A certificate
chain has to be verifiable with every algorithm this package signs with — which
includes the four brainpool curves and the three ML-DSA parameter sets — and
the TypeScript X.509 libraries verify through WebCrypto, which supports
neither. A meter certificate on brainpoolP256r1 is exactly the certificate they
cannot check. Verification here goes through the same path as every other
signature this package verifies, so whatever COSE can verify, a certificate can
be signed with.

The certificates the test suite reads are minted by Bouncy Castle rather than
written here, which is not a convenience: a DER parser checked against
certificates its own package produced would agree with itself about any
misreading whatsoever.

Not implemented: `COSE_Countersignature0`, AES-CBC-MAC, AES-CCM,
ChaCha20/Poly1305, ECDH-based key agreement, and the `x5bag` and `x5u` header
parameters — a bag is an unordered heap with no path to follow, and a URI is a
fetch, which a signature library has no business performing.

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
- **RFC 4231** — the canonical HMAC-SHA-2 vectors, all three digests, including
  the four-byte key and the one longer than the block size. RFC 9052's only
  `COSE_Mac0` example uses AES-CBC-MAC rather than HMAC, so no published
  message pins both the structure and the primitive at once; the structure is
  pinned against that example all the same — its 37 bytes are parsed, checked
  field by field, re-encoded identically and its MAC_structure asserted — and
  the primitive against these.
- **RFC 9052 Appendix C.5.4 and the COSE working group examples** — for the
  encrypted and enveloped structures. C.5.4 is a `COSE_Mac` whose recipient
  wraps the content key under a published 256-bit key: unwrapping it and
  recomputing the tag reproduces the RFC's published value byte for byte, which
  pins the key wrap, the recipient structure, the `"MAC"` context and HMAC in
  one chain. The working group's examples carry whole AES-GCM messages
  *together with their intermediates* — the `Enc_structure` as hex, the content
  key, the nonce — and every one of those is checked, not merely the final
  bytes: a message that comes out right by way of a wrong additional-data
  structure stops coming out right the moment anything changes.
- **A certificate corpus minted by Bouncy Castle** — fifteen certificates and
  the hierarchies they form, read back here field by field and walked to their
  anchors at a fixed instant. They cover an ECDSA root signing a brainpool
  authority, a chain signed with Ed25519 and one signed with ML-DSA-65, expired
  and not-yet-valid certificates, an issuer that is not an authority, and a
  chain that certifies the wrong key.
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
