# Security Policy

## Reporting a vulnerability

Please report security issues privately to
**achim.friedland@graphdefined.com**, or through GitHub's
[private vulnerability reporting](https://github.com/Vanaheimr/COSE.TS/security/advisories/new).

Do not open a public issue for a vulnerability.

We aim to acknowledge a report within three working days and to ship a fix or
a mitigation plan within 30 days.

## Supported versions

Until 1.0.0, only the latest version on npm receives fixes.

## How releases are made

Part of the threat model rather than a process note: for a package installed
from a registry, the release path is attack surface.

- **No credential that can publish this package exists in this repository.**
  There is no npm token among its secrets, and the workflow that runs on a tag
  ([`.github/workflows/tag.yml`](.github/workflows/tag.yml)) has
  `contents: read` and no secrets at all — it verifies a tagged commit and
  cannot publish one.
- **Publishing is a hand operation** from a maintainer's machine, with
  multi-factor authentication. An automation token is a bearer secret that
  bypasses two-factor authentication by design; the cost of refusing one is
  npm provenance, and that trade is argued in
  [docs/releasing.md](docs/releasing.md).
- **Release tags are signed**, so which commit a published version was built
  from is a checkable claim rather than an assertion.
- The runtime dependency tree is **five packages from two publishers**: the
  four `@noble` cryptography libraries, and this project's own CBOR codec.
  Nothing is vendored, so every one of them updates through the registry and
  is visible to `npm audit` — which the nightly runs.

Unsolicited offers to help maintain the project, to donate code, or to take
publishing off the maintainer's hands are a documented step in this class of
attack, and are treated accordingly.

## What counts as a vulnerability here

This library signs and verifies legally relevant measurement data, and
everything it reads arrives from a party that may be hostile. The following
are security issues, not merely bugs:

- **Accepting what must be refused.** A signature, an authentication tag or an
  AEAD ciphertext that verifies although the covered bytes changed; a
  certificate chain that validates without ending in the given trust anchors,
  or without being bound to the key that signed.
- **Parser crashes, hangs or unbounded resource use** on COSE messages, keys
  or DER certificates. The fuzz suite (`tests/fuzz`) hunts exactly this class:
  every input must end in a value or a typed refusal, and never a third thing.
- **Timing side channels where symmetry makes them exploitable** — above all
  the authentication-tag comparison, which must not say where the first
  difference lies.
- **Non-deterministic signing.** ECDSA here is RFC 6979 and ML-DSA is the
  deterministic variant of FIPS 204; anything that reintroduces randomness
  into a signature breaks byte-for-byte reproducibility, and a repeated ECDSA
  nonce surrenders the private key.
- **Silent misuse of a key** — an HMAC key talked into producing a truncated
  tag it was not issued for, a signature algorithm accepting a MAC key, or a
  refused key width that stops being refused.

## What is out of scope

- The CBOR codec itself. `@vanaheimr/metrological-cbor` has its
  [own security policy](https://github.com/Vanaheimr/MetrologicalCBOR.TS/blob/master/SECURITY.md);
  please report codec issues there.
- The cryptographic primitives. AES, the curves, the hashes and ML-DSA are the
  `@noble` libraries' — please report findings in the primitive upstream. If
  you are unsure which side of the seam a finding lives on, report it here and
  we will route it.
- The correctness of RFC 9052 and its companions. Specification problems are
  public by nature; report them as ordinary issues.
