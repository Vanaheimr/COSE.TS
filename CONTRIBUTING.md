# Contributing

Thank you for considering a contribution. This library signs measurement data
that legal metrology depends on, so a few of the rules below are stricter than
in an average TypeScript project. They exist because a signature that fails at
the other implementation — or verifies when it must not — is worse than a
missing feature.

## Getting started

```bash
npm ci
npm run verify
```

`verify` runs both type checks, the linter, the build, the tests and the API
reference — the same sequence as CI and as `prepublishOnly`. Run it before
opening a pull request.

## Project language

English, everywhere: code, identifiers, comments, documentation, commit
messages, issues and pull requests.

## The rules that are not negotiable

1. **Foreign bytes are the contract.** A COSE message is somebody else's
   bytes: its header maps keep the order the signer wrote, its tagged or
   untagged form is remembered, and re-encoding reproduces the input exactly —
   the fuzz suite asserts the round trip as a fixed point. Never normalise
   away a distinction the wire made; re-sorting a map invalidates signatures
   this library never touched. The one deliberate exception is the RFC 9679
   thumbprint, where deterministic encoding is what the specification asks
   for.

2. **Verification returns; malformation throws; nothing else escapes.**
   A failed signature, tag or decryption is the expected outcome of checking
   untrusted data and comes back as a value carrying the reason. Structurally
   broken input throws `CoseError`. A `TypeError` or `RangeError` escaping a
   parser is a defect — `tests/fuzz` exists to catch exactly that, and has.

3. **An algorithm exists when the other implementation can check it.** Every
   algorithm here is pinned against published vectors, byte for byte, and
   cross-signed against Styx's `Illias/COSE` by the
   [conformance suite](https://github.com/Vanaheimr/MCBORConformanceTests).
   Adding one this library's counterpart does not carry adds surface nothing
   can compare; the README records why AES-CCM, ChaCha20/Poly1305 and
   `COSE_Countersignature0` are absent, and additions of that kind start with
   that argument, not with code.

4. **One implementation, both platforms.** Nothing in `src/` touches `node:*`,
   `Buffer` or WebCrypto; the cryptography is the `@noble` family end to end.
   The claim is enforced twice — `tsconfig.browser.json` type-checks `src/`
   against a world with no Node in it, and `tests/bundle.test.ts` runs the
   bundled library in a V8 context with no Node globals at all.

5. **Signing is deterministic and takes no randomness.** ECDSA is RFC 6979,
   ML-DSA is the deterministic variant of FIPS 204, and keys and nonces are
   the caller's — nothing in this library draws randomness, which is what
   makes every published example recomputable. An API that generated either
   would make messages unreproducible and hide nonce management from the one
   party who can do it correctly.

6. **Symmetry buys constant time.** Whoever can verify a MAC can forge one,
   so the tag comparison must not say where the first difference lies. Keep
   the accumulating-XOR shape; an early return there is a security bug, not a
   style choice.

## Tests

- Golden vectors are somebody else's published bytes — RFC 9052, RFC 9338,
  RFC 6979, RFC 4231, the worked record of the Metrological CBOR
  specification, certificates minted by Bouncy Castle. They are not to be
  "adjusted": if a vector fails, the code is wrong.
- Negative tests belong to every normative MUST.
- The fuzz suites in `tests/fuzz` measure how often their corpus is
  *accepted*, not only what it produces. Every other property there is of the
  form "if it was accepted, then …", which holds vacuously over a corpus that
  has stopped reaching the parser. If you narrow the corpus, expect those
  floors to fail, and fix the corpus rather than the floor.

## Documentation

- Every exported function, class and interface carries a doc comment saying
  what it is for, not what it does. `npm run docs:api` builds the reference,
  and treats a symbol reachable from the API but not exported, or a link that
  goes nowhere, as an error.
- Typedoc's `notDocumented` check is deliberately off, as it is for the
  codec: what it reports is fields whose one-line restatement of the type
  would bury the warning that matters.

## Commits and pull requests

- One logical change per pull request; keep the diff reviewable.
- Update `CHANGELOG.md` under `## [Unreleased]`.
- New source files carry the same short Apache-2.0 header the existing files
  do.

## Security

Please report vulnerabilities privately; see [SECURITY.md](SECURITY.md) —
which also says what counts as one here.

## License

By contributing you agree that your contributions are licensed under the
Apache License 2.0, as described in [LICENSE.md](LICENSE.md).
