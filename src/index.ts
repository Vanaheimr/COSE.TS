/*
 * Copyright (c) 2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr COSE <https://github.com/Vanaheimr/COSE.TS>
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * CBOR Object Signing and Encryption [RFC 9052] in TypeScript.
 *
 * The TypeScript counterpart of Vanaheimr Styx's `Illias/COSE`, built on the
 * same CBOR codec that carries Metrological CBOR — which is the point: the
 * encoding of a metrological reading is a pure function of its value, unit,
 * prefix and uncertainty, so the same reading always produces the same bytes
 * and therefore the same signature. Two implementations that disagree about
 * one byte of a reading produce signatures that fail at the other, and that is
 * a conformance failure a test can catch.
 *
 * What is implemented: `COSE_Sign1` (tag 18) including detached payloads,
 * external additional authenticated data and the `crit` header parameter;
 * `COSE_Sign` (tag 98) with several independent signers; the version 2
 * countersignatures of RFC 9338; COSE keys of key type EC2 with the key
 * thumbprints of RFC 9679; and the ECDSA algorithms of RFC 9053 and RFC 9864.
 *
 * What is not: MAC, encryption, EdDSA, `COSE_Countersignature0`, and the X.509
 * header parameters of RFC 9360 beyond carrying them — a chain that travels is
 * read back unchanged, but nothing here validates one against a trust anchor.
 */

export { CoseError, notVerified, VERIFIED }         from './errors.ts';
export type { Verification }                        from './errors.ts';

export { bytesEqual, cbor, DETERMINISTIC,
         NO_BYTES, PRESERVE }                       from './cbor.ts';
export type { CborEntry, CborValue }                from './cbor.ts';

export { HeaderLabel, headerLabelName,
         isUnderstood, label, sameLabel }           from './labels.ts';

export { ALL_CURVES, CoseCurves, curveById,
         curveByName, KEY_TYPE_EC2, KEY_TYPE_OKP }  from './curve.ts';
export type { CoseCurve }                           from './curve.ts';

export { ALL_ALGORITHMS, algorithmById,
         algorithmByName, algorithmFromCbor,
         algorithmToCbor, CoseAlgorithms,
         resolveCurve, sameAlgorithm,
         signWith, verifyWith }                     from './algorithm.ts';
export type { CoseAlgorithm }                       from './algorithm.ts';

export { decompressY, digest, isImplemented,
         isOnCurve, publicKeyFor }                  from './ecdsa.ts';
export type { DigestAlgorithm }                     from './ecdsa.ts';

export { CoseHeaders,
         verifyCriticalHeaderParameters }           from './headers.ts';

export { CoseKey, KeyLabel }                        from './key.ts';
export type { CoseKeyParts }                        from './key.ts';

export { CoseSignature }                            from './signature.ts';

export { COSE_SIGN1_TAG, COUNTERSIGNATURE_CONTEXT,
         CoseSign1, SIGNATURE_CONTEXT }             from './sign1.ts';
export type { Sign1Options, VerifyOptions }         from './sign1.ts';

export { COSE_SIGN_TAG, CoseSign }                  from './sign.ts';
