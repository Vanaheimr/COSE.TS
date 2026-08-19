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
 * countersignatures of RFC 9338; `COSE_Mac0` (tag 17) with the HMAC algorithms
 * of RFC 9053; COSE keys of key type EC2, OKP, AKP and Symmetric with the key
 * thumbprints of RFC 9679; the ECDSA algorithms of RFC 9053 and RFC 9864,
 * EdDSA of RFC 8032 and ML-DSA of RFC 9964; and the X.509 chains of RFC 9360,
 * parsed, walked to a trust anchor and bound to the key that signed.
 *
 * A `COSE_Mac0` is the structural twin of a `COSE_Sign1` and means something
 * entirely different: a MAC is symmetric, so whoever can verify one can produce
 * one, and it therefore proves nothing to any third party. That is why a
 * metrological record is signed. `signWith` and `macWith` refuse each other's
 * algorithms so that the two can not be confused by accident.
 *
 * What is not: `COSE_Mac` with recipient structures, AES-CBC-MAC — whose
 * safety within COSE rests on the encoding rather than on the primitive, see
 * RFC 9053 Section 3.2.1 — encryption, `COSE_Countersignature0`, and the
 * `x5bag` and `x5u` header parameters: a bag is an unordered heap with no path
 * to follow, and a URI is a fetch, which a signature library has no business
 * performing.
 */

export { CoseError, notVerified, VERIFIED }         from './errors.ts';
export type { NotVerified, Verification }           from './errors.ts';

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
         macWith, resolveCurve, sameAlgorithm,
         signWith, verifyMacWith, verifyWith }      from './algorithm.ts';
export type { AlgorithmFamily, CoseAlgorithm }      from './algorithm.ts';

export { decompressY, digest, isImplemented,
         isOnCurve, publicKeyFor }                  from './ecdsa.ts';
export type { DigestAlgorithm }                     from './ecdsa.ts';

export { eddsaPublicKeyFor, eddsaSign,
         eddsaSignatureSize, eddsaVerify,
         isEddsaCurve }                             from './eddsa.ts';

export { isMldsaParameterSet, MLDSA_PARAMETER_SETS,
         MLDSA_SEED_SIZE, MLDSA_SIZES,
         mldsaPublicKeyFor, mldsaSign,
         mldsaVerify }                              from './mldsa.ts';
export type { MldsaParameterSet }                   from './mldsa.ts';

export { CoseHeaders,
         verifyCriticalHeaderParameters }           from './headers.ts';

export { CoseKey, KEY_TYPE_AKP,
         KEY_TYPE_SYMMETRIC, KeyLabel }             from './key.ts';
export type { CoseKeyParts }                        from './key.ts';

export { CoseSignature }                            from './signature.ts';

export { COSE_SIGN1_TAG, COUNTERSIGNATURE_CONTEXT,
         CoseSign1, SIGNATURE_CONTEXT }             from './sign1.ts';
export type { CertificateChainVerification,
              CertificateChainVerifyOptions,
              Sign1Options, VerifyOptions }         from './sign1.ts';

export { COSE_SIGN_TAG, CoseSign }                  from './sign.ts';

export { COSE_MAC0_TAG, CoseMac0, MAC0_CONTEXT }     from './mac0.ts';
export type { Mac0Options, Mac0VerifyOptions }      from './mac0.ts';

export { hmac, macTag, tagsEqual }                  from './hmac.ts';

export { contentsOf, contextTag, derBitString,
         derBitStringRaw, derBoolean, derInteger,
         derObjectIdentifier, derString, derTime,
         DerReader, Tag }                           from './asn1.ts';
export type { Asn1Node }                            from './asn1.ts';

export { curveByOid, KeyUsage, oidOfCurve,
         signatureAlgorithmByOid, X509Certificate,
         X509Name }                                 from './x509.ts';
export type { BasicConstraints, NameAttribute }     from './x509.ts';

export { CoseCertificateChain,
         CoseCertificateHash }                      from './x5chain.ts';
export type { ChainValidationOptions }              from './x5chain.ts';
