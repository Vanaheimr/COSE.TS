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
 * What is implemented: `COSE_Sign1` (tag 18) and `COSE_Sign` (tag 98);
 * `COSE_Mac0` (tag 17) and `COSE_Mac` (tag 97) with HMAC; `COSE_Encrypt0`
 * (tag 16) and `COSE_Encrypt` (tag 96) with AES-GCM; recipient structures
 * carrying a content key by `direct` or AES key wrap; the version 2
 * countersignatures of RFC 9338; COSE keys of key type EC2, OKP, AKP and
 * Symmetric with the key thumbprints of RFC 9679; the ECDSA algorithms of
 * RFC 9053 and RFC 9864, EdDSA of RFC 8032 and ML-DSA of RFC 9964; and the
 * X.509 chains of RFC 9360, walked to a trust anchor and bound to the key that
 * signed. Detached payloads, external additional authenticated data and the
 * `crit` header parameter throughout.
 *
 * The three families mean three different things, and the API keeps them
 * apart. A **signature** says "the holder of that private key produced this",
 * to anybody. A **MAC** says "someone holding the shared key produced this",
 * and only to someone holding that key — so it proves nothing to a third
 * party, and with several recipients nothing to the recipients either.
 * **Encryption** says even less about origin: AEAD integrity means "whoever
 * holds this key wrote this". That is why a metrological record is *signed*,
 * and why a signed payload inside an encrypted envelope is how one gets both.
 * `signWith` and `macWith` refuse each other's algorithms accordingly.
 *
 * What is not, each for a reason. AES-CBC-MAC, whose safety within COSE rests
 * on the encoding rather than on the primitive, see RFC 9053 Section 3.2.1.
 * AES-CCM and ChaCha20/Poly1305, as scope rather than judgement: CCM is eight
 * registered variants of nonce and tag width for a constrained-device world
 * this library does not live in — and, since the crypto moved to noble, a
 * primitive without a supplier — while ChaCha earns its keep where there is
 * no AES hardware; Styx carries neither, so the cross-signing suite would
 * have nothing to compare. `COSE_Countersignature0`, a bare signature with no
 * header buckets of its own: which algorithm made it and which key checks it
 * travel outside the message, by agreement, and everything else here works in
 * the opposite direction. ECDH-based key agreement and the HKDF key
 * derivations, which need COSE_KDF_Context, a structure of its own. And the
 * `x5bag` and `x5u` header parameters: a bag is an unordered heap with no
 * path to follow, and a URI is a fetch, which a signature library has no
 * business performing.
 */

export { CoseError, notDecrypted, notVerified,
         VERIFIED }                                 from './errors.ts';
export type { Decryption, NotVerified,
              Verification }                        from './errors.ts';

export { bytesEqual, cbor, DETERMINISTIC,
         NO_BYTES, PRESERVE }                       from './cbor.ts';

export { canonicalizePayload,
         isCanonicalPayload }                       from './payload.ts';
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

export { aesGcmDecrypt, aesGcmEncrypt, aesKeyUnwrap,
         aesKeyWrap, GCM_NONCE_SIZE, GCM_TAG_SIZE }  from './aes.ts';

export { CoseRecipient, keyWrapAlgorithmFor }       from './recipient.ts';
export type { RecipientOptions }                    from './recipient.ts';

export { COSE_MAC_TAG, CoseMac, MAC_CONTEXT }       from './mac.ts';
export type { MacOptions, MacVerifyOptions }        from './mac.ts';

export { COSE_ENCRYPT0_TAG, COSE_ENCRYPT_TAG,
         CoseEncrypt, CoseEncrypt0, encStructure,
         ENCRYPT0_CONTEXT, ENCRYPT_CONTEXT }        from './encrypt.ts';
export type { DecryptOptions, EncryptOptions }      from './encrypt.ts';

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
