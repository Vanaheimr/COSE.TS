/*
 * Copyright (c) 2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr COSE <https://github.com/Vanaheimr/COSE.TS>
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Every refusal, provoked once.
 *
 * The golden vectors prove that this library accepts what it must accept;
 * this file proves that it refuses what it must refuse, and says why. Each
 * test here corresponds to one guard in the source — a CoseError for a
 * caller's mistake, a not-verified or not-decrypted result for untrusted
 * data — and provokes it with the smallest input that reaches it. A guard
 * nothing can reach is dead code, and a guard no test reaches is one
 * refactoring away from becoming an acceptance.
 */

import { describe, expect, it }  from 'vitest';

import { aesGcmDecrypt, aesGcmEncrypt, aesKeyUnwrap, aesKeyWrap,
         bytesEqual, cbor, CoseAlgorithms, CoseCurves, CoseEncrypt,
         CoseEncrypt0, CoseError, CoseHeaders, CoseKey, CoseMac, CoseMac0,
         CoseRecipient, CoseSign, CoseSign1, CoseSignature,
         eddsaPublicKeyFor, eddsaSignatureSize, eddsaVerify, HeaderLabel,
         headerLabelName, label, macTag, macWith, MLDSA_SIZES,
         mldsaPublicKeyFor, mldsaSign, mldsaVerify, NO_BYTES, resolveCurve,
         sameLabel, signWith, verifyCriticalHeaderParameters,
         verifyWith }            from '../src/index.ts';
import { CONTENT, hex, KEY_11, unhex } from './vectors.ts';


const HMAC_KEY  = CoseKey.fromSymmetricKey(
    unhex('849B57219DAE48DE646D07DBB533566E976686457C1491BE3A76DCEA6C427188'),
    { algorithm: CoseAlgorithms.HMAC256_256 });

const GCM_KEY   = CoseKey.fromSymmetricKey(
    unhex('849B5786457C1491BE3A76DCEA6C4271'),
    { algorithm: CoseAlgorithms.A128GCM });

const IV        = unhex('C9CF4DF2FE6C632BF7886413');

/** A perfectly good P-256 key that simply does not say what it signs with. */
const NAMELESS  = CoseKey.fromPrivateScalar(
    CoseCurves.P256,
    unhex('57C920776641466876760C9520D054AA93C3AFB04E3067025D8264CA2871ED4D'));

// ---------------------------------------------------------------- labels ---

describe('header labels', () => {

    it('name every label the registry names', () => {

        const names: readonly (readonly [number, string])[] = [
            [1, 'alg'], [2, 'crit'], [3, 'content type'], [4, 'kid'],
            [5, 'IV'], [6, 'Partial IV'], [7, 'counter signature'],
            [11, 'counter signature version 2'],
            [12, 'counter signature 0 version 2'],
            [32, 'x5bag'], [34, 'x5t'], [35, 'x5u'],
        ];

        for (const [id, name] of names)
            expect(headerLabelName(cbor.int(id)), String(id)).toBe(name);

    });

    it('hand a text label back as itself, and spell an unknown one out', () => {
        expect(headerLabelName(cbor.text('vendor'))).toBe('vendor');
        expect(headerLabelName(cbor.int(99))).toBe('99');
    });

    it('compare text labels by value, and never across kinds', () => {
        expect(sameLabel(cbor.text('a'), cbor.text('a'))).toBe(true);
        expect(sameLabel(cbor.text('a'), cbor.text('b'))).toBe(false);
        expect(sameLabel(cbor.int(1), cbor.text('1'))).toBe(false);
    });

});


// ------------------------------------------------------------- algorithm ---

describe('the algorithm gates', () => {

    it('refuse to sign with a MAC algorithm', () => {
        expect(() => signWith(CoseAlgorithms.HMAC256_256, null, CONTENT, KEY_11.privateKeyBytes()))
            .toThrow(CoseError);
    });

    it('refuse to verify with an encryption algorithm', () => {
        expect(() => verifyWith(CoseAlgorithms.A128GCM, null, CONTENT, new Uint8Array(64), KEY_11.publicKeyBytes()))
            .toThrow(CoseError);
    });

    it('refuse to MAC with a signature algorithm', () => {
        expect(() => macWith(CoseAlgorithms.ES256, CONTENT, HMAC_KEY.privateKeyBytes()))
            .toThrow(CoseError);
    });

    it('refuse to resolve a curve for a non-signature algorithm', () => {
        expect(() => resolveCurve(CoseAlgorithms.HMAC256_256, null)).toThrow(CoseError);
    });

    it('need a key curve where the algorithm names none', () => {
        expect(() => resolveCurve(CoseAlgorithms.ES256, null)).toThrow(CoseError);
    });

    it('refuse a key on a different curve than the algorithm names', () => {
        expect(() => resolveCurve(CoseAlgorithms.ESP256, CoseCurves.P384)).toThrow(CoseError);
    });

});


// -------------------------------------------------------------------- aes ---

describe('the AES gates', () => {

    it('refuse a key of an impossible width', () => {
        expect(() => aesGcmEncrypt(new Uint8Array(15), new Uint8Array(12), CONTENT, NO_BYTES))
            .toThrow(CoseError);
    });

    it('refuse a nonce of the wrong width on decryption too', () => {
        expect(() => aesGcmDecrypt(new Uint8Array(16), new Uint8Array(11), new Uint8Array(32), NO_BYTES))
            .toThrow(CoseError);
    });

    it('answer a ciphertext shorter than its own tag with null', () => {
        expect(aesGcmDecrypt(new Uint8Array(16), new Uint8Array(12), new Uint8Array(15), NO_BYTES))
            .toBeNull();
    });

    it('refuse to wrap a key that RFC 3394 cannot wrap', () => {
        expect(() => aesKeyWrap(new Uint8Array(16), new Uint8Array(12))).toThrow(CoseError);
    });

    it('answer an unwrappable length with null', () => {
        expect(aesKeyUnwrap(new Uint8Array(16), new Uint8Array(17))).toBeNull();
    });

});


// ---------------------------------------------------------- hmac / ecdsa ---

describe('the primitive gates', () => {

    it('refuse to truncate an HMAC to more than it has', () => {
        expect(() => macTag('sha256', 33, HMAC_KEY.privateKeyBytes(), CONTENT)).toThrow(CoseError);
    });

    it('refuse ECDSA on a curve this build does not compute with', () => {
        expect(() => signWith(CoseAlgorithms.ES256, CoseCurves.Ed25519, CONTENT, new Uint8Array(32)))
            .toThrow(CoseError);
    });

    it('refuse an ECDSA signature of the wrong width, naming the DER suspicion', () => {
        expect(() => verifyWith(CoseAlgorithms.ES256, CoseCurves.P256, CONTENT,
                                new Uint8Array(63), KEY_11.publicKeyBytes()))
            .toThrow(CoseError);
    });

    it('answer an all-zero ECDSA signature with false, not with a throw', () => {
        expect(verifyWith(CoseAlgorithms.ES256, CoseCurves.P256, CONTENT,
                          new Uint8Array(64), KEY_11.publicKeyBytes()))
            .toBe(false);
    });

    it('report that two equal-length byte strings differ', () => {
        expect(bytesEqual(unhex('00'), unhex('01'))).toBe(false);
    });

});


// ------------------------------------------------------------------ eddsa ---

describe('the EdDSA gates', () => {

    it('have no signature size for a Weierstrass curve', () => {
        expect(() => eddsaSignatureSize(CoseCurves.P256)).toThrow(CoseError);
    });

    it('refuse a signature of the wrong width', () => {
        expect(() => eddsaVerify(CoseCurves.Ed25519, new Uint8Array(63), CONTENT,
                                 eddsaPublicKeyFor(CoseCurves.Ed25519, new Uint8Array(32))))
            .toThrow(CoseError);
    });

    it('answer a damaged public key with false, not with a throw', () => {
        // All bytes 0xFF is no point on the curve at all. (All zeroes would
        // be one — the identity — and an all-zero signature against it even
        // verifies under the ZIP-215 rules RFC 8032 permits.)
        expect(eddsaVerify(CoseCurves.Ed25519, new Uint8Array(64), CONTENT,
                           new Uint8Array(32).fill(0xFF)))
            .toBe(false);
    });

});


// ----------------------------------------------------------------- mldsa ---

describe('the ML-DSA gates', () => {

    it('refuse a parameter set the registry does not know', () => {
        expect(() => mldsaSign('ML-DSA-99', CONTENT, new Uint8Array(32))).toThrow(CoseError);
    });

    it('refuse a signature of the wrong width, naming the right one', () => {
        expect(() => mldsaVerify('ML-DSA-44', new Uint8Array(100), CONTENT, new Uint8Array(1312)))
            .toThrow(CoseError);
    });

    it('answer a garbage signature of the right width with false', () => {
        expect(mldsaVerify('ML-DSA-44', new Uint8Array(MLDSA_SIZES['ML-DSA-44'].signature),
                           CONTENT, new Uint8Array(1312)))
            .toBe(false);
    });

    it('refuse a seed of the wrong length', () => {
        expect(() => mldsaPublicKeyFor('ML-DSA-44', new Uint8Array(31))).toThrow(CoseError);
    });

});


// ---------------------------------------------------------------- headers ---

describe('the header buckets', () => {

    it('refuse a parameter given twice', () => {
        expect(() => new CoseHeaders([[label(HeaderLabel.algorithm), cbor.int(-7)],
                                      [label(HeaderLabel.algorithm), cbor.int(-7)]]))
            .toThrow(CoseError);
    });

    it('know their size and their content type', () => {

        const headers = new CoseHeaders([[label(HeaderLabel.contentType), cbor.int(42)]]);

        expect(CoseHeaders.empty.count).toBe(0);
        expect(headers.count).toBe(1);
        expect(headers.contentType?.type).toBe('int');

    });

    it('refuse crit outside the protected bucket', () => {
        const unprotectedCrit = new CoseHeaders([[label(HeaderLabel.critical),
                                                  cbor.array([cbor.int(1)])]]);
        expect(verifyCriticalHeaderParameters(CoseHeaders.empty, unprotectedCrit).verified).toBe(false);
    });

    it('refuse a crit that is not an array', () => {
        const headers = new CoseHeaders([[label(HeaderLabel.critical), cbor.int(1)]]);
        expect(verifyCriticalHeaderParameters(headers, CoseHeaders.empty).verified).toBe(false);
    });

    it('refuse a crit that lists nothing', () => {
        const headers = new CoseHeaders([[label(HeaderLabel.critical), cbor.array([])]]);
        expect(verifyCriticalHeaderParameters(headers, CoseHeaders.empty).verified).toBe(false);
    });

    it('refuse a crit naming a parameter the bucket does not hold', () => {
        const headers = new CoseHeaders([[label(HeaderLabel.critical),
                                          cbor.array([cbor.int(99)])]]);
        expect(verifyCriticalHeaderParameters(headers, CoseHeaders.empty).verified).toBe(false);
    });

});


// ------------------------------------------------------------------- keys ---

describe('the key gates', () => {

    it('refuse an OKP private key of the wrong width', () => {
        expect(() => CoseKey.fromOkpPrivateKey(CoseCurves.Ed25519, new Uint8Array(31)))
            .toThrow(CoseError);
    });

    it('refuse the private half of a parsed key that is too narrow', () => {

        const key = CoseKey.parse(cbor.map([
            [cbor.int(1),  cbor.int(2)],
            [cbor.int(-1), cbor.int(1)],
            [cbor.int(-4), cbor.bytes(new Uint8Array(31))],
        ]));

        expect(() => key.privateKeyBytes()).toThrow(CoseError);

    });

    it('refuse the all-zero private scalar, which is no scalar at all', () => {

        const key = CoseKey.parse(cbor.map([
            [cbor.int(1),  cbor.int(2)],
            [cbor.int(-1), cbor.int(1)],
            [cbor.int(-4), cbor.bytes(new Uint8Array(32))],
        ]));

        expect(() => key.privateKeyBytes()).toThrow(CoseError);

    });

    it('refuse an AKP seed for an algorithm that is no key pair', () => {
        expect(() => CoseKey.fromAkpSeed(CoseAlgorithms.ES256, new Uint8Array(32)))
            .toThrow(CoseError);
    });

    it('refuse an AKP public key for the wrong algorithm, and of the wrong size', () => {
        expect(() => CoseKey.fromAkpPublicKey(CoseAlgorithms.ES256, new Uint8Array(1312)))
            .toThrow(CoseError);
        expect(() => CoseKey.fromAkpPublicKey(CoseAlgorithms.MLDSA44, new Uint8Array(1311)))
            .toThrow(CoseError);
    });

    it('refuse a symmetric key that carries no key value', () => {
        expect(() => CoseKey.parse(cbor.map([[cbor.int(1), cbor.int(4)]]))).toThrow(CoseError);
    });

    it('refuse key operations that are not an array, on every key type', () => {

        // EC2 …
        expect(() => CoseKey.parse(cbor.map([
            [cbor.int(1),  cbor.int(2)],
            [cbor.int(-1), cbor.int(1)],
            [cbor.int(-2), cbor.bytes(new Uint8Array(32))],
            [cbor.int(4),  cbor.int(1)],
        ]))).toThrow(CoseError);

        // … and AKP alike.
        expect(() => CoseKey.parse(cbor.map([
            [cbor.int(1),  cbor.int(7)],
            [cbor.int(3),  cbor.int(-48)],
            [cbor.int(-1), cbor.bytes(new Uint8Array(1312))],
            [cbor.int(4),  cbor.int(1)],
        ]))).toThrow(CoseError);

    });

    it('keep key operations and unknown labels through a round trip', () => {

        for (const key of [
            cbor.map([
                [cbor.int(1),   cbor.int(4)],
                [cbor.int(-1),  cbor.bytes(new Uint8Array(16))],
                [cbor.int(4),   cbor.array([cbor.text('sign')])],
                [cbor.int(99),  cbor.text('vendor')],
            ]),
            cbor.map([
                [cbor.int(1),   cbor.int(2)],
                [cbor.int(-1),  cbor.int(1)],
                [cbor.int(-2),  cbor.bytes(new Uint8Array(32))],
                [cbor.int(99),  cbor.text('vendor')],
            ]),
            cbor.map([
                [cbor.int(1),   cbor.int(7)],
                [cbor.int(3),   cbor.int(-48)],
                [cbor.int(-1),  cbor.bytes(new Uint8Array(1312))],
                [cbor.int(4),   cbor.array([cbor.text('verify')])],
                [cbor.int(99),  cbor.text('vendor')],
            ]),
        ]) {

            // The writer has its own label order, so the first re-encoding
            // may re-arrange — but from then on the bytes are a fixed point,
            // and nothing may be lost on the way.
            const first  = CoseKey.parse(key).toBytes();
            const second = CoseKey.parse(first).toBytes();

            expect(hex(second)).toBe(hex(first));
            expect(hex(first)).toContain('76656E646F72');   // "vendor" survived

        }

    });

    it('fold a leading zero off an over-wide coordinate, and refuse a wide one', () => {

        expect(CoseKey.fromCoordinates(CoseCurves.P256,
                                       unhex('00' + 'AB'.repeat(32)),
                                       new Uint8Array(32)).x)
            .toHaveLength(32);

        expect(() => CoseKey.fromCoordinates(CoseCurves.P256,
                                             unhex('01' + 'AB'.repeat(32)),
                                             new Uint8Array(32)))
            .toThrow(CoseError);

    });

    it('pad a narrow coordinate back to the width of its curve', () => {
        expect(CoseKey.fromCoordinates(CoseCurves.P256,
                                       new Uint8Array(31).fill(0xAB),
                                       new Uint8Array(32)).x)
            .toHaveLength(32);
    });

    it('resolve a sign-bit y only with a curve and an x to resolve it against', () => {

        expect(() => CoseKey.parse(cbor.map([
            [cbor.int(1),  cbor.int(2)],
            [cbor.int(-2), cbor.bytes(new Uint8Array(32))],
            [cbor.int(-3), cbor.bool(true)],
        ]))).toThrow(CoseError);

        expect(() => CoseKey.parse(cbor.map([
            [cbor.int(1),  cbor.int(2)],
            [cbor.int(-1), cbor.int(1)],
            [cbor.int(-3), cbor.bool(true)],
        ]))).toThrow(CoseError);

    });

    it('refuse a y that is neither bytes nor a sign bit', () => {
        expect(() => CoseKey.parse(cbor.map([
            [cbor.int(1),  cbor.int(2)],
            [cbor.int(-1), cbor.int(1)],
            [cbor.int(-2), cbor.bytes(new Uint8Array(32))],
            [cbor.int(-3), cbor.text('up')],
        ]))).toThrow(CoseError);
    });

    it('have no elliptic curve to require on a symmetric key', () => {
        expect(() => HMAC_KEY.publicKeyBytes()).toThrow(CoseError);
    });

    it('tell an unnamed curve apart from an unregistered one', () => {

        expect(() => CoseKey.parse(cbor.map([
            [cbor.int(1),  cbor.int(2)],
            [cbor.int(-2), cbor.bytes(new Uint8Array(32))],
        ])).publicKeyBytes()).toThrow(/does not name/);

        expect(() => CoseKey.parse(cbor.map([
            [cbor.int(1),  cbor.int(2)],
            [cbor.int(-1), cbor.int(99)],
            [cbor.int(-2), cbor.bytes(new Uint8Array(32))],
        ])).publicKeyBytes()).toThrow(/not registered/);

    });

    it('have no public half on a key that carries none', () => {

        const bare = CoseKey.parse(cbor.map([
            [cbor.int(1),  cbor.int(2)],
            [cbor.int(-1), cbor.int(1)],
        ]));

        expect(() => bare.publicKeyBytes()).toThrow(CoseError);

    });

    it('hand out no private bytes from a public key', () => {
        expect(() => KEY_11.publicKey().privateKeyBytes()).toThrow(CoseError);
    });

    it('refuse an AKP private key that is not the 32-byte seed', () => {

        const key = CoseKey.parse(cbor.map([
            [cbor.int(1),  cbor.int(7)],
            [cbor.int(3),  cbor.int(-48)],
            [cbor.int(-2), cbor.bytes(new Uint8Array(31))],
        ]));

        expect(() => key.privateKeyBytes()).toThrow(CoseError);

    });

    it('need the whole key for a thumbprint, whatever the key type', () => {

        const ec2NoY = CoseKey.parse(cbor.map([
            [cbor.int(1),  cbor.int(2)],
            [cbor.int(-1), cbor.int(1)],
            [cbor.int(-2), cbor.bytes(new Uint8Array(32))],
        ]));

        const okpBare = CoseKey.parse(cbor.map([
            [cbor.int(1),  cbor.int(1)],
            [cbor.int(-1), cbor.int(6)],
        ]));

        const akpNoAlgorithm = CoseKey.parse(cbor.map([
            [cbor.int(1),  cbor.int(7)],
            [cbor.int(-1), cbor.bytes(new Uint8Array(1312))],
        ]));

        expect(() => ec2NoY.thumbprint()).toThrow(CoseError);
        expect(() => okpBare.thumbprint()).toThrow(CoseError);
        expect(() => akpNoAlgorithm.thumbprint()).toThrow(CoseError);

    });

    it('refuse a zero-length thumbprint key identifier, and default to eight bytes', () => {
        expect(() => KEY_11.withThumbprintKeyIdentifier(0)).toThrow(CoseError);
        expect(KEY_11.withThumbprintKeyIdentifier().keyIdentifier).toHaveLength(8);
    });

});


// -------------------------------------------------------------- signature ---

describe('a COSE_Signature', () => {

    it('must be three elements with an unprotected bucket', () => {

        expect(() => CoseSignature.parse(cbor.array([cbor.bytes(NO_BYTES), cbor.map([])])))
            .toThrow(CoseError);

        expect(() => CoseSignature.parse(cbor.array([cbor.bytes(NO_BYTES), cbor.int(1),
                                                     cbor.bytes(new Uint8Array(64))])))
            .toThrow(CoseError);

    });

    it('encodes back to bytes', () => {
        const message = CoseSign.sign(CONTENT, KEY_11);
        expect(message.signatures[0]!.toBytes().length).toBeGreaterThan(0);
    });

});


// ------------------------------------------------------------- sign, sign1 ---

describe('the signing gates', () => {

    it('need an algorithm from somewhere', () => {
        expect(() => CoseSign1.sign(CONTENT, NAMELESS)).toThrow(CoseError);
        expect(() => CoseSign.sign(CONTENT, NAMELESS)).toThrow(CoseError);
    });

    it('refuse to canonicalize a payload nobody will hold', () => {
        // 0x1817 is the integer 23 in a deliberately non-shortest spelling —
        // canonicalizing would change the bytes, and a detached payload means
        // nobody would hold the bytes that were actually signed.
        expect(() => CoseSign.sign(unhex('1817'), KEY_11, { detachPayload: true }))
            .toThrow(CoseError);
    });

    it('refuse a countersignature bucket that is neither one nor many', () => {

        const signed = CoseSign1.sign(CONTENT, KEY_11);
        const broken = new CoseSign1(signed.protectedHeaderBytes,
                                     new CoseHeaders([[label(HeaderLabel.counterSignatureV2), cbor.int(1)]]),
                                     signed.payload, signed.signature, signed.isTagged);

        expect(() => broken.countersignatures).toThrow(CoseError);

    });

    it('refuse to re-attach a different payload', () => {

        const detached = CoseSign1.sign(CONTENT, KEY_11).detach();

        expect(detached.attach(CONTENT).verify(KEY_11.publicKey()).verified).toBe(true);
        expect(() => detached.attach(CONTENT).attach(new Uint8Array(3))).toThrow(CoseError);

    });

    it('refuse a detached payload where the message carries its own', () => {

        const attached = CoseSign1.sign(CONTENT, KEY_11);

        expect(attached.verify(KEY_11.publicKey(), { detachedPayload: CONTENT }).verified)
            .toBe(false);

    });

    it('refuse a COSE_Sign of the wrong shape', () => {

        expect(() => CoseSign.parse(cbor.array([cbor.bytes(NO_BYTES), cbor.map([])])))
            .toThrow(CoseError);

        expect(() => CoseSign.parse(cbor.array([cbor.bytes(NO_BYTES), cbor.int(1),
                                                cbor.bytes(CONTENT),
                                                cbor.array([])])))
            .toThrow(CoseError);

    });

    it('refuse a COSE_Sign1 whose unprotected bucket is not a map', () => {
        expect(() => CoseSign1.parse(cbor.array([cbor.bytes(NO_BYTES), cbor.int(1),
                                                 cbor.bytes(CONTENT),
                                                 cbor.bytes(new Uint8Array(64))])))
            .toThrow(CoseError);
    });

});


// -------------------------------------------------------------- recipient ---

describe('the recipient gates', () => {

    it('refuse a key-encryption key whose name contradicts its width', () => {
        const kek = CoseKey.fromSymmetricKey(new Uint8Array(16), { algorithm: CoseAlgorithms.A256KW });
        expect(() => CoseRecipient.keyWrap(GCM_KEY.privateKeyBytes(), kek)).toThrow(CoseError);
    });

    it('refuse a direct recipient holding an EC2 key', () => {
        expect(() => CoseRecipient.direct(KEY_11)).toThrow(CoseError);
    });

    it('must be three or four elements with an unprotected bucket', () => {

        expect(() => CoseRecipient.parse(cbor.array([cbor.bytes(NO_BYTES), cbor.map([])])))
            .toThrow(CoseError);

        expect(() => CoseRecipient.parse(cbor.array([cbor.bytes(NO_BYTES), cbor.int(1),
                                                     cbor.bytes(NO_BYTES)])))
            .toThrow(CoseError);

        expect(() => CoseRecipient.parse(cbor.array([cbor.bytes(NO_BYTES), cbor.map([]),
                                                     cbor.bytes(NO_BYTES), cbor.int(1)])))
            .toThrow(CoseError);

    });

    it('carry nested recipients through a round trip', () => {

        const kek       = CoseKey.fromSymmetricKey(new Uint8Array(16),
                                                   { algorithm: CoseAlgorithms.A128KW,
                                                     keyIdentifier: new TextEncoder().encode('kek') });
        const recipient = CoseRecipient.keyWrap(GCM_KEY.privateKeyBytes(), kek,
                                                { recipients: [CoseRecipient.direct(HMAC_KEY)] });
        const reparsed  = CoseRecipient.parse(recipient.toCbor());

        expect(reparsed.recipients).toHaveLength(1);
        expect(recipient.keyIdentifier).not.toBeNull();
        expect(String(recipient)).toContain('recipient');

    });

    it('answer the wrong unwrapping key with null rather than a guess', () => {

        const kek       = CoseKey.fromSymmetricKey(new Uint8Array(16),
                                                   { algorithm: CoseAlgorithms.A128KW });
        const other     = CoseKey.fromSymmetricKey(new Uint8Array(16).fill(0xFF),
                                                   { algorithm: CoseAlgorithms.A128KW });
        const recipient = CoseRecipient.keyWrap(GCM_KEY.privateKeyBytes(), kek);

        expect(recipient.contentKey(other)).toBeNull();
        expect(recipient.contentKey(HMAC_KEY)).toBeNull();

    });

});


// ------------------------------------------------------------ mac0 and mac ---

describe('the MAC gates', () => {

    it('refuse to create with an encryption algorithm, or without one', () => {
        expect(() => CoseMac0.create(CONTENT, GCM_KEY)).toThrow(CoseError);
        expect(() => CoseMac0.create(CONTENT, CoseKey.fromSymmetricKey(new Uint8Array(32))))
            .toThrow(CoseError);
    });

    it('refuse to verify with an asymmetric key', () => {
        const message = CoseMac0.create(CONTENT, HMAC_KEY);
        expect(message.verify(KEY_11).verified).toBe(false);
    });

    it('refuse a crit demanding what is absent, at verification', () => {

        const message   = CoseMac0.create(CONTENT, HMAC_KEY);
        const protected_ = new CoseHeaders([[label(HeaderLabel.algorithm), cbor.int(5)],
                                            [label(HeaderLabel.critical), cbor.array([cbor.int(99)])]]);
        const broken    = new CoseMac0(protected_.toProtectedBytes(), message.unprotectedHeader,
                                       message.payload, message.tag, message.isTagged);

        expect(broken.verify(HMAC_KEY).verified).toBe(false);

    });

    it('need the detached payload it was told about', () => {

        const detached = CoseMac0.create(CONTENT, HMAC_KEY).detach();

        expect(detached.verify(HMAC_KEY).verified).toBe(false);
        expect(detached.verify(HMAC_KEY, { detachedPayload: CONTENT }).verified).toBe(true);
        expect(() => detached.toBeMaced()).toThrow(CoseError);

    });

    it('refuse a message of the wrong shape', () => {

        expect(() => CoseMac0.parse(cbor.array([cbor.bytes(NO_BYTES), cbor.int(1),
                                                cbor.bytes(CONTENT),
                                                cbor.bytes(new Uint8Array(32))])))
            .toThrow(CoseError);

        expect(() => CoseMac0.parse(cbor.array([cbor.bytes(NO_BYTES), cbor.map([]),
                                                cbor.bytes(CONTENT), cbor.int(1)])))
            .toThrow(CoseError);

        expect(() => CoseMac.parse(cbor.array([cbor.bytes(NO_BYTES), cbor.int(1),
                                               cbor.bytes(CONTENT),
                                               cbor.bytes(new Uint8Array(32)),
                                               cbor.array([])])))
            .toThrow(CoseError);

    });

    it('refuse a COSE_Mac created without a proper key', () => {
        expect(() => CoseMac.create(CONTENT, GCM_KEY, [CoseRecipient.direct(HMAC_KEY)]))
            .toThrow(CoseError);
        expect(() => CoseMac.create(CONTENT, KEY_11, [CoseRecipient.direct(HMAC_KEY)]))
            .toThrow(CoseError);
        expect(() => CoseMac.create(CONTENT, CoseKey.fromSymmetricKey(new Uint8Array(32)),
                                    [CoseRecipient.direct(HMAC_KEY)]))
            .toThrow(CoseError);
    });

    it('refuse to verify a COSE_Mac with the wrong kind of key', () => {
        const message = CoseMac.create(CONTENT, HMAC_KEY, [CoseRecipient.direct(HMAC_KEY)]);
        expect(message.verify(KEY_11).verified).toBe(false);
    });

    it('need the detached payload of a COSE_Mac too', () => {
        const message = CoseMac.create(CONTENT, HMAC_KEY, [CoseRecipient.direct(HMAC_KEY)]);
        const detached = CoseMac.parse(cbor.array([
            cbor.bytes(message.protectedHeaderBytes),
            message.unprotectedHeader.toCbor(),
            cbor.nullValue,
            cbor.bytes(message.tag),
            cbor.array(message.recipients.map(each => each.toCbor())),
        ]));
        expect(detached.isDetached).toBe(true);
        expect(detached.verify(HMAC_KEY).verified).toBe(false);
        expect(detached.verify(HMAC_KEY, { detachedPayload: CONTENT }).verified).toBe(true);
    });

    it('open the recipient the key fits, and walk past the ones it does not', () => {

        const kek     = CoseKey.fromSymmetricKey(new Uint8Array(16),
                                                 { algorithm: CoseAlgorithms.A128KW,
                                                   keyIdentifier: new TextEncoder().encode('kek') });
        const message = CoseMac.create(CONTENT, HMAC_KEY,
                                       [CoseRecipient.direct(HMAC_KEY),
                                        CoseRecipient.keyWrap(HMAC_KEY.privateKeyBytes(), kek)]);

        // The key-encryption key opens the second recipient — after walking
        // past the first, which it cannot open — and the direct key opens the
        // first. A key that opens neither verifies nothing.
        expect(message.verify(kek).verified).toBe(true);
        expect(message.verify(HMAC_KEY).verified).toBe(true);
        expect(message.verify(CoseKey.fromSymmetricKey(new Uint8Array(32),
                                                       { algorithm: CoseAlgorithms.HMAC256_256 })).verified)
            .toBe(false);
        expect(String(message)).toContain('COSE_Mac');

    });

});


// ---------------------------------------------------------------- encrypt ---

describe('the encryption gates', () => {

    const sealed = CoseEncrypt0.encrypt(CONTENT, GCM_KEY, { iv: IV });

    it('refuse an initialization vector that is not a byte string', () => {

        const broken = new CoseEncrypt0(sealed.protectedHeaderBytes,
                                        new CoseHeaders([[label(HeaderLabel.iv), cbor.int(1)]]),
                                        sealed.ciphertext, sealed.isTagged);

        expect(() => broken.iv).toThrow(CoseError);

    });

    it('refuse to encrypt without an algorithm, with the wrong family, or the wrong key', () => {
        expect(() => CoseEncrypt0.encrypt(CONTENT, CoseKey.fromSymmetricKey(new Uint8Array(16)), { iv: IV }))
            .toThrow(CoseError);
        expect(() => CoseEncrypt0.encrypt(CONTENT, HMAC_KEY, { iv: IV })).toThrow(CoseError);
        expect(() => CoseEncrypt0.encrypt(CONTENT, KEY_11, { iv: IV })).toThrow(CoseError);
    });

    it('refuse to encrypt to nobody', () => {
        expect(() => CoseEncrypt.encrypt(CONTENT, GCM_KEY, [], { iv: IV })).toThrow(CoseError);
    });

    it('say why a decryption failed, in every documented way', () => {

        // No stated algorithm anywhere.
        const unstated = new CoseEncrypt0(NO_BYTES, CoseHeaders.empty, sealed.ciphertext, true);
        expect(unstated.decrypt(CoseKey.fromSymmetricKey(GCM_KEY.privateKeyBytes())).decrypted).toBe(false);

        // Stated and expected algorithms disagree.
        const a256 = new CoseHeaders([[label(HeaderLabel.algorithm), cbor.int(3)]]);
        const mislabeled = new CoseEncrypt0(a256.toProtectedBytes(), sealed.unprotectedHeader,
                                            sealed.ciphertext, true);
        expect(mislabeled.decrypt(GCM_KEY).decrypted).toBe(false);

        // The stated algorithm is no content encryption algorithm.
        const hmacAlg = new CoseHeaders([[label(HeaderLabel.algorithm), cbor.int(5)]]);
        const wrongFamily = new CoseEncrypt0(hmacAlg.toProtectedBytes(), sealed.unprotectedHeader,
                                             sealed.ciphertext, true);
        expect(wrongFamily.decrypt(CoseKey.fromSymmetricKey(new Uint8Array(32))).decrypted).toBe(false);

        // No initialization vector.
        const noIv = new CoseEncrypt0(sealed.protectedHeaderBytes, CoseHeaders.empty,
                                      sealed.ciphertext, true);
        expect(noIv.decrypt(GCM_KEY).decrypted).toBe(false);

        // An initialization vector of the wrong width.
        const shortIv = new CoseEncrypt0(sealed.protectedHeaderBytes,
                                         new CoseHeaders([[label(HeaderLabel.iv),
                                                           cbor.bytes(new Uint8Array(8))]]),
                                         sealed.ciphertext, true);
        expect(shortIv.decrypt(GCM_KEY).decrypted).toBe(false);

        // An attached ciphertext plus a detached one.
        expect(sealed.decrypt(GCM_KEY, { detachedCiphertext: sealed.ciphertext! }).decrypted).toBe(false);

        // The wrong kind of key.
        expect(sealed.decrypt(KEY_11).decrypted).toBe(false);

        // A crit demanding what is absent.
        const critical = new CoseHeaders([[label(HeaderLabel.algorithm), cbor.int(1)],
                                          [label(HeaderLabel.critical), cbor.array([cbor.int(99)])]]);
        const demanding = new CoseEncrypt0(critical.toProtectedBytes(), sealed.unprotectedHeader,
                                           sealed.ciphertext, true);
        expect(demanding.decrypt(GCM_KEY).decrypted).toBe(false);

    });

    it('name themselves', () => {
        expect(String(sealed)).toContain('COSE_Encrypt0');
        const enveloped = CoseEncrypt.encrypt(CONTENT, GCM_KEY,
                                              [CoseRecipient.direct(GCM_KEY)], { iv: IV });
        expect(String(enveloped)).toContain('COSE_Encrypt');
        expect(enveloped.decrypt(KEY_11).decrypted).toBe(false);
    });

    it('hold the enveloped form to the same standards as the bare one', () => {

        const recipients = [CoseRecipient.direct(GCM_KEY)];

        expect(() => CoseEncrypt.encrypt(CONTENT, CoseKey.fromSymmetricKey(new Uint8Array(16)),
                                         recipients, { iv: IV }))
            .toThrow(CoseError);
        expect(() => CoseEncrypt.encrypt(CONTENT, HMAC_KEY, recipients, { iv: IV }))
            .toThrow(CoseError);
        expect(() => CoseEncrypt.encrypt(CONTENT, KEY_11, recipients, { iv: IV }))
            .toThrow(CoseError);

        // A symmetric key of no width AES knows fails inside the AEAD, which
        // comes back as a reason rather than as an exception.
        const oddKey = CoseKey.fromSymmetricKey(new Uint8Array(15),
                                                { algorithm: CoseAlgorithms.A128GCM });
        expect(new CoseEncrypt0(sealed.protectedHeaderBytes, sealed.unprotectedHeader,
                                sealed.ciphertext, true)
                   .decrypt(oddKey).decrypted).toBe(false);

        // And a nameless key of the wrong type fails on the type, not the name.
        expect(sealed.decrypt(NAMELESS).decrypted).toBe(false);

    });

    it('have no key identifier unless one was given', () => {
        const anonymous = CoseKey.fromSymmetricKey(GCM_KEY.privateKeyBytes(),
                                                   { algorithm: CoseAlgorithms.A128GCM });
        expect(CoseEncrypt.encrypt(CONTENT, anonymous, [CoseRecipient.direct(anonymous)],
                                   { iv: IV }).keyIdentifier)
            .toBeNull();
    });

});


// ------------------------------------------------------------ second pass ---

describe('the multi-signer gates', () => {

    const signed = CoseSign.sign(CONTENT, KEY_11);

    it('refuse a signature from another message', () => {
        const other = CoseSign.sign(new Uint8Array(3), KEY_11);
        expect(signed.verify(other.signatures[0]!, KEY_11.publicKey()).verified).toBe(false);
    });

    it('refuse a crit demanding the absent, on the body and on the signature', () => {

        const critical = new CoseHeaders([[label(HeaderLabel.critical),
                                           cbor.array([cbor.int(99)])]]).toProtectedBytes();

        const criticalBody = CoseSign.parse(cbor.array([
            cbor.bytes(critical),
            cbor.map([]),
            cbor.bytes(CONTENT),
            cbor.array([signed.signatures[0]!.toCbor()]),
        ]));

        expect(criticalBody.verify(criticalBody.signatures[0]!, KEY_11.publicKey()).verified)
            .toBe(false);

        const criticalSignature = CoseSign.parse(cbor.array([
            cbor.bytes(signed.protectedHeaderBytes),
            cbor.map([]),
            cbor.bytes(CONTENT),
            cbor.array([cbor.array([cbor.bytes(critical), cbor.map([]),
                                    cbor.bytes(new Uint8Array(64))])]),
        ]));

        expect(criticalSignature.verify(criticalSignature.signatures[0]!, KEY_11.publicKey()).verified)
            .toBe(false);

    });

    it('refuse a detached payload where the body carries its own', () => {
        expect(signed.verify(signed.signatures[0]!, KEY_11.publicKey(),
                             { detachedPayload: CONTENT }).verified)
            .toBe(false);
        expect(() => signed.addSignature(KEY_11, { detachedPayload: CONTENT }))
            .toThrow(CoseError);
    });

});


describe('the remaining key gates', () => {

    it('need both coordinates, at the right width', () => {

        expect(() => CoseKey.parse(cbor.map([
            [cbor.int(1),  cbor.int(2)],
            [cbor.int(-1), cbor.int(1)],
            [cbor.int(-2), cbor.bytes(new Uint8Array(32))],
        ])).publicKeyBytes()).toThrow(/both of its coordinates/);

        expect(() => CoseKey.parse(cbor.map([
            [cbor.int(1),  cbor.int(2)],
            [cbor.int(-1), cbor.int(1)],
            [cbor.int(-2), cbor.bytes(new Uint8Array(32))],
            [cbor.int(-3), cbor.bytes(new Uint8Array(31))],
        ])).publicKeyBytes()).toThrow(/including leading zeroes/);

    });

    it('hold no private material after parsing a public key', () => {
        expect(() => CoseKey.parse(cbor.map([
            [cbor.int(1),  cbor.int(2)],
            [cbor.int(-1), cbor.int(1)],
            [cbor.int(-2), cbor.bytes(new Uint8Array(32))],
            [cbor.int(-3), cbor.bytes(new Uint8Array(32))],
        ])).privateKeyBytes()).toThrow(/no private key material/);
    });

});


describe('the remaining MAC gates', () => {

    it('hand out the MAC_structure of an attached message', () => {
        expect(CoseMac0.create(CONTENT, HMAC_KEY).toBeMaced().length).toBeGreaterThan(0);
    });

    it('refuse to verify with a key of the wrong type, whatever it is named', () => {
        const message = CoseMac0.create(CONTENT, HMAC_KEY);
        expect(message.verify(NAMELESS).verified).toBe(false);
    });

    it('refuse a COSE_Mac whose stated algorithm cannot authenticate', () => {

        const message = CoseMac.create(CONTENT, HMAC_KEY, [CoseRecipient.direct(HMAC_KEY)]);
        const gcm     = new CoseHeaders([[label(HeaderLabel.algorithm), cbor.int(1)]]);

        const mislabeled = CoseMac.parse(cbor.array([
            cbor.bytes(gcm.toProtectedBytes()),
            cbor.map([]),
            cbor.bytes(CONTENT),
            cbor.bytes(message.tag),
            cbor.array(message.recipients.map(each => each.toCbor())),
        ]));

        expect(mislabeled.verify(HMAC_KEY).verified).toBe(false);

    });

    it('refuse a COSE_Mac whose crit demands the absent', () => {

        const message  = CoseMac.create(CONTENT, HMAC_KEY, [CoseRecipient.direct(HMAC_KEY)]);
        const critical = new CoseHeaders([[label(HeaderLabel.algorithm), cbor.int(5)],
                                          [label(HeaderLabel.critical), cbor.array([cbor.int(99)])]]);

        const demanding = CoseMac.parse(cbor.array([
            cbor.bytes(critical.toProtectedBytes()),
            cbor.map([]),
            cbor.bytes(CONTENT),
            cbor.bytes(message.tag),
            cbor.array(message.recipients.map(each => each.toCbor())),
        ]));

        expect(demanding.verify(HMAC_KEY).verified).toBe(false);

    });

});
