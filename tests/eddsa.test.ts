/*
 * Copyright (c) 2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr COSE <https://github.com/Vanaheimr/COSE.TS>
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * EdDSA, against the published vectors of RFC 8032.
 *
 * These are stronger checks than the ECDSA ones can be. EdDSA has no nonce to
 * draw, so a published signature is not merely verifiable but *reproducible*:
 * signing the RFC's message with the RFC's key has to yield the RFC's bytes,
 * and one wrong step anywhere would give something else entirely.
 */

import { describe, expect, it }              from 'vitest';

import { CoseAlgorithms, CoseCurves, CoseKey,
         CoseSign1, eddsaSign, eddsaVerify,
         KEY_TYPE_OKP,
         KeyLabel, cbor }                    from '../src/index.ts';
import { hex, unhex }                        from './vectors.ts';


/** RFC 8032, Section 7.1 and Section 7.4. */
const VECTORS = [
    {
        name:      'Ed25519 TEST 1',
        curve:     CoseCurves.Ed25519,
        algorithm: CoseAlgorithms.Ed25519,
        secret:    '9D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BAC031CAE7F60',
        publicKey: 'D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F707511A',
        message:   '',
        signature: 'E5564300C360AC729086E2CC806E828A84877F1EB8E5D974D873E06522490155' +
                   '5FB8821590A33BACC61E39701CF9B46BD25BF5F0595BBE24655141438E7A100B',
    },
    {
        name:      'Ed25519 TEST 3',
        curve:     CoseCurves.Ed25519,
        algorithm: CoseAlgorithms.Ed25519,
        secret:    'C5AA8DF43F9F837BEDB7442F31DCB7B166D38535076F094B85CE3A2E0B4458F7',
        publicKey: 'FC51CD8E6218A1A38DA47ED00230F0580816ED13BA3303AC5DEB911548908025',
        message:   'AF82',
        signature: '6291D657DEEC24024827E69C3ABE01A30CE548A284743A445E3680D7DB5AC3AC' +
                   '18FF9B538D16F290AE67F760984DC6594A7C15E9716ED28DC027BECEEA1EC40A',
    },
    {
        name:      'Ed448 Blank',
        curve:     CoseCurves.Ed448,
        algorithm: CoseAlgorithms.Ed448,
        secret:    '6C82A562CB808D10D632BE89C8513EBF6C929F34DDFA8C9F63C9960EF6E348A3' +
                   '528C8A3FCC2F044E39A3FC5B94492F8F032E7549A20098F95B',
        publicKey: '5FD7449B59B461FD2CE787EC616AD46A1DA1342485A70E1F8A0EA75D80E96778' +
                   'EDF124769B46C7061BD6783DF1E50F6CD1FA1ABEAFE8256180',
        message:   '',
        signature: '533A37F6BBE457251F023C0D88F976AE2DFB504A843E34D2074FD823D41A591F' +
                   '2B233F034F628281F2FD7A22DDD47D7828C59BD0A21BFD3980FF0D2028D4B18A' +
                   '9DF63E006C5D1C2D345B925D8DC00B4104852DB99AC5C7CDDA8530A113A0F4DB' +
                   'B61149F05A7363268C71D95808FF2E652600',
    },
] as const;


describe('the published RFC 8032 vectors', () => {

    it.each(VECTORS)('derive the published public key — $name', vector => {

        const key = CoseKey.fromOkpPrivateKey(vector.curve, unhex(vector.secret));

        expect(key.keyType).toBe(KEY_TYPE_OKP);
        expect(hex(key.x!)).toBe(vector.publicKey);

        // An octet key pair has no y at all — a COSE key that carried one
        // would not be one.
        expect(key.y).toBeNull();

    });

    it.each(VECTORS)('are reproduced byte for byte — $name', vector => {

        // Deterministic without a switch: RFC 8032 derives the nonce from the
        // private key and the message, and offers no other option.
        const signature = eddsaSign(vector.curve, unhex(vector.message), unhex(vector.secret));

        expect(hex(signature)).toBe(vector.signature);

    });

    it.each(VECTORS)('verify against the published public key alone — $name', vector => {

        // The public half on its own, as a verifier would receive it: no
        // private key anywhere in this check.
        const key = CoseKey.fromOkpPublicKey(vector.curve, unhex(vector.publicKey),
                                             { algorithm: vector.algorithm });

        expect(key.isPrivate).toBe(false);
        expect(eddsaVerify(vector.curve, unhex(vector.signature),
                           unhex(vector.message), key.publicKeyBytes())).toBe(true);

        // ...and it is not a signature over any other message. Appending a
        // byte changes the message whether or not there was one to begin with.
        expect(eddsaVerify(vector.curve, unhex(vector.signature),
                           unhex(`${vector.message}00`), key.publicKeyBytes())).toBe(false);

    });

});


describe('an EdDSA COSE_Sign1', () => {

    const payload = new TextEncoder().encode('This is the content.');

    it.each([
        { name: 'Ed25519', curve: CoseCurves.Ed25519, algorithm: CoseAlgorithms.Ed25519,
          secret: VECTORS[0].secret, signatureSize: 64 },
        { name: 'Ed448',   curve: CoseCurves.Ed448,   algorithm: CoseAlgorithms.Ed448,
          secret: VECTORS[2].secret, signatureSize: 114 },
    ])('signs, verifies and round-trips — $name', ({ curve, algorithm, secret, signatureSize }) => {

        const key     = CoseKey.fromOkpPrivateKey(curve, unhex(secret), { algorithm });
        const message = CoseSign1.sign(payload, key);

        expect(message.signature).toHaveLength(signatureSize);
        expect(message.verify(key.publicKey())).toStrictEqual({ verified: true });

        const parsed = CoseSign1.parse(message.toBytes());

        expect(hex(parsed.toBytes())).toBe(hex(message.toBytes()));
        expect(parsed.verify(key.publicKey()).verified).toBe(true);

    });

    it('signs the Sig_structure itself and not a digest of it', () => {

        // The property that separates a pure scheme from ECDSA, and the one
        // that fails silently: a signature over SHA-512 of the Sig_structure
        // verifies against nothing but the same mistake made twice.
        const key       = CoseKey.fromOkpPrivateKey(CoseCurves.Ed25519, unhex(VECTORS[0].secret),
                                                    { algorithm: CoseAlgorithms.Ed25519 });
        const message   = CoseSign1.sign(payload, key);
        const structure = message.toBeSigned();

        expect(hex(message.signature))
            .toBe(hex(eddsaSign(CoseCurves.Ed25519, structure, unhex(VECTORS[0].secret))));

    });

    it('is deterministic, so the whole message is a function of what it signs', () => {

        const key = CoseKey.fromOkpPrivateKey(CoseCurves.Ed25519, unhex(VECTORS[0].secret),
                                              { algorithm: CoseAlgorithms.Ed25519 });

        expect(hex(CoseSign1.sign(payload, key).toBytes()))
            .toBe(hex(CoseSign1.sign(payload, key).toBytes()));

    });

});


describe('an OKP COSE key', () => {

    const key = CoseKey.fromOkpPrivateKey(CoseCurves.Ed25519, unhex(VECTORS[0].secret),
                                          { algorithm: CoseAlgorithms.Ed25519 });

    it('round-trips through its own bytes', () => {

        const parsed = CoseKey.parse(key.toBytes());

        expect(parsed.keyType).toBe(KEY_TYPE_OKP);
        expect(parsed.curve?.name).toBe('Ed25519');
        expect(hex(parsed.toBytes())).toBe(hex(key.toBytes()));

    });

    it('writes kty, alg, crv, x and d — and no y', () => {

        const value = key.toCbor();

        if (value.type !== 'map')
            throw new Error('unreachable');

        expect(value.entries.map(([label]) => Number((label as { value: bigint }).value)))
            .toStrictEqual([KeyLabel.keyType, KeyLabel.algorithm, KeyLabel.curve,
                            KeyLabel.x, KeyLabel.d]);

    });

    it('has a thumbprint over kty, crv and x alone', () => {

        expect(hex(key.thumbprintInput()))
            .toBe(hex(cbor.encode(cbor.map([
                [cbor.int(1),  cbor.int(KEY_TYPE_OKP)],
                [cbor.int(-1), cbor.int(CoseCurves.Ed25519.id)],
                [cbor.int(-2), cbor.bytes(key.x!)],
            ]), { mapKeys: 'sorted' })));

        // The private half and any key identifier stay out of it.
        expect(hex(key.thumbprint())).toBe(hex(key.publicKey().thumbprint()));

    });

});
