/*
 * Copyright (c) 2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr COSE <https://github.com/Vanaheimr/COSE.TS>
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * COSE keys and the two registries, where most of the quiet interoperability
 * failures live: a coordinate one byte too short, an algorithm paired with the
 * wrong curve, a name that differs in case.
 */

import { describe, expect, it }              from 'vitest';

import { ALL_ALGORITHMS, ALL_CURVES, cbor,
         CoseAlgorithms, CoseCurves, CoseError,
         CoseKey, CoseSign1, isEddsaCurve,
         isImplemented,
         KEY_TYPE_EC2, KEY_TYPE_OKP,
         KeyLabel }                          from '../src/index.ts';
import { hex, KEY_11, KEY_BILBO, unhex }     from './vectors.ts';


describe('a COSE key', () => {

    it('writes its labels in the order that is also the deterministic one', () => {

        const value = KEY_11.toCbor();

        expect(value.type).toBe('map');

        if (value.type !== 'map')
            throw new Error('unreachable');

        expect(value.entries.map(([label]) => label.type === 'int' ? Number(label.value) : label))
            .toStrictEqual([KeyLabel.keyType, KeyLabel.keyIdentifier, KeyLabel.algorithm,
                            KeyLabel.curve, KeyLabel.x, KeyLabel.y, KeyLabel.d]);

        // 1, 2, 3, −1, −2, −3, −4 encode to 0x01, 0x02, 0x03, 0x20, 0x21,
        // 0x22, 0x23 — already ascending, so canonical encoding moves nothing.
        expect(hex(cbor.encode(value, { mapKeys: 'sorted' }))).toBe(hex(KEY_11.toBytes()));

    });

    it('survives a round trip through its own bytes', () => {

        const parsed = CoseKey.parse(KEY_11.toBytes());

        expect(hex(parsed.toBytes())).toBe(hex(KEY_11.toBytes()));
        expect(parsed.algorithm?.name).toBe('ES256');
        expect(parsed.curve?.name).toBe('P-256');
        expect(hex(parsed.d!)).toBe(hex(KEY_11.d!));

    });

    it('drops its private half on request and keeps its identity', () => {

        const publicKey = KEY_BILBO.publicKey();

        expect(publicKey.isPrivate).toBe(false);
        expect(publicKey.d).toBeNull();
        expect(hex(publicKey.thumbprint())).toBe(hex(KEY_BILBO.thumbprint()));

    });

    it('refuses a coordinate that lost its leading zero', () => {

        // Exactly what a naive big-integer serialization produces from the
        // P-521 key, whose x begins with a zero byte.
        const shortened = CoseKey.parse(cbor.map([
            [cbor.int(KeyLabel.keyType), cbor.int(2)],
            [cbor.int(KeyLabel.curve),   cbor.int(CoseCurves.P521.id)],
            [cbor.int(KeyLabel.x),       cbor.bytes(KEY_BILBO.x!.slice(1))],
            [cbor.int(KeyLabel.y),       cbor.bytes(KEY_BILBO.y!)],
        ]));

        // Reading it is fine — that is how one finds out that it is wrong.
        expect(shortened.x).toHaveLength(65);

        // Using it is not.
        expect(() => shortened.publicKeyBytes()).toThrow(CoseError);
        expect(() => shortened.publicKeyBytes()).toThrow(/66 bytes wide, including leading zeroes/u);

    });

    it('refuses a point that does not lie on its curve', () => {

        const bogus = CoseKey.fromCoordinates(CoseCurves.P256,
                                              new Uint8Array(32).fill(1),
                                              new Uint8Array(32).fill(2));

        expect(() => bogus.publicKeyBytes()).toThrow(/does not lie on the curve/u);

    });

    it('resolves a y coordinate that travels as a sign bit', () => {

        for (const oddY of [true, false]) {

            const compressed = CoseKey.parse(cbor.map([
                [cbor.int(KeyLabel.keyType), cbor.int(2)],
                [cbor.int(KeyLabel.curve),   cbor.int(CoseCurves.P256.id)],
                [cbor.int(KeyLabel.x),       cbor.bytes(KEY_11.x!)],
                [cbor.int(KeyLabel.y),       cbor.bool(oddY)],
            ]));

            expect(compressed.y).toHaveLength(32);
            expect(() => compressed.publicKeyBytes()).not.toThrow();

            // One of the two parities is the published key; the other is the
            // other point with the same x, and it is a different key.
            expect(hex(compressed.y!) === hex(KEY_11.y!)).toBe(!oddY === (KEY_11.y![31]! % 2 === 0));

        }

    });

    it('is refused as a signing key when it carries no private half', () => {

        expect(() => CoseSign1.sign(new Uint8Array([1]), KEY_11.publicKey()))
            .toThrow(/carries no private key material/u);

    });

});


describe('the algorithm registry', () => {

    it('has no duplicate identifiers or names', () => {

        expect(new Set(ALL_ALGORITHMS.map(each => each.id)).size).toBe(ALL_ALGORITHMS.length);
        expect(new Set(ALL_ALGORITHMS.map(each => each.name)).size).toBe(ALL_ALGORITHMS.length);

    });

    it('pairs every fully-specified algorithm with its own curve', () => {

        expect(CoseAlgorithms.ESP256.curve).toBe(CoseCurves.P256);
        expect(CoseAlgorithms.ESP384.curve).toBe(CoseCurves.P384);
        expect(CoseAlgorithms.ESP512.curve).toBe(CoseCurves.P521);
        expect(CoseAlgorithms.ESB256.curve).toBe(CoseCurves.brainpoolP256r1);
        expect(CoseAlgorithms.ESB384.curve).toBe(CoseCurves.brainpoolP384r1);
        expect(CoseAlgorithms.ESB512.curve).toBe(CoseCurves.brainpoolP512r1);
        expect(CoseAlgorithms.ES256K.curve).toBe(CoseCurves.secp256k1);

        // The three older ones leave the curve to the key, which is what
        // RFC 9864 deprecates them for.
        expect(CoseAlgorithms.ES256.curve).toBeNull();
        expect(CoseAlgorithms.ES256.deprecated).toBe(true);

    });

    it('pairs a 320-bit curve with SHA-384, which is not a typo', () => {

        expect(CoseAlgorithms.ESB320.id).toBe(-266);
        expect(CoseAlgorithms.ESB320.hash).toBe('sha384');
        expect(CoseAlgorithms.ESB320.curve).toBe(CoseCurves.brainpoolP320r1);

    });

    it('refuses to verify a fully-specified algorithm with the wrong curve', () => {

        const message = CoseSign1.sign(new Uint8Array([1]),
                                       KEY_11.withAlgorithm(CoseAlgorithms.ESP256));

        const wrongCurve = CoseKey.fromCoordinates(CoseCurves.P384,
                                                   KEY_BILBO.x!.slice(0, 48),
                                                   KEY_BILBO.y!.slice(0, 48),
                                                   { algorithm: CoseAlgorithms.ESP256 });

        expect(message.verify(wrongCurve).verified).toBe(false);

    });

    it('keeps an unregistered algorithm inspectable rather than unreadable', () => {

        const message = CoseSign1.parse(cbor.tag(18, cbor.array([
            cbor.bytes(cbor.encode(cbor.map([[cbor.int(1), cbor.int(-99999)]]))),
            cbor.map([]),
            cbor.bytes(new Uint8Array([1])),
            cbor.bytes(new Uint8Array(64)),
        ])));

        expect(message.algorithm?.id).toBe(-99999);
        expect(message.algorithm?.signing).toBe(false);

        // ...and it fails where it means something: at the verification.
        expect(message.verify(KEY_11.publicKey()).verified).toBe(false);

    });

});


describe('the curve registry', () => {

    it('has no duplicate identifiers or names', () => {

        expect(new Set(ALL_CURVES.map(each => each.id)).size).toBe(ALL_CURVES.length);
        expect(new Set(ALL_CURVES.map(each => each.name)).size).toBe(ALL_CURVES.length);

    });

    it('knows that P-521 is 66 bytes wide', () => {

        expect(CoseCurves.P521.fieldSize).toBe(66);
        expect(CoseCurves.P521.orderSize).toBe(66);

    });

    it('can compute with every EC2 curve it registers', () => {

        for (const curve of ALL_CURVES.filter(each => each.keyType === KEY_TYPE_EC2))
            expect(isImplemented(curve), curve.name).toBe(true);

    });

    it('keeps the OKP curves out of the ECDSA module, where they do not belong', () => {

        // An OKP curve is not an ECDSA curve, so the ECDSA implementation
        // knows none of them — the EdDSA one does.
        for (const curve of ALL_CURVES.filter(each => each.keyType === KEY_TYPE_OKP))
            expect(isImplemented(curve), curve.name).toBe(false);

        expect(isEddsaCurve(CoseCurves.Ed25519)).toBe(true);
        expect(isEddsaCurve(CoseCurves.Ed448)).toBe(true);

    });

    it('refuses the two key-agreement curves, which sign nothing', () => {

        // X25519 and X448 are in the registry and are not signature curves at
        // all. The refusal names the curve, which is the honest failure;
        // silently substituting one would not be.
        for (const curve of [CoseCurves.X25519, CoseCurves.X448]) {

            expect(isImplemented(curve), curve.name).toBe(false);
            expect(isEddsaCurve(curve),  curve.name).toBe(false);

            expect(() => CoseKey.fromOkpPrivateKey(curve, new Uint8Array(32).fill(1)))
                .toThrow(/not an EdDSA signature curve/u);

        }

    });

});


describe('a signature of the wrong shape', () => {

    it('is refused with the reason it is usually refused for', () => {

        const message = CoseSign1.parse(cbor.tag(18, cbor.array([
            cbor.bytes(unhex('A10126')),
            cbor.map([]),
            cbor.bytes(new Uint8Array([1])),
            cbor.bytes(unhex('3045022100')),        // the head of a DER signature
        ])));

        const result = message.verify(KEY_11.publicKey());

        expect(result.verified).toBe(false);
        expect(result.verified === false && result.reason).toMatch(/DER encoding that was never converted/u);

    });

});
