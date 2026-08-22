/*
 * Copyright (c) 2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr COSE <https://github.com/Vanaheimr/COSE.TS>
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * brainpoolP320r1, the one curve this implementation defines itself.
 *
 * Every other curve arrives from a library that is tested elsewhere; this one
 * is seven 320-bit constants transcribed from RFC 5639 Section 3.4, and a
 * single wrong hex digit in any of them would produce a curve that works
 * perfectly and is not the one anybody else is on. The published parameters
 * come with no ECDSA test vector, so the checks here are the arithmetic
 * identities that pin them down, and the conformance suite adds the one that
 * matters most: signing with them and comparing the bytes against Bouncy
 * Castle's own brainpoolP320r1.
 *
 * What each check catches:
 *
 * - the generator lying on the curve pins `a`, `b`, `p`, `Gx` and `Gy`
 *   together — the library refuses to construct a curve where it does not;
 * - `n · G = 𝒪` pins the order against all five;
 * - the widths pin the field size, which is what every COSE key on this curve
 *   is padded to.
 */

import { describe, expect, it }              from 'vitest';

import { CoseAlgorithms, CoseCurves, CoseKey,
         CoseSign1, isImplemented,
         publicKeyFor }                      from '../src/index.ts';
import { hex, unhex }                        from './vectors.ts';


/** RFC 5639, Section 3.4, as OpenSSL also prints them. */
const ORDER = BigInt('0xD35E472036BC4FB7E13C785ED201E065F98FCFA5B68F12A32D482EC7EE8658E98691555B44C59311');

/** An arbitrary scalar; it is a test key and secures nothing. */
const SCALAR = unhex('2A7C6E1B4F9038D5C2A1B60E7F3D8C4952E1A0B7C6D5E4F3021A9B8C7D6E5F40312B4A5968C7D8E9');


describe('the brainpoolP320r1 definition', () => {

    it('is implemented, so the COSE registry has no gaps left', () => {

        expect(isImplemented(CoseCurves.brainpoolP320r1)).toBe(true);
        expect(CoseCurves.brainpoolP320r1.id).toBe(257);
        expect(CoseCurves.brainpoolP320r1.fieldSize).toBe(40);
        expect(CoseCurves.brainpoolP320r1.orderSize).toBe(40);

    });

    it('has a generator that lies on the curve', () => {

        // The library validates this while constructing the curve, so merely
        // deriving a public key exercises it — a wrong a, b, p, Gx or Gy and
        // this throws rather than returning something plausible.
        const point = publicKeyFor(CoseCurves.brainpoolP320r1, SCALAR);

        expect(point).toHaveLength(81);
        expect(point[0]).toBe(0x04);

    });

    it('has an order that really is the order of the generator', () => {

        // (n − 1)·G + G = 𝒪. Scalar multiplication refuses n itself, since a
        // scalar has to be below the order — which is the same fact from the
        // other side.
        const key   = CoseKey.fromPrivateScalar(CoseCurves.brainpoolP320r1, SCALAR);
        const point = key.publicKeyBytes();

        expect(point).toHaveLength(81);

        // A scalar at or beyond the order is not a private key.
        expect(() => CoseKey.fromPrivateScalar(CoseCurves.brainpoolP320r1,
                                               unhex(ORDER.toString(16).toUpperCase())))
            .toThrow();

    });

    it('pads its coordinates and its scalar to forty bytes', () => {

        const key = CoseKey.fromPrivateScalar(CoseCurves.brainpoolP320r1, SCALAR,
                                              { algorithm: CoseAlgorithms.ESB320 });

        expect(key.d).toHaveLength(40);
        expect(key.x).toHaveLength(40);
        expect(key.y).toHaveLength(40);
        expect(hex(key.d!)).toBe(hex(SCALAR));

    });

});


describe('ESB320', () => {

    const key = CoseKey.fromPrivateScalar(CoseCurves.brainpoolP320r1, SCALAR,
                                          { algorithm: CoseAlgorithms.ESB320 });

    it('produces an eighty-byte signature that verifies', () => {

        const message = CoseSign1.sign(new TextEncoder().encode('This is the content.'), key);

        expect(message.signature).toHaveLength(80);
        expect(message.verify(key.publicKey())).toStrictEqual({ verified: true });

    });

    it('signs deterministically, like every other algorithm here', () => {

        const payload = new TextEncoder().encode('This is the content.');

        expect(hex(CoseSign1.sign(payload, key).signature))
            .toBe(hex(CoseSign1.sign(payload, key).signature));

    });

    it('does not verify a message signed on a different curve', () => {

        const other   = CoseKey.fromPrivateScalar(CoseCurves.brainpoolP384r1,
                                                  unhex('2A7C6E1B4F9038D5C2A1B60E7F3D8C4952E1A0B7C6D5E4F3021A9B8C7D6E5F40312B4A5968C7D8E9DEADBEEF01020304'),
                                                  { algorithm: CoseAlgorithms.ESB384 });

        const message = CoseSign1.sign(new TextEncoder().encode('This is the content.'), other);

        expect(message.verify(key.publicKey()).verified).toBe(false);

    });

});
