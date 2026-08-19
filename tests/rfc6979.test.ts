/*
 * Copyright (c) 2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr COSE <https://github.com/Vanaheimr/COSE.TS>
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Deterministic ECDSA [RFC 6979], against the vectors of Appendix A.2.5.
 *
 * The nonce is derived from the private key and the message rather than drawn
 * at random, which has two consequences worth having. A published example
 * becomes recomputable rather than merely checkable — a much stronger claim,
 * because reproducing a signature byte for byte means every byte of the
 * Sig_structure was reproduced too. And a device with no dependable source of
 * randomness stops being a liability: a repeated nonce hands over the private
 * key, and there is no nonce to repeat.
 */

import { describe, expect, it }              from 'vitest';

import { CoseAlgorithms, CoseCurves, CoseKey,
         CoseSign1, digest, signWith }       from '../src/index.ts';
import { CONTENT, hex, unhex }               from './vectors.ts';


/** RFC 6979, Appendix A.2.5: ECDSA, 256 bits, curve NIST P-256. */
const PRIVATE_KEY = unhex('C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721');

const VECTORS = [
    {
        message: 'sample',
        r:       'EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716',
        s:       'F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8',
    },
    {
        message: 'test',
        r:       'F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367',
        s:       '019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083',
    },
] as const;


const key = CoseKey.fromPrivateScalar(CoseCurves.P256, PRIVATE_KEY,
                                      { algorithm: CoseAlgorithms.ES256 });


describe('the published RFC 6979 vectors', () => {

    it.each(VECTORS)('are reproduced for the message "$message"', ({ message, r, s }) => {

        const signature = signWith(CoseAlgorithms.ES256,
                                   CoseCurves.P256,
                                   new TextEncoder().encode(message),
                                   PRIVATE_KEY);

        // r and s, each 32 bytes wide, exactly as the RFC prints them.
        expect(signature).toHaveLength(64);
        expect(hex(signature.slice(0, 32))).toBe(r);
        expect(hex(signature.slice(32))).toBe(s);

    });

    it('are the digest of the message, not the message', () => {

        // What is signed is SHA-256 of the input; the algorithm decides which
        // digest, and the curve never sees the message itself.
        expect(digest('sha256', new TextEncoder().encode('sample'))).toHaveLength(32);

    });

});


describe('a deterministic signature', () => {

    it('is a function of what it signs', () => {

        const first  = CoseSign1.sign(CONTENT, key);
        const second = CoseSign1.sign(CONTENT, key);

        expect(hex(second.toBytes())).toBe(hex(first.toBytes()));
        expect(first.verify(key.publicKey()).verified).toBe(true);

    });

    it('differs as soon as anything it covers differs', () => {

        const first     = CoseSign1.sign(CONTENT, key);
        const other     = CoseSign1.sign(new TextEncoder().encode('Something else.'), key);
        const withAad   = CoseSign1.sign(CONTENT, key, { externalAad: unhex('00') });

        expect(hex(other.signature)).not.toBe(hex(first.signature));
        expect(hex(withAad.signature)).not.toBe(hex(first.signature));

    });

    it('is unchanged by the CBOR tag, which no signature covers', () => {

        const tagged   = CoseSign1.sign(CONTENT, key);
        const untagged = CoseSign1.sign(CONTENT, key, { tagged: false });

        expect(hex(untagged.signature)).toBe(hex(tagged.signature));
        expect(untagged.toBytes()).toHaveLength(tagged.toBytes().length - 1);

    });

});
