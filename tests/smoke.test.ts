/*
 * Copyright (c) 2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr COSE <https://github.com/Vanaheimr/COSE.TS>
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * That the pieces are wired together at all: the CBOR codec resolves, a key
 * is a key, and a signature this library makes is one it also accepts.
 */

import { describe, expect, it }  from 'vitest';

import { cbor, CoseAlgorithms, CoseCurves, CoseKey,
         CoseSign1, CoseSign }   from '../src/index.ts';


const PAYLOAD = new TextEncoder().encode('This is the content.');

const key = CoseKey.fromPrivateScalar(
    CoseCurves.P256,
    cbor.hexToBytes('57C92077664146E876760C9520D054AA93C3AFB04E306705DB6090308507B4D3'),
    { algorithm: CoseAlgorithms.ES256 },
);


describe('the CBOR codec', () => {

    it('is reachable from here', () => {
        expect(cbor.encodeToHex(cbor.text('a'))).toBe('6161');
    });

});


describe('a COSE_Sign1 this library makes', () => {

    it('verifies, and says so', () => {

        const message = CoseSign1.sign(PAYLOAD, key);

        expect(message.verify(key.publicKey()).verified).toBe(true);

    });

    it('survives a round trip through its own bytes', () => {

        const bytes  = CoseSign1.sign(PAYLOAD, key).toBytes();
        const parsed = CoseSign1.parse(bytes);

        expect(parsed.isTagged).toBe(true);
        expect(cbor.bytesToHex(parsed.toBytes())).toBe(cbor.bytesToHex(bytes));
        expect(parsed.verify(key.publicKey()).verified).toBe(true);

    });

    it('does not verify a payload it did not sign', () => {

        const message = CoseSign1.sign(PAYLOAD, key);
        const other   = new Uint8Array(PAYLOAD);
        other[0]      = (PAYLOAD[0] ?? 0) ^ 0x01;

        const result = CoseSign1.parse(message.toBytes()).detach()
                                .verify(key.publicKey(), { detachedPayload: other });

        expect(result.verified).toBe(false);

    });

});


describe('a COSE_Sign this library makes', () => {

    it('verifies each of its signatures independently', () => {

        const second  = CoseKey.fromPrivateScalar(
            CoseCurves.P384,
            cbor.hexToBytes('6952487A0A16EACE6E9A69EFD062D7671D68D23FF68722326348827C3A94E2A1' +
                            '743A1DF8901B948412CCA26CA4372CED'),
            { algorithm: CoseAlgorithms.ES384 },
        );

        const message = CoseSign.sign(PAYLOAD, key).addSignature(second);
        const parsed  = CoseSign.parse(message.toBytes());

        expect(parsed.signatures).toHaveLength(2);
        expect(parsed.verify(parsed.signatures[0]!, key.publicKey()).verified).toBe(true);
        expect(parsed.verify(parsed.signatures[1]!, second.publicKey()).verified).toBe(true);

        // ...and never with the other party's key.
        expect(parsed.verify(parsed.signatures[0]!, second.publicKey()).verified).toBe(false);

    });

});
