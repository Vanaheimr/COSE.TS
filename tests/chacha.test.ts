/*
 * Copyright (c) 2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr COSE <https://github.com/Vanaheimr/COSE.TS>
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * ChaCha20/Poly1305 [RFC 9053, Section 4.3], pinned the way AES-GCM is: the
 * primitive against RFC 8439's own AEAD example, the COSE structures against
 * the COSE working group's two examples — together with the Enc_structure
 * they publish, since a message that comes out right by way of a wrong
 * additional-data structure stops coming out right the moment anything
 * changes.
 */

import { describe, expect, it }  from 'vitest';

import { chachaPolyDecrypt, chachaPolyEncrypt, CoseAlgorithms, CoseCurves,
         CoseEncrypt, CoseEncrypt0, CoseError, CoseKey, CoseRecipient,
         NO_BYTES }              from '../src/index.ts';
import { hex, unhex }            from './vectors.ts';


const CONTENT = new TextEncoder().encode('This is the content.');

/** The 256-bit key of the working group's examples, kid "sec-256". */
const KEY_256 = unhex('0F1E2D3C4B5A69788796A5B4C3D2E1F01F2E3D4C5B6A798897A6B5C4D3E2F100');


describe('the ChaCha20/Poly1305 primitive', () => {

    it('reproduces the AEAD example of RFC 8439, Section 2.8.2', () => {

        const key       = unhex('808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F');
        const nonce     = unhex('070000004041424344454647');
        const aad       = unhex('50515253C0C1C2C3C4C5C6C7');
        const plaintext = new TextEncoder().encode(
            'Ladies and Gentlemen of the class of \'99: If I could offer you only one tip for the future, sunscreen would be it.');

        const sealed = chachaPolyEncrypt(key, nonce, plaintext, aad);

        expect(hex(sealed)).toBe(
            'D31A8D34648E60DB7B86AFBC53EF7EC2A4ADED51296E08FEA9E2B5A736EE62D63DBEA45E8CA9671282FAFB69DA92728B' +
            '1A71DE0A9E060B2905D6A5B67ECD3B3692DDBD7F2D778B8C9803AEE328091B58FAB324E4FAD675945585808B4831D7BC' +
            '3FF4DEF08E4B7A9DE576D26586CEC64B6116' +
            '1AE10B594F09E26A7E902ECBD0600691');

        expect(hex(chachaPolyDecrypt(key, nonce, sealed, aad)!)).toBe(hex(plaintext));

    });

    it('refuses a key or a nonce of the wrong width, and answers damage with null', () => {

        expect(() => chachaPolyEncrypt(new Uint8Array(16), new Uint8Array(12), CONTENT, NO_BYTES)).toThrow(CoseError);
        expect(() => chachaPolyEncrypt(KEY_256, new Uint8Array(8), CONTENT, NO_BYTES)).toThrow(CoseError);

        const sealed  = chachaPolyEncrypt(KEY_256, new Uint8Array(12), CONTENT, NO_BYTES);
        const damaged = sealed.slice();
        damaged[0] = (damaged[0] ?? 0) ^ 0x01;

        expect(chachaPolyDecrypt(KEY_256, new Uint8Array(12), damaged, NO_BYTES)).toBeNull();
        expect(chachaPolyDecrypt(KEY_256, new Uint8Array(12), new Uint8Array(15), NO_BYTES)).toBeNull();

    });

});


describe('ChaCha20/Poly1305 in COSE, against the working group\'s examples', () => {

    const key = CoseKey.fromSymmetricKey(KEY_256, { algorithm: CoseAlgorithms.ChaCha20Poly1305,
                                                    keyIdentifier: new TextEncoder().encode('sec-256') });

    it('is algorithm 24, with one key width', () => {
        expect(CoseAlgorithms.ChaCha20Poly1305.id).toBe(24);
        expect(CoseAlgorithms.ChaCha20Poly1305.name).toBe('ChaCha20/Poly1305');
        expect(CoseAlgorithms.ChaCha20Poly1305.keySize).toBe(32);
    });

    it('writes chacha-poly-enc-01, a COSE_Encrypt0', () => {

        const message = CoseEncrypt0.encrypt(CONTENT, key, { iv: unhex('5C3A9950BD2852F66E6C8D4F'), keyIdentifier: null });

        expect(hex(message.toBeEncrypted())).toBe('8368456E63727970743044A101181840');
        expect(hex(message.toBytes())).toBe(
            'D08344A1011818A1054C5C3A9950BD2852F66E6C8D4F5824CA119C45926DA993D29B5D0CAC9A84228C7668D492A1B9D7E32020EF21372E74DEF431B9');

        const opened = CoseEncrypt0.parse(message.toBytes()).decrypt(key);
        expect(opened.decrypted && hex(opened.plaintext)).toBe(hex(CONTENT));

    });

    it('writes chacha-poly-01, a COSE_Encrypt with a direct recipient', () => {

        const message = CoseEncrypt.encrypt(CONTENT, CoseKey.fromSymmetricKey(KEY_256, { algorithm: CoseAlgorithms.ChaCha20Poly1305 }),
                                            [CoseRecipient.direct(key)], { iv: unhex('26682306D4FB28CA01B43B80') });

        expect(hex(message.toBeEncrypted())).toBe('8367456E637279707444A101181840');
        expect(hex(message.toBytes())).toBe(
            'D8608444A1011818A1054C26682306D4FB28CA01B43B8058241CD5D49DAA014CCAFFB30E765DC5CD410689AAE1C60B4564' +
            '8853298FF6808DB3FA8235DB818340A2012504477365632D32353640');

        expect(CoseEncrypt.parse(message.toBytes()).decrypt(key).decrypted).toBe(true);

    });

    it('refuses a key of any width but 256 bits, and a key naming AES-GCM', () => {

        expect(() => CoseEncrypt0.encrypt(CONTENT, CoseKey.fromSymmetricKey(new Uint8Array(16), { algorithm: CoseAlgorithms.ChaCha20Poly1305 }),
                                          { iv: new Uint8Array(12) }))
            .toThrow(/32-byte key/u);

        const sealed = CoseEncrypt0.encrypt(CONTENT, key, { iv: new Uint8Array(12) });
        const gcmKey = CoseKey.fromSymmetricKey(KEY_256, { algorithm: CoseAlgorithms.A256GCM });

        // The same 32 bytes under the other AEAD's name: the stated and the
        // expected algorithm disagree, and the message says which it was.
        expect(sealed.decrypt(gcmKey, { expectedAlgorithm: CoseAlgorithms.A256GCM }).decrypted).toBe(false);

    });

    it('opens nothing that was altered', () => {

        const sealed  = CoseEncrypt0.encrypt(CONTENT, key, { iv: new Uint8Array(12) });
        const broken  = sealed.ciphertext!.slice();
        broken[3] = (broken[3] ?? 0) ^ 0x01;

        const altered = new CoseEncrypt0(sealed.protectedHeaderBytes, sealed.unprotectedHeader, broken);

        expect(altered.decrypt(key).decrypted).toBe(false);

    });

});


describe('ChaCha20/Poly1305 behind a key agreed by ECDH-ES', () => {

    it('takes a 256-bit content key derived for it, and nothing else', () => {

        const sender   = CoseKey.fromOkpPrivateKey(CoseCurves.X25519, new Uint8Array(32).fill(0x11));
        const receiver = CoseKey.fromOkpPrivateKey(CoseCurves.X25519, new Uint8Array(32).fill(0x22));

        const { recipient, contentKey } = CoseRecipient.ecdhDirect(receiver.publicKey(), sender,
                                                                   CoseAlgorithms.ChaCha20Poly1305);

        expect(contentKey.privateKeyBytes()).toHaveLength(32);

        const message = CoseEncrypt.encrypt(CONTENT, contentKey, [recipient], { iv: new Uint8Array(12).fill(7) });
        const opened  = CoseEncrypt.parse(message.toBytes()).decrypt(receiver);

        expect(opened.decrypted && hex(opened.plaintext)).toBe(hex(CONTENT));

    });

});
