/*
 * Copyright (c) 2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr COSE <https://github.com/Vanaheimr/COSE.TS>
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Encryption and enveloped authentication: `COSE_Encrypt0` (tag 16),
 * `COSE_Encrypt` (tag 96) and `COSE_Mac` (tag 97), with AES-GCM, AES key wrap
 * and the `direct` recipient algorithm.
 *
 * The vectors are published ones throughout, and unusually complete for this
 * corner of COSE:
 *
 *   - The **COSE working group example repository** carries whole messages
 *     together with their intermediates — the `Enc_structure` as hex, the
 *     content key, the nonce, and the resulting CBOR. Every one of those
 *     intermediates is checked here, not merely the final bytes, because a
 *     message that comes out right by way of a wrong AAD is a message that
 *     stops coming out right the moment anything changes.
 *   - **RFC 9052 Appendix C.5.4** is a `COSE_Mac` whose second recipient wraps
 *     the content key under a published 256-bit key. Unwrapping it and
 *     recomputing the tag reproduces the RFC's published value byte for byte,
 *     which pins the key wrap, the recipient structure, the `"MAC"` context and
 *     HMAC in one go.
 */

import { describe, expect, it }              from 'vitest';

import { CoseAlgorithms, CoseEncrypt,
         CoseEncrypt0, CoseError, CoseKey,
         CoseMac, CoseRecipient, encStructure,
         aesKeyUnwrap, aesKeyWrap,
         keyWrapAlgorithmFor }               from '../src/index.ts';
import { CONTENT, hex, unhex }               from './vectors.ts';


const IV = unhex('02D1F7E6F26C43D4868D87CE');

/** The 128-, 192- and 256-bit content keys of the working group's examples. */
const CEK = {
    128: unhex('849B57219DAE48DE646D07DBB533566E'),
    192: unhex('0F1E2D3C4B5A69788796A5B4C3D2E1F01F2E3D4C5B6A7988'),
    256: unhex('0F1E2D3C4B5A69788796A5B4C3D2E1F01F2E3D4C5B6A798897A6B5C4D3E2F100'),
} as const;

const keyFor = (bits: 128 | 192 | 256, algorithm = CoseAlgorithms.A128GCM): CoseKey =>
    CoseKey.fromSymmetricKey(CEK[bits], { algorithm });


// -------------------------------------------------------- COSE_Encrypt0 ---

/** cose-wg `aes-gcm-examples/aes-gcm-enc-0{1,2,3}`. */
const ENCRYPT0 = [
    { bits: 128, algorithm: CoseAlgorithms.A128GCM,
      aad: '8368456E63727970743043A1010140',
      cbor: 'D08343A10101A1054C02D1F7E6F26C43D4868D87CE582460973A94BB2898009EE52EC' +
            'FD9AB1DD25867374B162E2C03568B41F57C3CC16F9166250A' },
    { bits: 192, algorithm: CoseAlgorithms.A192GCM,
      aad: '8368456E63727970743043A1010240',
      cbor: 'D08343A10102A1054C02D1F7E6F26C43D4868D87CE5824134D3B9223A00C1552C775' +
            '85C157F467F295919D530FBE21F7689AB3CD4D18FFE8E17CEB' },
    { bits: 256, algorithm: CoseAlgorithms.A256GCM,
      aad: '8368456E63727970743043A1010340',
      cbor: 'D08343A10103A1054C02D1F7E6F26C43D4868D87CE58249D64A5A59A3B04867DCCF6' +
            'B8EF82F7D1A3B25EF84ECA2BC5D7593A96E943859A9CC24AD3' },
] as const;


describe('COSE_Encrypt0 with AES-GCM, against the published examples', () => {

    for (const vector of ENCRYPT0) {

        it(`reproduces the A${String(vector.bits)}GCM example byte for byte`, () => {

            const key     = keyFor(vector.bits, vector.algorithm);
            const message = CoseEncrypt0.encrypt(CONTENT, key, { iv: IV, keyIdentifier: null });

            // The intermediate first: the Enc_structure is what the AEAD
            // authenticates, and getting the final bytes right by way of a
            // wrong one is possible and would not survive any change.
            expect(hex(message.toBeEncrypted())).toBe(vector.aad);
            expect(hex(message.toBytes())).toBe(vector.cbor);

        });

        it(`reads the A${String(vector.bits)}GCM example back`, () => {

            const message = CoseEncrypt0.parse(unhex(vector.cbor));

            expect(message.isTagged).toBe(true);
            expect(message.algorithm?.name).toBe(vector.algorithm.name);
            expect(hex(message.iv!)).toBe(hex(IV));

            const result = message.decrypt(keyFor(vector.bits, vector.algorithm));

            expect(result.decrypted).toBe(true);
            expect(result.decrypted === true && new TextDecoder().decode(result.plaintext))
                .toBe('This is the content.');

        });

    }

    it('has an Enc_structure of three elements and no payload', () => {

        // [ "Encrypt0", h'a10101', h'' ] — the payload is what is encrypted,
        // not what is authenticated alongside.
        expect(hex(encStructure('Encrypt0', unhex('A10101'))))
            .toBe('83' + '68' + '456E6372797074' + '30' + '43A10101' + '40');

    });

    it('appends the authentication tag to the ciphertext', () => {

        const message = CoseEncrypt0.encrypt(CONTENT, keyFor(128), { iv: IV });

        // 20 bytes of plaintext, 16 of tag.
        expect(message.ciphertext).toHaveLength(CONTENT.length + 16);

    });

    it('refuses a ciphertext that was altered, in any single bit', () => {

        const key      = keyFor(128);
        const original = CoseEncrypt0.encrypt(CONTENT, key, { iv: IV });

        for (const position of [0, 19, 20, 35]) {

            const broken = Uint8Array.from(original.ciphertext!);
            broken[position] = (broken[position] ?? 0) ^ 0x01;

            const message = new CoseEncrypt0(original.protectedHeaderBytes,
                                             original.unprotectedHeader,
                                             broken, original.isTagged);

            expect(message.decrypt(key).decrypted, `byte ${String(position)}`).toBe(false);

        }

    });

    it('refuses a protected bucket that was altered, because it is the AAD', () => {

        const key      = keyFor(128);
        const original = CoseEncrypt0.encrypt(CONTENT, key, { iv: IV });

        // Say A256GCM in the header while the ciphertext is A128GCM.
        const message = new CoseEncrypt0(unhex('A10103'),
                                         original.unprotectedHeader,
                                         original.ciphertext, original.isTagged);

        expect(message.decrypt(key).decrypted).toBe(false);

    });

    it('carries external additional authenticated data without transporting it', () => {

        const key = keyFor(128);
        const aad = unhex('11AA22BB33CC44DD55006699');

        const message = CoseEncrypt0.encrypt(CONTENT, key, { iv: IV, externalAad: aad });

        expect(hex(message.toBytes())).not.toContain('11AA22BB');
        expect(message.decrypt(key, { externalAad: aad }).decrypted).toBe(true);
        expect(message.decrypt(key).decrypted).toBe(false);

    });

    it('insists on a nonce rather than inventing one', () => {

        // There is no default and there must not be one: a repeated nonce
        // breaks AES-GCM outright, and this package cannot know which ones a
        // caller has already spent.
        expect(() => CoseEncrypt0.encrypt(CONTENT, keyFor(128),
                                          { iv: unhex('0011') })).toThrow(/12-byte nonce/u);

    });

    it('refuses a key of the wrong width for the algorithm named', () => {

        const wrong = CoseKey.fromSymmetricKey(CEK[256], { algorithm: CoseAlgorithms.A128GCM });

        expect(() => CoseEncrypt0.encrypt(CONTENT, wrong, { iv: IV })).toThrow(/16-byte key/u);

    });

    it('refuses to encrypt with an algorithm that is not a cipher', () => {

        const wrong = CoseKey.fromSymmetricKey(CEK[128], { algorithm: CoseAlgorithms.HMAC256_256 });

        expect(() => CoseEncrypt0.encrypt(CONTENT, wrong, { iv: IV }))
            .toThrow(/not a content encryption algorithm/u);

    });

    it('keeps the same ciphertext with the payload detached', () => {

        const key      = keyFor(128);
        const attached = CoseEncrypt0.encrypt(CONTENT, key, { iv: IV });
        const detached = CoseEncrypt0.encrypt(CONTENT, key, { iv: IV, detachPayload: true });

        expect(detached.ciphertext).toBeNull();
        expect(detached.decrypt(key, { detachedCiphertext: attached.ciphertext }).decrypted).toBe(true);
        expect(detached.decrypt(key).decrypted).toBe(false);

    });

});


// --------------------------------------------------------- COSE_Encrypt ---

/** cose-wg `aes-gcm-examples/aes-gcm-0{1,2,3}`, enveloped with one `direct` recipient. */
const ENCRYPT = [
    { bits: 128, algorithm: CoseAlgorithms.A128GCM,
      aad: '8367456E637279707443A1010140',
      cbor: 'D8608443A10101A1054C02D1F7E6F26C43D4868D87CE582460973A94BB2898009EE52E' +
            'CFD9AB1DD25867374B3581F2C80039826350B97AE2300E42FC818340A20125044A6F' +
            '75722D73656372657440' },
    // Only the 128-bit message is pinned byte for byte: the other two use key
    // identifiers of their own ("sec-48", "sec-64"), so what they pin here is
    // the Enc_structure, which is the part that differs from Encrypt0.
    { bits: 192, algorithm: CoseAlgorithms.A192GCM,
      aad: '8367456E637279707443A1010240', cbor: null },
    { bits: 256, algorithm: CoseAlgorithms.A256GCM,
      aad: '8367456E637279707443A1010340', cbor: null },
] as const;


describe('COSE_Encrypt with a direct recipient', () => {

    const secretKey = (bits: 128 | 192 | 256, algorithm: typeof CoseAlgorithms.A128GCM) =>
        CoseKey.fromSymmetricKey(CEK[bits], { algorithm, keyIdentifier: new TextEncoder().encode('our-secret') });

    it('reproduces the published A128GCM message byte for byte', () => {

        const key       = secretKey(128, CoseAlgorithms.A128GCM);
        const recipient = CoseRecipient.direct(key);
        const message   = CoseEncrypt.encrypt(CONTENT, key, [recipient], { iv: IV });

        expect(hex(message.toBeEncrypted())).toBe(ENCRYPT[0].aad);
        expect(hex(message.toBytes())).toBe(ENCRYPT[0].cbor);

    });

    it('builds the "Encrypt" context, which is not "Encrypt0"', () => {

        for (const vector of ENCRYPT) {

            const key     = secretKey(vector.bits, vector.algorithm);
            const message = CoseEncrypt.encrypt(CONTENT, key, [CoseRecipient.direct(key)], { iv: IV });

            expect(hex(message.toBeEncrypted()), vector.algorithm.name).toBe(vector.aad);

        }

    });

    it('round-trips and decrypts', () => {

        const key     = secretKey(256, CoseAlgorithms.A256GCM);
        const message = CoseEncrypt.parse(
                            CoseEncrypt.encrypt(CONTENT, key, [CoseRecipient.direct(key)], { iv: IV }).toBytes());

        expect(message.recipients).toHaveLength(1);
        expect(message.recipients[0]!.algorithm?.name).toBe('direct');
        expect(message.recipients[0]!.ciphertext).toHaveLength(0);
        expect(message.decrypt(key).decrypted).toBe(true);

    });

    it('refuses a direct recipient that carries key material', () => {

        const key       = secretKey(128, CoseAlgorithms.A128GCM);
        const original  = CoseEncrypt.encrypt(CONTENT, key, [CoseRecipient.direct(key)], { iv: IV });

        // RFC 9053 §6.1.1: nothing is transported by this route, so a
        // non-empty ciphertext means the structure is not what it claims.
        const tampered = new CoseEncrypt(
                             original.protectedHeaderBytes, original.unprotectedHeader,
                             original.ciphertext,
                             [new CoseRecipient(original.recipients[0]!.protectedHeaderBytes,
                                                original.recipients[0]!.unprotectedHeader,
                                                unhex('00112233'))],
                             original.isTagged);

        expect(tampered.decrypt(key).decrypted).toBe(false);

    });

});


// ------------------------------------------------------------ key wrap ---

describe('AES key wrap', () => {

    it('recovers the content key of RFC 9052 Appendix C.5.4', () => {

        const kek     = unhex('849B57219DAE48DE646D07DBB533566E976686457C1491BE3A76DCEA6C427188');
        const wrapped = unhex('0B2C7CFCE04E98276342D6476A7723C090DFDD15F9A518E7736549E998370695E6D6A83B4AE507BB');

        const cek = aesKeyUnwrap(kek, wrapped);

        expect(cek).not.toBeNull();
        expect(hex(cek!)).toBe('2B7459201E5046E33FDB514C5E14A1B01D9893F8936335F821FCB1AFF450B226');

        // Deterministic, which is the property that makes this checkable at
        // all — and safe only because what it wraps is a random key.
        expect(hex(aesKeyWrap(kek, cek!))).toBe(hex(wrapped));

    });

    it('fails rather than returning rubbish under the wrong key', () => {

        const wrapped = unhex('0B2C7CFCE04E98276342D6476A7723C090DFDD15F9A518E7736549E998370695E6D6A83B4AE507BB');

        expect(aesKeyUnwrap(new Uint8Array(32), wrapped)).toBeNull();

    });

    it('names the algorithm after the key-encryption key, not the wrapped one', () => {

        expect(keyWrapAlgorithmFor(16).name).toBe('A128KW');
        expect(keyWrapAlgorithmFor(24).name).toBe('A192KW');
        expect(keyWrapAlgorithmFor(32).name).toBe('A256KW');
        expect(() => keyWrapAlgorithmFor(20)).toThrow(CoseError);

    });

    it('grows the key by the eight bytes of the RFC 3394 check value', () => {

        const kek = unhex('849B57219DAE48DE646D07DBB533566E');

        expect(aesKeyWrap(kek, CEK[128])).toHaveLength(16 + 8);
        expect(aesKeyWrap(kek, CEK[256])).toHaveLength(32 + 8);

    });

});


// ------------------------------------------------------------ COSE_Mac ---

describe('COSE_Mac with recipients', () => {

    /** RFC 9052 Appendix C.5.4: HMAC 256/256 over a wrapped content key. */
    const C_5_4_KEK      = unhex('849B57219DAE48DE646D07DBB533566E976686457C1491BE3A76DCEA6C427188');
    const C_5_4_WRAPPED  = unhex('0B2C7CFCE04E98276342D6476A7723C090DFDD15F9A518E7736549E998370695E6D6A83B4AE507BB');
    const C_5_4_TAG      = unhex('BF48235E809B5C42E995F2B7D5FA13620E7ED834E337F6AA43DF161E49E9323E');

    it('reproduces the published tag of RFC 9052 Appendix C.5.4', () => {

        // The whole chain in one test: unwrap the content key with A256KW,
        // build the MAC_structure with the "MAC" context, and recompute the
        // tag the RFC prints.
        const cek        = aesKeyUnwrap(C_5_4_KEK, C_5_4_WRAPPED)!;
        const contentKey = CoseKey.fromSymmetricKey(cek, { algorithm: CoseAlgorithms.HMAC256_256 });

        const message = CoseMac.create(CONTENT, contentKey,
                                       [CoseRecipient.keyWrap(cek,
                                            CoseKey.fromSymmetricKey(C_5_4_KEK))]);

        expect(hex(message.tag)).toBe(hex(C_5_4_TAG));

        // ...and the MAC_structure differs from a COSE_Mac0's in one string.
        expect(hex(message.toBeMaced())).toBe('84' + '63' + '4D4143' + '43A10105' + '40' +
                                              '54' + hex(CONTENT));

    });

    it('verifies with the key-encryption key alone', () => {

        const cek        = aesKeyUnwrap(C_5_4_KEK, C_5_4_WRAPPED)!;
        const contentKey = CoseKey.fromSymmetricKey(cek, { algorithm: CoseAlgorithms.HMAC256_256 });
        const kek        = CoseKey.fromSymmetricKey(C_5_4_KEK);

        const message = CoseMac.parse(
                            CoseMac.create(CONTENT, contentKey,
                                           [CoseRecipient.keyWrap(cek, kek)]).toBytes());

        expect(message.verify(kek).verified).toBe(true);
        expect(message.verify(CoseKey.fromSymmetricKey(new Uint8Array(32))).verified).toBe(false);

    });

    it('is a COSE_Mac0 with ceremony when the single recipient is direct', () => {

        const key     = CoseKey.fromSymmetricKey(CEK[256], { algorithm: CoseAlgorithms.HMAC256_256 });
        const message = CoseMac.create(CONTENT, key, [CoseRecipient.direct(key)]);

        expect(message.recipients[0]!.protectedHeaderBytes).toHaveLength(0);
        expect(message.recipients[0]!.ciphertext).toHaveLength(0);
        expect(message.verify(key).verified).toBe(true);

    });

    it('delivers one content key to several recipients', () => {

        const cek        = CEK[256];
        const contentKey = CoseKey.fromSymmetricKey(cek, { algorithm: CoseAlgorithms.HMAC256_256 });

        const alice = CoseKey.fromSymmetricKey(unhex('00'.repeat(32)),
                                               { keyIdentifier: new TextEncoder().encode('alice') });
        const bob   = CoseKey.fromSymmetricKey(unhex('11'.repeat(16)),
                                               { keyIdentifier: new TextEncoder().encode('bob') });

        const message = CoseMac.parse(
                            CoseMac.create(CONTENT, contentKey,
                                           [CoseRecipient.keyWrap(cek, alice),
                                            CoseRecipient.keyWrap(cek, bob)]).toBytes());

        expect(message.recipients).toHaveLength(2);
        expect(message.recipients[0]!.algorithm?.name).toBe('A256KW');
        expect(message.recipients[1]!.algorithm?.name).toBe('A128KW');

        // Both get in, each through their own entry — and that is exactly the
        // property that makes the tag say nothing about which of them wrote it.
        expect(message.verify(alice).verified).toBe(true);
        expect(message.verify(bob).verified).toBe(true);

        expect(message.verify(CoseKey.fromSymmetricKey(unhex('22'.repeat(32)))).verified).toBe(false);

    });

    it('refuses a message with no recipients at all', () => {

        const key = CoseKey.fromSymmetricKey(CEK[256], { algorithm: CoseAlgorithms.HMAC256_256 });

        expect(() => CoseMac.create(CONTENT, key, [])).toThrow(/at least one recipient/u);

    });

    it('refuses a payload that was changed', () => {

        const key      = CoseKey.fromSymmetricKey(CEK[256], { algorithm: CoseAlgorithms.HMAC256_256 });
        const original = CoseMac.create(CONTENT, key, [CoseRecipient.direct(key)]);

        const tampered = new CoseMac(original.protectedHeaderBytes,
                                     original.unprotectedHeader,
                                     new TextEncoder().encode('This is the contenu.'),
                                     original.tag, original.recipients, original.isTagged);

        expect(tampered.verify(key).verified).toBe(false);

    });

});
