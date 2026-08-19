/*
 * Copyright (c) 2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr COSE <https://github.com/Vanaheimr/COSE.TS>
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * COSE_Mac0 [RFC 9052, Section 6.2] with HMAC [RFC 9053, Section 3.1].
 *
 * The vectors here are split in two on purpose, because RFC 9052 leaves a gap:
 * its only `COSE_Mac0` example, Appendix C.6.1, uses **AES-CBC-MAC** and not
 * HMAC, so there is no published message that pins both halves at once.
 *
 *   - **The structure** is pinned against C.6.1 all the same. Its 37 bytes are
 *     parsed, every field is checked, the message re-encodes to the identical
 *     bytes, and the MAC_structure built from its inputs is asserted. That
 *     covers everything except the primitive.
 *   - **The primitive** is pinned against RFC 4231, the canonical HMAC-SHA-2
 *     vectors, including the truncation `HMAC 256/64` asks for.
 *
 * What neither can reach — that the two implementations of this project build
 * the same COSE_Mac0 for the same inputs — is what the conformance suite is
 * for. A MAC is deterministic, so those bytes are directly comparable, with
 * none of the arrangements a signature needs.
 */

import { describe, expect, it }              from 'vitest';

import { cbor, CoseAlgorithms, CoseError,
         CoseHeaders, CoseKey, CoseMac0,
         hmac, KEY_TYPE_SYMMETRIC, macTag,
         tagsEqual }                         from '../src/index.ts';
import { CONTENT, hex, unhex }               from './vectors.ts';


// --------------------------------------------------- RFC 9052 Appendix C.6.1 --

/**
 * The example, assembled from the diagnostic notation the RFC prints:
 *
 *     17([ h'a1010f', {}, 'This is the content.', h'726043745027214f' ])
 *
 * Its stated size, 37 bytes, is the check on the assembly.
 */
const C_6_1 = unhex('D18443A1010FA054546869732069732074686520' +
                    '636F6E74656E742E48726043745027214F');

const C_6_1_TAG = unhex('726043745027214F');


describe('The one COSE_Mac0 example RFC 9052 prints', () => {

    it('is 37 bytes, as the RFC says', () => {

        expect(C_6_1.length).toBe(37);

    });

    it('parses field by field', () => {

        const message = CoseMac0.parse(C_6_1);

        expect(message.isTagged).toBe(true);
        expect(hex(message.protectedHeaderBytes)).toBe('A1010F');
        expect(message.unprotectedHeader.parameters).toHaveLength(0);
        expect(message.payload).not.toBeNull();
        expect(hex(message.payload!)).toBe(hex(CONTENT));
        expect(hex(message.tag)).toBe(hex(C_6_1_TAG));

        // Algorithm 15 is AES-MAC 256/64, which this implementation does not
        // provide. Reading a message is not the place to refuse it: the
        // identifier is recorded as it travelled, and only *using* it fails.
        expect(message.algorithm?.id).toBe(15);
        expect(message.algorithm?.family).toBe('none');

    });

    it('re-encodes to the identical bytes', () => {

        expect(hex(CoseMac0.parse(C_6_1).toBytes())).toBe(hex(C_6_1));

    });

    it('builds the MAC_structure the RFC defines', () => {

        // ["MAC0", h'a1010f', h'', 'This is the content.']
        //  84                array(4)
        //  64 4D414330       "MAC0"
        //  43 A1010F          the protected bucket, verbatim
        //  40                 no external data
        //  54 …               the payload, all 20 bytes of it
        expect(hex(CoseMac0.toBeMaced(unhex('A1010F'), CONTENT)))
            .toBe('84' + '644D414330' + '43A1010F' + '40' + '54' + hex(CONTENT));

    });

    it('differs from a Sig_structure in exactly the context string', () => {

        const maced = hex(CoseMac0.toBeMaced(unhex('A1010F'), CONTENT));

        // "MAC0" is 4 characters, "Signature1" is 10, and the rest is equal.
        expect(maced.slice(0, 2)).toBe('84');
        expect(maced).toContain('43A1010F4054');

    });

});


// ------------------------------------------------------------- RFC 4231 --

/** The published HMAC-SHA-2 vectors, key and data as the RFC prints them. */
const RFC4231 = [
    {
        name:   'Test Case 1',
        key:    '0b'.repeat(20),
        data:   '4869205468657265',
        sha256: 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7',
        sha384: 'afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59c' +
                'faea9ea9076ede7f4af152e8b2fa9cb6',
        sha512: '87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde' +
                'daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854',
    },
    {
        // A four-byte key: shorter than the hash output, which RFC 9053 only
        // SHOULD-nots. Refusing it would make this vector unreproducible.
        name:   'Test Case 2',
        key:    '4a656665',
        data:   '7768617420646f2079612077616e7420666f72206e6f7468696e673f',
        sha256: '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
        sha384: 'af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e' +
                '8e2240ca5e69e2c78b3239ecfab21649',
        sha512: '164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554' +
                '9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737',
    },
    {
        name:   'Test Case 3',
        key:    'aa'.repeat(20),
        data:   'dd'.repeat(50),
        sha256: '773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe',
        sha384: '88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b' +
                '2a5ab39dc13814b94e3ab6e101a34f27',
        sha512: 'fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39' +
                'bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb',
    },
    {
        // A key longer than the block size, which the primitive has to hash
        // before using — the one case a naive implementation gets wrong.
        name:   'Test Case 7',
        key:    'aa'.repeat(131),
        data:   Buffer.from('This is a test using a larger than block-size key ' +
                            'and a larger than block-size data. The key needs to ' +
                            'be hashed before being used by the HMAC algorithm.').toString('hex'),
        sha256: '9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2',
        sha384: '6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5' +
                'a678cc31e799176d3860e6110c46523e',
        sha512: 'e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944' +
                'b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58',
    },
] as const;


describe('The HMAC primitive against RFC 4231', () => {

    for (const vector of RFC4231) {

        it(`reproduces ${vector.name}`, () => {

            const key  = unhex(vector.key);
            const data = unhex(vector.data);

            expect(hex(hmac('sha256', key, data)).toLowerCase()).toBe(vector.sha256);
            expect(hex(hmac('sha384', key, data)).toLowerCase()).toBe(vector.sha384);
            expect(hex(hmac('sha512', key, data)).toLowerCase()).toBe(vector.sha512);

        });

    }

    it('truncates to the leftmost bits, as HMAC 256/64 asks', () => {

        const vector = RFC4231[0];
        const tag    = macTag('sha256', 8, unhex(vector.key), unhex(vector.data));

        expect(tag).toHaveLength(8);
        expect(hex(tag).toLowerCase()).toBe(vector.sha256.slice(0, 16));

    });

    it('refuses to truncate to more than there is', () => {

        expect(() => macTag('sha256', 64, unhex('00'), unhex('00'))).toThrow(/can not be truncated/u);

    });

});


// ------------------------------------------------------------ the messages --

const SECRET = unhex('849B57219DAE48DE646D07DBB533566E976686457C1491BE3A76DCEA6C427188');

const keyFor = (algorithm = CoseAlgorithms.HMAC256_256): CoseKey =>
    CoseKey.fromSymmetricKey(SECRET, { algorithm, keyIdentifier: unhex('3131') });


describe('Authenticating and verifying a COSE_Mac0', () => {

    it('round-trips through its bytes', () => {

        const key      = keyFor();
        const created  = CoseMac0.create(CONTENT, key);
        const message  = CoseMac0.parse(created.toBytes());

        expect(message.isTagged).toBe(true);
        expect(message.algorithm?.name).toBe('HMAC 256/256');
        expect(hex(message.keyIdentifier!)).toBe('3131');
        expect(message.tag).toHaveLength(32);
        expect(message.verify(key).verified).toBe(true);
        expect(hex(message.toBytes())).toBe(hex(created.toBytes()));

    });

    it('produces the tag width its algorithm names', () => {

        for (const [algorithm, width] of [[CoseAlgorithms.HMAC256_64,   8],
                                          [CoseAlgorithms.HMAC256_256, 32],
                                          [CoseAlgorithms.HMAC384_384, 48],
                                          [CoseAlgorithms.HMAC512_512, 64]] as const) {

            const key = keyFor(algorithm);

            expect(CoseMac0.create(CONTENT, key).tag, algorithm.name).toHaveLength(width);
            expect(CoseMac0.create(CONTENT, key).verify(key).verified, algorithm.name).toBe(true);

        }

    });

    it('is a prefix, not a different computation, when truncated', () => {

        // HMAC 256/64 is the leftmost 8 bytes of HMAC 256/256 over the very
        // same MAC_structure. A verifier that recomputed the short one some
        // other way would still interoperate with itself and nothing else.
        const short = CoseMac0.create(CONTENT, keyFor(CoseAlgorithms.HMAC256_64));
        const long  = CoseMac0.create(CONTENT, keyFor(CoseAlgorithms.HMAC256_256));

        // The protected buckets differ — they name different algorithms — so
        // the structures differ too. Compare the primitive directly instead.
        const structure = CoseMac0.toBeMaced(short.protectedHeaderBytes, CONTENT);

        expect(hex(short.tag)).toBe(hex(hmac('sha256', SECRET, structure)).slice(0, 16));
        expect(long.tag).toHaveLength(32);

    });

    it('refuses a payload that was changed', () => {

        const key      = keyFor();
        const created  = CoseMac0.create(CONTENT, key);
        const tampered = new CoseMac0(created.protectedHeaderBytes,
                                      created.unprotectedHeader,
                                      new TextEncoder().encode('This is the contenu.'),
                                      created.tag,
                                      created.isTagged);

        expect(tampered.verify(key).verified).toBe(false);

    });

    it('refuses a tag that was changed, in any single bit', () => {

        const key     = keyFor();
        const created = CoseMac0.create(CONTENT, key);

        for (const position of [0, 15, 31]) {

            const tag = Uint8Array.from(created.tag);
            tag[position] = (tag[position] ?? 0) ^ 0x01;

            const tampered = new CoseMac0(created.protectedHeaderBytes,
                                          created.unprotectedHeader,
                                          created.payload,
                                          tag,
                                          created.isTagged);

            expect(tampered.verify(key).verified, `byte ${String(position)}`).toBe(false);

        }

    });

    it('refuses another key', () => {

        const other = CoseKey.fromSymmetricKey(unhex('00'.repeat(32)),
                                               { algorithm: CoseAlgorithms.HMAC256_256 });

        expect(CoseMac0.create(CONTENT, keyFor()).verify(other).verified).toBe(false);

    });

    it('carries external additional authenticated data without transporting it', () => {

        const key      = keyFor();
        const aad      = unhex('11AA22BB33CC44DD55006699');
        const created  = CoseMac0.create(CONTENT, key, { externalAad: aad });

        expect(hex(created.toBytes())).not.toContain('11AA22BB');
        expect(created.verify(key, { externalAad: aad }).verified).toBe(true);
        expect(created.verify(key).verified).toBe(false);

    });

    it('keeps the same tag with the payload detached', () => {

        const key      = keyFor();
        const attached = CoseMac0.create(CONTENT, key);
        const detached = CoseMac0.create(CONTENT, key, { detachPayload: true });

        expect(hex(detached.tag)).toBe(hex(attached.tag));
        expect(detached.payload).toBeNull();
        expect(detached.verify(key, { detachedPayload: CONTENT }).verified).toBe(true);

        // Without the payload there is nothing to authenticate.
        expect(detached.verify(key).verified).toBe(false);

    });

    it('keeps the same tag untagged, because CBOR tag 17 is not covered', () => {

        const key      = keyFor();
        const tagged   = CoseMac0.create(CONTENT, key);
        const untagged = CoseMac0.create(CONTENT, key, { tagged: false });

        expect(hex(untagged.tag)).toBe(hex(tagged.tag));
        expect(untagged.toBytes()).toHaveLength(tagged.toBytes().length - 1);
        expect(CoseMac0.parse(untagged.toBytes()).verify(key).verified).toBe(true);

    });

});


describe('A MAC is not a signature, and the code says so', () => {

    it('refuses to authenticate with a signature algorithm', () => {

        const key = CoseKey.fromSymmetricKey(SECRET, { algorithm: CoseAlgorithms.ES256 });

        expect(() => CoseMac0.create(CONTENT, key)).toThrow(CoseError);
        expect(() => CoseMac0.create(CONTENT, key)).toThrow(/not a message authentication algorithm/u);

    });

    it('refuses to authenticate with a key that is not symmetric', () => {

        const elliptic = CoseKey.fromPrivateScalar(
                             CoseAlgorithms.ES256.curve ?? { id: 1, name: 'P-256', keyType: 2, fieldSize: 32, orderSize: 32 },
                             unhex('57C92077664146E876760C9520D054AA93C3AFB04E306705DB6090308507B4D3'),
                             { algorithm: CoseAlgorithms.HMAC256_256 });

        expect(() => CoseMac0.create(CONTENT, elliptic)).toThrow(/key type Symmetric/u);

    });

    it('refuses a message whose algorithm is not a MAC algorithm', () => {

        // The key names no algorithm, so nothing contradicts the message and
        // the refusal has to come from the family itself.
        const key     = CoseKey.fromSymmetricKey(SECRET);
        const forged  = new CoseMac0(new CoseHeaders([[cbor.int(1), cbor.int(-7)]]).toProtectedBytes(),
                                     null, CONTENT, new Uint8Array(32));

        const refused = forged.verify(key);

        expect(refused.verified).toBe(false);
        expect(refused.verified === false && refused.reason).toContain('not a message authentication algorithm');

    });

    it('refuses a key that contradicts the message before looking at anything else', () => {

        const key     = keyFor(CoseAlgorithms.HMAC256_256);
        const forged  = new CoseMac0(new CoseHeaders([[cbor.int(1), cbor.int(-7)]]).toProtectedBytes(),
                                     null, CONTENT, new Uint8Array(32));

        const refused = forged.verify(key);

        expect(refused.verified).toBe(false);
        expect(refused.verified === false && refused.reason).toContain("but the algorithm 'HMAC 256/256' was expected");

    });

    it('reads the AES-MAC example but will not pretend to verify it', () => {

        const refused = CoseMac0.parse(C_6_1).verify(CoseKey.fromSymmetricKey(SECRET));

        expect(refused.verified).toBe(false);
        expect(refused.verified === false && refused.reason).toContain('not a message authentication algorithm');

    });

    it('refuses a key whose algorithm is not the one being used', () => {

        // A key issued for HMAC 256/256 must not be talked into producing the
        // 64-bit tag, which is a downgrade the holder never agreed to.
        const key     = keyFor(CoseAlgorithms.HMAC256_256);
        const headers = new CoseHeaders([[cbor.int(1), cbor.int(CoseAlgorithms.HMAC256_64.id)]]);

        expect(() => CoseMac0.createWithHeaders(CONTENT, key, headers))
            .toThrow(/but the key names/u);

    });

});


describe('The symmetric COSE key [RFC 9053, Section 7.3]', () => {

    it('is key type 4 and carries its value under label -1', () => {

        const key = CoseKey.fromSymmetricKey(SECRET);

        expect(key.keyType).toBe(KEY_TYPE_SYMMETRIC);
        expect(key.k).not.toBeNull();
        expect(hex(key.k!)).toBe(hex(SECRET));

        const written = CoseKey.parse(key.toBytes());

        expect(written.keyType).toBe(KEY_TYPE_SYMMETRIC);
        expect(hex(written.k!)).toBe(hex(SECRET));

    });

    it('reads label -1 as the key value and not as a curve', () => {

        // The same label is the curve on an EC2 key and the public key on an
        // AKP one. Establishing the key type first is what keeps them apart.
        const key = CoseKey.parse(CoseKey.fromSymmetricKey(SECRET).toBytes());

        expect(key.curveId).toBeNull();
        expect(key.pub).toBeNull();

    });

    it('has no public half, and says so rather than returning itself', () => {

        expect(() => CoseKey.fromSymmetricKey(SECRET).publicKey()).toThrow(/no public half/u);
        expect(() => CoseKey.fromSymmetricKey(SECRET).publicKeyBytes()).toThrow(/no public key/u);

    });

    it('refuses a symmetric key without a key value', () => {

        expect(() => CoseKey.parse(cbor.map([[cbor.int(1), cbor.int(4)]])))
            .toThrow(/must carry its key value/u);

    });

    it('has a thumbprint over kty and k [RFC 9679, Section 4.4]', () => {

        const key = CoseKey.fromSymmetricKey(SECRET, { algorithm: CoseAlgorithms.HMAC256_256 });

        // The algorithm is not covered — unlike AKP, where it must be.
        expect(hex(key.thumbprint()))
            .toBe(hex(CoseKey.fromSymmetricKey(SECRET).thumbprint()));

        expect(key.thumbprint()).toHaveLength(32);

    });

});


describe('The comparison is constant time', () => {

    it('says equal only for equal tags', () => {

        expect(tagsEqual(unhex('0011223344556677'), unhex('0011223344556677'))).toBe(true);
        expect(tagsEqual(unhex('0011223344556677'), unhex('0011223344556678'))).toBe(false);

        // Differing in the *first* byte and in the last must be equally
        // indistinguishable, which is what the primitive underneath provides.
        expect(tagsEqual(unhex('0011223344556677'), unhex('0111223344556677'))).toBe(false);

    });

    it('says unequal for different lengths rather than throwing', () => {

        // The width follows from the algorithm and is public, so returning
        // early on it leaks nothing — but the underlying primitive throws on
        // mismatched lengths, and a verifier must not.
        expect(tagsEqual(unhex('00112233'), unhex('0011223344556677'))).toBe(false);

    });

});
