/*
 * Copyright (c) 2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr COSE <https://github.com/Vanaheimr/COSE.TS>
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * RSA keys [RFC 8230] and the six RSA signature algorithms: RSASSA-PSS
 * (PS256, PS384, PS512) and RSASSA-PKCS1-v1_5 (RS256, RS384, RS512).
 *
 * There are no published COSE vectors for RSA to reproduce, so every signature
 * here is checked against a second, independent implementation instead: the
 * RSA of Node, which is OpenSSL. What this package signs Node has to verify
 * and the other way round, and RSASSA-PKCS1-v1_5 — which has no salt and no
 * randomness at all — has to come out of both as the very same bytes.
 *
 * Styx checks its own RSA exactly this way against the RSA of .NET, and the
 * cross-implementation conformance suite then holds those two to each other.
 * Three implementations, and no published vector needed.
 *
 * `node:crypto` appears here and nowhere in `src/`: the library is the `@noble`
 * family end to end, and `tests/bundle.test.ts` is what enforces that. A test
 * may use the platform, and here the platform is the point.
 *
 * The key is a fixed 2048-bit one of this suite's own, printed in full, and
 * the same key the conformance vectors carry. It secures nothing.
 */

import { constants, createPrivateKey,
         createPublicKey, sign, verify }       from 'node:crypto';

import { describe, expect, it }                from 'vitest';

import { cbor, CoseAlgorithms, CoseCurves,
         CoseKey, CoseSign1, KEY_TYPE_RSA,
         KeyLabel, rsaSign, rsaVerify }        from '../src/index.ts';
import type { CoseAlgorithm, DigestAlgorithm,
              RsaPrivateKey }                  from '../src/index.ts';
import { CONTENT, hex, unhex }                 from './vectors.ts';


/** A 2048-bit RSA key, generated once for this suite and never a secret. */
const RSA: RsaPrivateKey = {
    n:    unhex('A9444B7F1EAD3049F224C9B2D57C2F7AE79AAE794E54011C152C4DBA9F34536A' +
                '799D0359D859E787B8B44DAA781F76C55515EAC686AAC60E26100B10CF04F481' +
                '35B64D2478126EBE7CF4F64C8761D018EC26EBF1C6DEA8883D1A9DEBEF915324' +
                'CCBAA57757294225D805F33583129397BC7C33185993F778D24607C3F20D1D60' +
                'B47A5C3974427BC23B0F3727ECB60729B579C8363BDA8EDF5537AA18C417A964' +
                'F51B1CA8283F5836F4C95D48904850D1DB6CF7FE62C7407831A9C4F3E216938C' +
                '10A7BACC13BA5168F5E55966D8FA03B1089630E45B3E0005354544874EB045A2' +
                '6238354603E5E83BC28AD8F3478B4AEC4310034DDC0974598F99B623394252C3'),
    e:    unhex('010001'),
    d:    unhex('12AE0B48E1994A5176CC11884F600F9B5830ED5D4CC41F853A5EF3CB0B23CAAA' +
                'DEF5F1773A559DA41041B1AA84EC2FFED20783ABDA13C19CB11DA722F93DBA40' +
                '022DF6B07621CE9FEE09589F1477BA6FEDABD3F11039E54E77B3D6C6C15EFFD6' +
                '795385CC384DC0D38D5606C39A8DF3C4D493BE4DCB20F5B81B388845DB121072' +
                '3BC6CD2C8A647A3ACAF4204BD6FE9C5A8BF76D4394F84F7AFEC9A135FAE4616D' +
                '4507F223DCC57B9B7D0610815543EF3927767D526EADAE6AB1AE08C70DA2FF65' +
                '9E4D479EAE2023459DAFA71BAC715EFB3660E3343D2FD6C35CD5E58D0F08707D' +
                '79E30486D4637B85C5E5F4321BD2CA332C64F9EE4293D6E382312BD2A944F535'),
    p:    unhex('EEE7089DE483A7F45B1351C4C6238040406775108B947E8F9A16F4DA8267AA1A' +
                '5BA0A8FF7318D470000FFDFFFE1DCB5AA721771D7F3679C1339C0459105E686A' +
                'EDC02223E953746477FA32A40C2C5DEA680A5ECAA4DFC782F3310682F36746C2' +
                '93CC5ECC7F1B785D799CB0EC1BE47C376EB6F51450EBA975C73C4072F7F1D76D'),
    q:    unhex('B56174A7BC3CBE5844160B7060DEF835511C434A2350548B2FB7909ACB93A248' +
                '9E6D1575BDA6A25322E562C60A1861A45852A02745FF474B5E3BD24CAFA1A7D3' +
                '1DF3EF3C84B3F0F8C70057D35D0A1FBAA68F56F43B6B04A111107E8B8C3CD192' +
                '14E073C768FE78D07BBBA02431C2CDFFEF9D7247C1298706140D76F7FB3E84EF'),
    dP:   unhex('47431939E7F931B75D177533AA1ADADDCF984CBE23B4A6CFF519D5EDFC2A29FE' +
                '74C886C0B4377ADEF1D5D361720EB7231269941B735FEF8FA6F26A059B315E1A' +
                '4F53199BF6B4932A88F353F9C53BD2C3E246FDA19AEEB997A12D4590F8441D42' +
                '5B4E021523F130C5494A6927F4E601FB9305F6331A3441B74537FECD8C92523D'),
    dQ:   unhex('02719CB3C1DA83AA06C8D140A35D7DB4A2322249F66DD7A5C46FD1B7F4343A04' +
                '8675EBCB19520C6FD85184E22C32A5E623F68107E66E89145FE1A874B60D1488' +
                'C8A787BAA60312A517714EBD9F4C4A9F262D5A3B922D5FF3979A444A370A7EBC' +
                '5C21A60DB2C172F944218407D8CFCA1CBFAABC667118D123E8D3419E17B980EB'),
    qInv: unhex('EC4899C7F2D27C94FFE9767B1B5D4F6577A4FE44A03891447954BA00EA3B5511' +
                'FBA8E5805A12720B77DE322A0A565FC945011CEF2D74526CB577D4B03C63D373' +
                'CDEA605C93CAC2B63F34E009A98997A5910636E83E553A28B58C076CC2873BEB' +
                'CB80179D9181A2246813ABEC758EE9C9488ECBF0B72FDC8CB8EC99919FDC005E'),
};


/** The very same eight numbers, as Node takes them. */
const asJwk = (value: Uint8Array): string => Buffer.from(value).toString('base64url');

const nodePrivate = createPrivateKey({
                        format:  'jwk',
                        key:     {
                            kty:  'RSA',
                            n:    asJwk(RSA.n),
                            e:    asJwk(RSA.e),
                            d:    asJwk(RSA.d),
                            p:    asJwk(RSA.p),
                            q:    asJwk(RSA.q),
                            dp:   asJwk(RSA.dP),
                            dq:   asJwk(RSA.dQ),
                            qi:   asJwk(RSA.qInv),
                        },
                    });

const nodePublic  = createPublicKey(nodePrivate);

const PSS_PADDING = {
    padding:     constants.RSA_PKCS1_PSS_PADDING,
    saltLength:  constants.RSA_PSS_SALTLEN_DIGEST,
} as const;

const OTHER_CONTENT = unhex('54686973206973206E6F742E');


interface Row {
    readonly name:       string;
    readonly algorithm:  CoseAlgorithm;
    readonly hash:       DigestAlgorithm;
    readonly saltSize:   number;
}

const PSS: readonly Row[] = [
    { name: 'PS256', algorithm: CoseAlgorithms.PS256, hash: 'sha256', saltSize: 32 },
    { name: 'PS384', algorithm: CoseAlgorithms.PS384, hash: 'sha384', saltSize: 48 },
    { name: 'PS512', algorithm: CoseAlgorithms.PS512, hash: 'sha512', saltSize: 64 },
];

const PKCS1: readonly Row[] = [
    { name: 'RS256', algorithm: CoseAlgorithms.RS256, hash: 'sha256', saltSize: 0 },
    { name: 'RS384', algorithm: CoseAlgorithms.RS384, hash: 'sha384', saltSize: 0 },
    { name: 'RS512', algorithm: CoseAlgorithms.RS512, hash: 'sha512', saltSize: 0 },
];


/** A value with leading zeroes in front of it, as most RSA interfaces hand them out. */
function padded(value: Uint8Array, zeroes: number): Uint8Array {

    const result = new Uint8Array(value.length + zeroes);

    result.set(value, zeroes);

    return result;

}


// ----------------------------------------------- RSASSA-PKCS1-v1_5 ---

describe('RSASSA-PKCS1-v1_5, against the RSA of Node', () => {

    for (const row of PKCS1) {

        it(`produces with ${row.name} the very bytes Node produces`, () => {

            const mine   = rsaSign(row.hash, 'pkcs1', RSA, CONTENT);
            const theirs = Uint8Array.from(sign(row.hash, CONTENT, nodePrivate));

            expect(hex(mine)).toBe(hex(theirs));
            expect(verify(row.hash, CONTENT, nodePublic, mine)).toBe(true);
            expect(rsaVerify(row.hash, 'pkcs1', RSA, CONTENT, theirs)).toBe(true);

        });

        it(`refuses with ${row.name} a signature over other content`, () => {

            expect(rsaVerify(row.hash, 'pkcs1', RSA, OTHER_CONTENT,
                             rsaSign(row.hash, 'pkcs1', RSA, CONTENT))).toBe(false);

        });

    }

    it('is not interchangeable with the other padding', () => {

        // One primitive and two paddings: a verifier that tries the wrong one
        // sees a forgery rather than an error.
        expect(rsaVerify('sha256', 'pss', RSA, CONTENT,
                         rsaSign('sha256', 'pkcs1', RSA, CONTENT))).toBe(false);

        expect(rsaVerify('sha256', 'pkcs1', RSA, CONTENT,
                         rsaSign('sha256', 'pss', RSA, CONTENT))).toBe(false);

    });

    it('refuses a signature of the wrong width, and one that is no smaller than the modulus', () => {

        expect(rsaVerify('sha256', 'pkcs1', RSA, CONTENT, new Uint8Array(255))).toBe(false);
        expect(rsaVerify('sha256', 'pkcs1', RSA, CONTENT, new Uint8Array(256).fill(0xff))).toBe(false);
        expect(rsaVerify('sha256', 'pkcs1', RSA, CONTENT, new Uint8Array(256))).toBe(false);

    });

});


// ------------------------------------------------------- RSASSA-PSS ---

describe('RSASSA-PSS, against the RSA of Node', () => {

    for (const row of PSS) {

        it(`signs with ${row.name} what Node verifies, and verifies what Node signs`, () => {

            const mine   = rsaSign(row.hash, 'pss', RSA, CONTENT);
            const theirs = Uint8Array.from(sign(row.hash, CONTENT,
                                                { key: nodePrivate, ...PSS_PADDING }));

            expect(verify(row.hash, CONTENT, { key: nodePublic, ...PSS_PADDING }, mine)).toBe(true);
            expect(rsaVerify(row.hash, 'pss', RSA, CONTENT, theirs)).toBe(true);

            // The salt travels inside the signature. Node draws one at random,
            // so its bytes differ from ours; ours do not differ at all.
            expect(hex(rsaSign(row.hash, 'pss', RSA, CONTENT))).toBe(hex(mine));
            expect(hex(theirs)).not.toBe(hex(mine));

        });

        it(`takes a salt from the caller with ${row.name}`, () => {

            const salt   = new Uint8Array(row.saltSize).fill(0x2a);
            const salted = rsaSign(row.hash, 'pss', RSA, CONTENT, salt);

            expect(hex(salted)).not.toBe(hex(rsaSign(row.hash, 'pss', RSA, CONTENT)));
            expect(rsaVerify(row.hash, 'pss', RSA, CONTENT, salted)).toBe(true);
            expect(verify(row.hash, CONTENT, { key: nodePublic, ...PSS_PADDING }, salted)).toBe(true);

        });

        it(`refuses with ${row.name} a salt of any other width`, () => {

            // "The salt length is the same length as the hash function output"
            // [RFC 8230, Section 2]: a verifier recovers exactly that many
            // bytes, so a salt of another width is a signature nobody reads.
            expect(() => rsaSign(row.hash, 'pss', RSA, CONTENT, new Uint8Array(row.saltSize - 1)))
                .toThrow(/bytes long/u);

        });

    }

});


// ------------------------------------------------------- COSE_Sign1 ---

describe('COSE_Sign1 with an RSA key', () => {

    for (const row of [...PSS, ...PKCS1]) {

        it(`signs and verifies with ${row.name}`, () => {

            const key     = CoseKey.fromRsaPrivateKey(RSA, { algorithm: row.algorithm });
            const message = CoseSign1.sign(CONTENT, key);

            expect(message.algorithm?.name).toBe(row.name);
            expect(message.signature.length).toBe(RSA.n.length);
            expect(message.verify(key.publicKey()).verified).toBe(true);
            expect(CoseSign1.parse(message.toBytes()).verify(key.publicKey()).verified).toBe(true);

        });

    }

    it('is verified by Node from the Sig_structure alone', () => {

        // The strongest of these: what a COSE_Sign1 signature covers is the
        // Sig_structure, so a second implementation handed those bytes and
        // the signature must accept it knowing nothing about COSE.
        const key     = CoseKey.fromRsaPrivateKey(RSA, { algorithm: CoseAlgorithms.RS256 });
        const message = CoseSign1.sign(CONTENT, key);

        expect(verify('sha256',
                      CoseSign1.toBeSigned(message.protectedHeaderBytes, message.payload!, null),
                      nodePublic,
                      message.signature)).toBe(true);

    });

    it('refuses a message whose payload was changed', () => {

        const key     = CoseKey.fromRsaPrivateKey(RSA, { algorithm: CoseAlgorithms.PS256 });
        const message = CoseSign1.sign(CONTENT, key);
        const altered = new CoseSign1(message.protectedHeaderBytes,
                                      message.unprotectedHeader,
                                      OTHER_CONTENT,
                                      message.signature,
                                      message.isTagged);

        expect(altered.verify(key.publicKey()).verified).toBe(false);

    });

    it('does not let the two key shapes substitute for each other', () => {

        // ESP256 rather than ES256, which an RSA key fails earlier: a
        // deprecated identifier leaves the curve to the key, and an RSA key
        // has none to leave it.
        const rsa = CoseKey.fromRsaPrivateKey(RSA, { algorithm: CoseAlgorithms.ESP256 });
        const ec  = CoseKey.fromPrivateScalar(CoseCurves.P256,
                                              unhex('57C920776641466876760C9520D054AA93C3AFB04E3067025D8264CA2871ED4D'),
                                              { algorithm: CoseAlgorithms.PS256 });

        expect(() => CoseSign1.sign(CONTENT, rsa)).toThrow(/parameters of an RSA key/u);
        expect(() => CoseSign1.sign(CONTENT, ec)).toThrow(/needs an RSA key/u);

    });

});


// ---------------------------------------------------------- the keys ---

describe('RSA keys [RFC 8230, Section 4]', () => {

    it('round-trip through CBOR unchanged', () => {

        const key = CoseKey.fromRsaPrivateKey(RSA);

        expect(hex(CoseKey.parse(key.toBytes()).toBytes())).toBe(hex(key.toBytes()));
        expect(key.keyType).toBe(KEY_TYPE_RSA);
        expect(key.isPrivate).toBe(true);

    });

    it('write the eight parameters at the labels of Table 4, in order', () => {

        const decoded = cbor.decode(CoseKey.fromRsaPrivateKey(RSA).toBytes());
        const labels  = decoded.type === 'map'
                            ? decoded.entries.map(([label]) => label.type === 'int' ? Number(label.value) : null)
                            : [];

        expect(labels).toEqual([KeyLabel.keyType, -1, -2, -3, -4, -5, -6, -7, -8]);

    });

    it('keep nothing private in the public half', () => {

        // "For public keys, the fields 'n' and 'e' MUST be present. All other
        // fields defined in the following table below MUST be absent."
        const half = CoseKey.fromRsaPrivateKey(RSA).publicKey();

        expect(half.isPrivate).toBe(false);
        expect([half.d, half.p, half.q, half.dP, half.dQ, half.qInv])
            .toEqual([null, null, null, null, null, null]);
        expect(hex(half.n!)).toBe(hex(RSA.n));
        expect(hex(half.e!)).toBe(hex(RSA.e));

    });

    it('have one thumbprint for both halves, over the key type, n and e', () => {

        const key = CoseKey.fromRsaPrivateKey(RSA);

        expect(hex(key.thumbprint())).toBe(hex(key.publicKey().thumbprint()));
        expect(hex(key.thumbprintInput())).toContain(hex(RSA.n));
        expect(hex(key.thumbprintInput())).toContain(hex(RSA.e));
        expect(hex(key.thumbprintInput())).not.toContain(hex(RSA.d));

    });

    it('refuse a parameter that is not in the fewest octets', () => {

        // The thumbprint is computed over these bytes as they stand, so a
        // modulus with a leading zero would be a second identity for one key.
        const key = cbor.map([
            [cbor.int(KeyLabel.keyType), cbor.int(KEY_TYPE_RSA)],
            [cbor.int(KeyLabel.n),       cbor.bytes(padded(RSA.n, 1))],
            [cbor.int(KeyLabel.e),       cbor.bytes(RSA.e)],
        ]);

        expect(() => CoseKey.parse(key)).toThrow(/minimum number of octets/u);

    });

    it('refuse a key without its modulus and its public exponent', () => {

        const key = cbor.map([
            [cbor.int(KeyLabel.keyType), cbor.int(KEY_TYPE_RSA)],
            [cbor.int(KeyLabel.n),       cbor.bytes(RSA.n)],
        ]);

        expect(() => CoseKey.parse(key)).toThrow(/modulus n and its public exponent/u);

    });

    it('strip leading zeroes a caller brought along, and refuse a zero', () => {

        expect(hex(CoseKey.fromRsaPrivateKey({ ...RSA, n: padded(RSA.n, 2) }).n!)).toBe(hex(RSA.n));
        expect(() => CoseKey.fromRsaPublicKey(new Uint8Array(4), RSA.e)).toThrow(/must not be zero/u);

    });

    it('refuse to sign without the CRT parameters a COSE key carries', () => {

        const key = CoseKey.parse(cbor.map([
            [cbor.int(KeyLabel.keyType), cbor.int(KEY_TYPE_RSA)],
            [cbor.int(KeyLabel.n),       cbor.bytes(RSA.n)],
            [cbor.int(KeyLabel.e),       cbor.bytes(RSA.e)],
            [cbor.int(KeyLabel.rsaD),    cbor.bytes(RSA.d)],
        ]));

        expect(() => key.signingKey()).toThrow(/prime factor p/u);
        expect(hex(CoseKey.parse(key.toBytes()).d!)).toBe(hex(RSA.d));

    });

    it('refuse the accessors that promise one value', () => {

        const key = CoseKey.fromRsaPrivateKey(RSA);

        expect(() => key.privateKeyBytes()).toThrow(/signingKey/u);
        expect(() => key.publicKeyBytes()).toThrow(/verificationKey/u);

    });

    it('refuse a modulus of fewer than 2048 bits', () => {

        // "A key size of 2048 bits or larger MUST be used with these
        // algorithms" [RFC 8230, Section 6.1].
        expect(() => rsaVerify('sha256', 'pss', { n: new Uint8Array(128).fill(0xff), e: RSA.e },
                               CONTENT, new Uint8Array(128)))
            .toThrow(/at least 2048 bits/u);

    });

    it('refuse an exponent that is not one', () => {

        expect(() => rsaVerify('sha256', 'pkcs1', { n: RSA.n, e: Uint8Array.of(0x01) },
                               CONTENT, new Uint8Array(256)))
            .toThrow(/not an exponent/u);

    });

    it('refuse primes that do not multiply to the modulus', () => {

        expect(() => rsaSign('sha256', 'pkcs1', { ...RSA, q: RSA.p }, CONTENT))
            .toThrow(/do not multiply to its modulus/u);

    });

});
