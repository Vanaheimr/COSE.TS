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
 * the same key the conformance vectors carry. It secures nothing. A second
 * one, further down, has three prime factors rather than two — the
 * multi-prime form of RFC 8230 Section 4, which nothing in reach generates
 * and OpenSSL does. It secures nothing either, and every claim it makes
 * about itself is recomputed below from the parameters printed here.
 */

import { constants, createPrivateKey,
         createPublicKey, sign, verify }       from 'node:crypto';

import { pow }                                 from '@noble/curves/abstract/modular.js';
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


// ------------------------------------------------- the multi-prime form ---

/**
 * A 2048-bit key with three prime factors, and never a secret.
 *
 * Nothing in reach generates one. `@noble` has no RSA at all; Bouncy Castle's
 * private key class is the two-prime CRT one; .NET has no multi-prime form
 * either. OpenSSL does — `openssl genrsa -primes 3 2048` — and this is its
 * output, read out of a PKCS #1 structure whose version field is 1 rather
 * than 0 for exactly this reason.
 *
 * `t` is the field worth reading twice: it does not invert this prime but
 * everything before it, "(r_1 * r_2 * ... * r_(i-1))^(-1) mod r_i" [RFC 8230,
 * Section 4], so here it inverts p·q modulo r_3.
 */
const MULTI_PRIME: RsaPrivateKey = {
    n:    unhex('BCB36284D8B8480ECD5173C3A45C735FEAC58571FADA993CA377A1E0819304B8' +
                '2DAFE070FD80803B4090422958205E01384EE6F7A24FD4FB9B914E8157BF2887' +
                '4D29B755E5E179BF7576B27DD8BB184BD1F5519D18FA98CCCB53F782A3782732' +
                '80B5DF3EBB5EF18D10F1C55CB5EF77ACCBD4674DBDF67B2AB49A406B31021E52' +
                '532A5C3EB4FDAC93EA122B3145933195C33F87F94D313D6CFD65E102A54BB5F1' +
                '11E208FABAF4A2B4BF11A5B9357495EF423B38718C0EFD59E1E4ADC3450C4E3C' +
                '406EF4AA78CE935A98C4AECDF27AED1F3971CED402A26481300D9562F4E14264' +
                '770D9BE4D1652EE4D046DD51658B61747C23406E02CA752D8683C5C75EEBA903'),
    e:    unhex('010001'),
    d:    unhex('3CA58EA95199D096E9481F63A6848C142CB934CD5029478CA4A10366CB5E3BEB' +
                '11CBEFDF80A9F70C941089230E8EC087B5D82E0532A663B645E66A8BC96EC790' +
                'CCACF69E65D694B18308160FBA434F68B6DF184EDC20F483812F7D86F6E25DF7' +
                '758ED38495C543AF5193303FE02FD5059A0FF034F68C6FFAD9D93D56A56C96AD' +
                '1B6DB544206E3BEFC36B248029B25A2492525BE2809B98D360E55619B4904430' +
                '38CC5CF9ADEE12357AA9B5465331862A363317E8B2B56CECF239AD5E76E56FEB' +
                'E1A285E53C06C9C1AB5988538734E23CD44F240F5B1AB2BFEB17E31B0FEAD63F' +
                '4D2445FF22C0DD19C177777E724629507F2262E66204C4A93691778A7E330421'),
    p:    unhex('079AA5EA2806BF86F41F00AFDD13CD547AD64B3E9BC86E7DE108D7D7F4B50157' +
                '49E145FC5AAAAD00CBD140083154B1C9F7B561E6D8B07C34E156EC7CCFDBECE6' +
                '4ABAF76834221D80CB905CFB1A9701379A45244A7FF5'),
    q:    unhex('077E3CB613734832ADD09A392A27135A76C45C99095F25C578D1EC42D84B6CEF' +
                'AD7A96975BAE84D04291809BB828D99803BE4634E40BE655D13C123103326F88' +
                'D491FF2EB28786ECC31386DB793EA981EE0F78EFF0AD'),
    dP:   unhex('0294A7AE7A7B1FD14B54A2450D40C534E0A38DD1E7C8F446E072C1DE56FC7F42' +
                '029EE3C3AB79B55149DAF062576BA913247078938203138456DDCB50E8B2790A' +
                '075EC0CCAAB4D1527EC3B5EABAB1790647E32357ED69'),
    dQ:   unhex('0200377DF71BA57FC2E21D0C7EB1087DF390E39909E39A566CB8C179E7FFDC0A' +
                'F42BF3E25EDCEF221D64750F1FD1E8A8AAF738100F850DF0847AA1F0EC859F3A' +
                'CE685DD7BE5C6A2EF6B8541E6EF5C895A55804572DD1'),
    qInv: unhex('0531B5EA58EBCEFD727D60B34FB58442E5E3AB2813ACE337AAA42AC769A9294F' +
                'CAA6F4A1D6BB413D2C405ABA36E5BF05F6EB5CA775BEFD3917CA6C6AFEDB59DA' +
                '29A9EC3F4DD6DB5633441465CF01654C66DF2E5297E6'),
    other: [{
        r:  unhex('034FD1F20CBE22ED6B924FF7C1C9E82402974866447E3FE1AC70CCD2F81CDA5D' +
                  '23DA0CC1C8B50407CFB6F0AD3F9C35B3F459FB8CE68CB6025BBD758E4F032154' +
                  'FCF1DC218A12E267C326D4CBE701ED76C27C05AC6253'),
        d:  unhex('013040F8AB6804A2CD6AE975D13EC3274122C761A40CE6A1F73F57D21226509B' +
                  '0245BB3443F1EA2B5F789870A4164C13738A6342D26E06D75BD2E700160CDA86' +
                  '646BEB82C1C93B24DF9CECDAEBE0FE36135F6CADCB6F'),
        t:  unhex('E792A46FF2BC4C7C0CA3F0516FE2201094C6DEFB78E91B7007C64F45D48D3328' +
                  '172E1AE52C658A801A89B8AD535922EEF2875D149B98CF0F6F5C11E42284F8F9' +
                  'E9BB76A870BA39D963229CE9189D9958CCDDFF3998'),
    }],
};


/** The same eleven numbers, as Node takes them: `oth` is RFC 7518's name for the array. */
const nodeMultiPrime = createPrivateKey({
                           format:  'jwk',
                           key:     {
                               kty:  'RSA',
                               n:    asJwk(MULTI_PRIME.n),
                               e:    asJwk(MULTI_PRIME.e),
                               d:    asJwk(MULTI_PRIME.d),
                               p:    asJwk(MULTI_PRIME.p),
                               q:    asJwk(MULTI_PRIME.q),
                               dp:   asJwk(MULTI_PRIME.dP),
                               dq:   asJwk(MULTI_PRIME.dQ),
                               qi:   asJwk(MULTI_PRIME.qInv),
                               oth:  MULTI_PRIME.other!.map(prime => ({
                                         r:  asJwk(prime.r),
                                         d:  asJwk(prime.d),
                                         t:  asJwk(prime.t),
                                     })),
                           },
                       });

const nodeMultiPrimePublic = createPublicKey(nodeMultiPrime);

/** An RSA parameter as the integer it is. */
const number = (value: Uint8Array): bigint => BigInt(`0x${hex(value)}`);

/** The further primes of {@link MULTI_PRIME}, which are one. */
const THIRD = MULTI_PRIME.other![0]!;


describe('a key with three primes [RFC 8230, Section 4]', () => {

    it('is the key it says it is', () => {

        // Everything these parameters claim, recomputed from them. Without
        // this the whole family would rest on one invocation of a key
        // generator, which is not something a reader of the file can check.
        const n = number(MULTI_PRIME.n);
        const d = number(MULTI_PRIME.d);
        const p = number(MULTI_PRIME.p);
        const q = number(MULTI_PRIME.q);
        const r = number(THIRD.r);

        expect(p * q * r).toBe(n);
        expect(number(MULTI_PRIME.dP)).toBe(d % (p - BigInt(1)));
        expect(number(MULTI_PRIME.dQ)).toBe(d % (q - BigInt(1)));
        expect(number(THIRD.d)).toBe(d % (r - BigInt(1)));

        // qInv inverts q modulo p, and t_3 inverts p·q modulo r_3.
        expect(number(MULTI_PRIME.qInv) * q % p).toBe(BigInt(1));
        expect(number(THIRD.t) * (p * q) % r).toBe(BigInt(1));

        // Three primes of 683, 683 and 682 bits, and the modulus Section 6.1
        // asks for as a minimum.
        expect([p, q, r].map(value => value.toString(2).length)).toStrictEqual([683, 683, 682]);
        expect(n.toString(2).length).toBe(2048);

    });

    for (const row of PKCS1) {

        it(`produces with ${row.name} the very bytes Node produces`, () => {

            const mine   = rsaSign(row.hash, 'pkcs1', MULTI_PRIME, CONTENT);
            const theirs = Uint8Array.from(sign(row.hash, CONTENT, nodeMultiPrime));

            expect(hex(mine)).toBe(hex(theirs));
            expect(rsaVerify(row.hash, 'pkcs1', MULTI_PRIME, CONTENT, theirs)).toBe(true);

        });

    }

    it('signs with PS256 what Node verifies, and verifies what Node signs', () => {

        const mine   = rsaSign('sha256', 'pss', MULTI_PRIME, CONTENT);
        const theirs = Uint8Array.from(sign('sha256', CONTENT,
                                            { key: nodeMultiPrime, ...PSS_PADDING }));

        expect(verify('sha256', CONTENT, { key: nodeMultiPrimePublic, ...PSS_PADDING }, mine)).toBe(true);
        expect(rsaVerify('sha256', 'pss', MULTI_PRIME, CONTENT, theirs)).toBe(true);

    });

    it('joins three primes into the number one exponentiation with d gives', () => {

        // What steps ii and v of RFC 8017 Section 5.1.2 are: an optimization
        // of the first form of RSASP1, s = m^d mod n, which is the definition
        // they have to agree with. The encoded message is recovered from the
        // signature with the public exponent, so the padding is not
        // reimplemented here.
        const n         = number(MULTI_PRIME.n);
        const signature = number(rsaSign('sha256', 'pkcs1', MULTI_PRIME, CONTENT));
        const message   = pow(signature, number(MULTI_PRIME.e), n);

        expect(pow(message, number(MULTI_PRIME.d), n)).toBe(signature);

    });

    it('refuses a third prime that does not belong to the modulus', () => {

        // The sentence counts the primes, because the two-prime one would
        // mislead here: p·q is not the modulus of this key and is not meant
        // to be. What this catches is a prime that was mistyped.
        expect(() => rsaSign('sha256', 'pkcs1',
                             { ...MULTI_PRIME, other: [{ ...THIRD, r: MULTI_PRIME.p }] },
                             CONTENT))
            .toThrow(/The 3 prime factors of this multi-prime RSA private key do not multiply/u);

    });

    it('is refused outright when its primes are read as two', () => {

        // Which is the arrangement this package had before it read the form:
        // the eight parameters taken alone describe a key whose primes do not
        // multiply to its modulus, and that is the sentence it got.
        const { other, ...twoPrime } = MULTI_PRIME;

        expect(other).toBeDefined();
        expect(() => rsaSign('sha256', 'pkcs1', twoPrime, CONTENT))
            .toThrow(/The prime factors of this RSA private key do not multiply/u);

    });

});


describe('a COSE key with three primes', () => {

    const keyOf = (): CoseKey =>
        CoseKey.fromRsaPrivateKey(MULTI_PRIME, { algorithm: CoseAlgorithms.PS256 });

    const labelsOf = (key: CoseKey): number[] => {

        const value = key.toCbor();

        if (value.type !== 'map')
            throw new Error('unreachable');

        return value.entries.map(([label]) => label.type === 'int' ? Number(label.value) : NaN);

    };

    it('writes the array at label -9, after the eight', () => {

        expect(labelsOf(keyOf()))
            .toStrictEqual([KeyLabel.keyType, KeyLabel.algorithm,
                            KeyLabel.n, KeyLabel.e, KeyLabel.rsaD,
                            KeyLabel.p, KeyLabel.q, KeyLabel.dP, KeyLabel.dQ,
                            KeyLabel.qInv, KeyLabel.other]);

    });

    it('survives a round trip through its own bytes', () => {

        const bytes = keyOf().toBytes();

        expect(hex(CoseKey.parse(bytes).toBytes())).toBe(hex(bytes));

    });

    it('signs and verifies through the COSE layer', () => {

        const key     = keyOf();
        const message = CoseSign1.sign(CONTENT, key);

        expect(message.signature.length).toBe(MULTI_PRIME.n.length);
        expect(CoseSign1.parse(message.toBytes()).verify(key.publicKey()).verified).toBe(true);

    });

    it('drops the further primes from its public half', () => {

        // "For public keys, the fields 'n' and 'e' MUST be present. All other
        // fields defined in the following table below MUST be absent" [RFC
        // 8230, Section 4] — and `other` is in that table, holding a prime
        // factor of the modulus, which is the most private thing in the key.
        expect(labelsOf(keyOf().publicKey()))
            .toStrictEqual([KeyLabel.keyType, KeyLabel.algorithm, KeyLabel.n, KeyLabel.e]);

    });

    it('keeps the further primes out of its thumbprint', () => {

        // RFC 9679 Section 4.3 names kty, n and e and nothing else, so a
        // three-prime key and the two-prime reading of it are one identity.
        const { other, ...twoPrime } = MULTI_PRIME;

        expect(other).toBeDefined();
        expect(hex(keyOf().thumbprint()))
            .toBe(hex(CoseKey.fromRsaPrivateKey(twoPrime, { algorithm: CoseAlgorithms.PS256 }).thumbprint()));

    });

    const rsaKey = (other: ReturnType<typeof cbor.array>): unknown => cbor.map([
        [cbor.int(KeyLabel.keyType), cbor.int(KEY_TYPE_RSA)],
        [cbor.int(KeyLabel.n),       cbor.bytes(MULTI_PRIME.n)],
        [cbor.int(KeyLabel.e),       cbor.bytes(MULTI_PRIME.e)],
        [cbor.int(KeyLabel.other),   other],
    ]);

    it('refuses an array that names no prime at all', () => {

        // A two-prime key must not carry the field: "the fields 'other',
        // 'r_i', 'd_i', and 't_i' MUST be absent". So an empty array is not
        // the two-prime form spelled differently — it is a key saying it has
        // further primes and naming none.
        expect(() => CoseKey.parse(rsaKey(cbor.array([])) as Parameters<typeof CoseKey.parse>[0]))
            .toThrow(/must name at least one prime, or the field must be absent/u);

    });

    it('refuses a prime that is missing one of its three fields', () => {

        const incomplete = cbor.array([cbor.map([
            [cbor.int(KeyLabel.rI), cbor.bytes(THIRD.r)],
            [cbor.int(KeyLabel.dI), cbor.bytes(THIRD.d)],
        ])]);

        expect(() => CoseKey.parse(rsaKey(incomplete) as Parameters<typeof CoseKey.parse>[0]))
            .toThrow(/carries no CRT coefficient t_i/u);

    });

    it('refuses an array of something that is not a prime', () => {

        expect(() => CoseKey.parse(rsaKey(cbor.array([cbor.int(3)])) as Parameters<typeof CoseKey.parse>[0]))
            .toThrow(/the entry of prime 3 is not one/u);

    });

});
