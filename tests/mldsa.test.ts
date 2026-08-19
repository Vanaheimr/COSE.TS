/*
 * Copyright (c) 2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr COSE <https://github.com/Vanaheimr/COSE.TS>
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * ML-DSA [FIPS 204] as COSE uses it [RFC 9964].
 *
 * FIPS 204 publishes no small signature vector to paste in here, so the checks
 * are the properties that pin the encoding down: the sizes RFC 9964 prints,
 * the seed-derived key pair, the deterministic variant, and the fact that an
 * algorithm key pair reads its labels differently from every other COSE key.
 * The byte-for-byte agreement with a second implementation is established by
 * the cross-signing suite, where it belongs.
 */

import { describe, expect, it }              from 'vitest';

import { cbor, CoseAlgorithms, CoseCurves,
         CoseKey, CoseSign1, KEY_TYPE_AKP,
         KeyLabel, MLDSA_SEED_SIZE,
         MLDSA_SIZES, mldsaSign }            from '../src/index.ts';
import { hex, unhex }                        from './vectors.ts';


/** An arbitrary seed. It is a test key and secures nothing. */
const SEED = unhex('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F');

const PARAMETER_SETS = [
    { algorithm: CoseAlgorithms.MLDSA44, id: -48, name: 'ML-DSA-44' },
    { algorithm: CoseAlgorithms.MLDSA65, id: -49, name: 'ML-DSA-65' },
    { algorithm: CoseAlgorithms.MLDSA87, id: -50, name: 'ML-DSA-87' },
] as const;

const PAYLOAD = new TextEncoder().encode('This is the content.');


describe('the ML-DSA registry', () => {

    it.each(PARAMETER_SETS)('registers $name at the identifier RFC 9964 gives it', ({ algorithm, id, name }) => {

        expect(algorithm.id).toBe(id);
        expect(algorithm.name).toBe(name);
        expect(algorithm.family).toBe('mldsa');
        expect(algorithm.signing).toBe(true);

        // No curve and no digest: an ML-DSA key is a key pair of an algorithm,
        // and the algorithm signs the message whole.
        expect(algorithm.curve).toBeNull();
        expect(algorithm.hash).toBeNull();

    });

});


describe('an ML-DSA key', () => {

    it.each(PARAMETER_SETS)('has the public key size RFC 9964 prints — $name', ({ algorithm, name }) => {

        const key = CoseKey.fromAkpSeed(algorithm, SEED);

        expect(key.keyType).toBe(KEY_TYPE_AKP);
        expect(key.pub).toHaveLength(MLDSA_SIZES[name].publicKey);

    });

    it('keeps the private key at the 32-byte seed, not the expanded key', () => {

        const key = CoseKey.fromAkpSeed(CoseAlgorithms.MLDSA87, SEED);

        // The expanded secret key of ML-DSA-87 is 4896 bytes. RFC 9964 puts
        // the seed on the wire instead, and the whole key is then 32 bytes of
        // private material rather than five kilobytes.
        expect(key.priv).toHaveLength(MLDSA_SEED_SIZE);
        expect(hex(key.priv!)).toBe(hex(SEED));

        expect(() => CoseKey.fromAkpSeed(CoseAlgorithms.MLDSA87, unhex('0011')))
            .toThrow(/must be 32 bytes long/u);

    });

    it('is reproducible from its seed', () => {

        expect(hex(CoseKey.fromAkpSeed(CoseAlgorithms.MLDSA44, SEED).pub!))
            .toBe(hex(CoseKey.fromAkpSeed(CoseAlgorithms.MLDSA44, SEED).pub!));

    });

    it('reads label −1 as the public key and not as a curve', () => {

        // The trap of RFC 9964: on an EC2 or OKP key, −1 is the curve and −2
        // the x coordinate; on an AKP key they are the public and the private
        // key. A parser that switches on the label alone reads a 1312-byte
        // public key as a curve identifier and says nothing at all.
        const parsed = CoseKey.parse(CoseKey.fromAkpSeed(CoseAlgorithms.MLDSA44, SEED).toBytes());

        expect(parsed.keyType).toBe(KEY_TYPE_AKP);
        expect(parsed.pub).toHaveLength(1312);
        expect(parsed.priv).toHaveLength(32);
        expect(parsed.curveId).toBeNull();
        expect(parsed.x).toBeNull();

        // ...while a key that really is on a curve still reads −1 as one.
        const onCurve = CoseKey.parse(
            CoseKey.fromOkpPrivateKey(CoseCurves.Ed25519, new Uint8Array(32).fill(3)).toBytes());

        expect(onCurve.curveId).toBe(CoseCurves.Ed25519.id);
        expect(onCurve.pub).toBeNull();

    });

    it('round-trips through its own bytes', () => {

        const key    = CoseKey.fromAkpSeed(CoseAlgorithms.MLDSA65, SEED,
                                           { keyIdentifier: unhex('AABB') });
        const parsed = CoseKey.parse(key.toBytes());

        expect(hex(parsed.toBytes())).toBe(hex(key.toBytes()));
        expect(parsed.algorithm?.name).toBe('ML-DSA-65');

    });

    it('has a thumbprint that covers the algorithm, unlike every other key type', () => {

        const key = CoseKey.fromAkpSeed(CoseAlgorithms.MLDSA44, SEED);

        expect(hex(key.thumbprintInput()))
            .toBe(hex(cbor.encode(cbor.map([
                [cbor.int(KeyLabel.keyType),   cbor.int(KEY_TYPE_AKP)],
                [cbor.int(KeyLabel.algorithm), cbor.int(-48)],
                [cbor.int(KeyLabel.pub),       cbor.bytes(key.pub!)],
            ]), { mapKeys: 'sorted' })));

        // Which is the point: an ML-DSA public key does not say which
        // parameter set produced it, so two keys of different strengths must
        // not be able to share an identity. The private half is excluded as
        // everywhere else, so both halves keep the same one.
        expect(hex(key.thumbprint())).toBe(hex(key.publicKey().thumbprint()));

    });

});


describe('an ML-DSA COSE_Sign1', () => {

    it.each(PARAMETER_SETS)('signs, verifies and round-trips — $name', ({ algorithm, name }) => {

        const key     = CoseKey.fromAkpSeed(algorithm, SEED);
        const message = CoseSign1.sign(PAYLOAD, key);

        expect(message.signature).toHaveLength(MLDSA_SIZES[name].signature);
        expect(message.verify(key.publicKey())).toStrictEqual({ verified: true });

        const parsed = CoseSign1.parse(message.toBytes());

        expect(hex(parsed.toBytes())).toBe(hex(message.toBytes()));
        expect(parsed.verify(key.publicKey()).verified).toBe(true);

    });

    it('signs deterministically, which is what makes two implementations comparable', () => {

        // FIPS 204 allows a randomized and a deterministic variant and RFC
        // 9964 does not choose. This library always takes the deterministic
        // one, in which the per-signature randomness is 32 zero bytes.
        const key = CoseKey.fromAkpSeed(CoseAlgorithms.MLDSA44, SEED);

        expect(hex(CoseSign1.sign(PAYLOAD, key).toBytes()))
            .toBe(hex(CoseSign1.sign(PAYLOAD, key).toBytes()));

    });

    it('signs the Sig_structure itself and not a digest of it', () => {

        const key     = CoseKey.fromAkpSeed(CoseAlgorithms.MLDSA44, SEED);
        const message = CoseSign1.sign(PAYLOAD, key);

        expect(hex(message.signature))
            .toBe(hex(mldsaSign('ML-DSA-44', message.toBeSigned(), SEED)));

    });

    it('does not verify a message signed under a different parameter set', () => {

        const weaker  = CoseKey.fromAkpSeed(CoseAlgorithms.MLDSA44, SEED);
        const message = CoseSign1.sign(PAYLOAD, weaker);

        expect(message.verify(CoseKey.fromAkpSeed(CoseAlgorithms.MLDSA87, SEED).publicKey())
                     .verified).toBe(false);

    });

    it('costs what post-quantum costs, which is the argument for CBOR', () => {

        // A metrological reading of about thirty bytes, signed. In JSON the
        // signature would travel as base64 and grow by a further third; in
        // CBOR a byte string costs its bytes and a three-byte head.
        const reading = unhex('D9ACDC84C482221A0012D6870203A401C48220187B020203C48221185F0401');
        const message = CoseSign1.sign(reading, CoseKey.fromAkpSeed(CoseAlgorithms.MLDSA87, SEED));

        expect(reading.length).toBe(31);
        expect(message.toBytes().length).toBeGreaterThan(4627);
        expect(message.toBytes().length).toBeLessThan(4800);

    });

});
