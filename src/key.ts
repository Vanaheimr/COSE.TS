/*
 * Copyright (c) 2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr COSE <https://github.com/Vanaheimr/COSE.TS>
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * A COSE key: elliptic curve (EC2), octet key pair (OKP) or algorithm key
 * pair (AKP) [RFC 9052 Section 7, RFC 9964].
 *
 * **The labels are not the same for all three.** On an EC2 or OKP key, −1 is
 * the curve and −2 is the x coordinate; on an AKP key, −1 is the public key
 * and −2 is the private one. A parser that switches on the label alone reads
 * an ML-DSA public key as a curve identifier and says nothing. Everything here
 * therefore establishes the key type first and interprets the rest in its
 * light.
 *
 * On EC2 and OKP keys, coordinates and private keys are fixed-width byte
 * strings whose **leading zeroes must be preserved** [RFC 9053, Section
 * 7.1.1]. A plain big-integer serialization shortens them roughly one time in
 * 256, and the resulting key is rejected by other implementations — a bug that
 * passes every test until the day it does not. Every width is therefore
 * checked on the way out of this module, and every value is padded on the way
 * in.
 */

import { algorithmFromCbor, algorithmToCbor } from './algorithm.ts';
import type { CoseAlgorithm }                 from './algorithm.ts';
import { cbor, decode, DETERMINISTIC,
         encode }                             from './cbor.ts';
import type { CborEntry, CborValue }          from './cbor.ts';
import { curveById, KEY_TYPE_EC2,
         KEY_TYPE_OKP }                       from './curve.ts';
import type { CoseCurve }                     from './curve.ts';
import { decompressY, digest, isOnCurve,
         publicKeyFor }                       from './ecdsa.ts';
import type { DigestAlgorithm }               from './ecdsa.ts';
import { eddsaPublicKeyFor }                  from './eddsa.ts';
import { CoseError }                          from './errors.ts';
import { MLDSA_SEED_SIZE, MLDSA_SIZES,
         mldsaPublicKeyFor }                  from './mldsa.ts';
import type { MldsaParameterSet }             from './mldsa.ts';


/** Key type 7, a key pair belonging to an algorithm rather than a curve. */
export const KEY_TYPE_AKP = 7;

/** Key type 4, a shared secret [RFC 9053, Section 7.3]. */
export const KEY_TYPE_SYMMETRIC = 4;


/**
 * The labels of a COSE *key*, which are not the labels of a header bucket:
 * 3 is the algorithm here and the content type there, 4 is the key operations
 * here and the key identifier there.
 */
export const KeyLabel = {
    keyType:        1,
    keyIdentifier:  2,
    algorithm:      3,
    keyOperations:  4,

    // EC2 and OKP.
    curve:         -1,
    x:             -2,
    y:             -3,
    d:             -4,

    // AKP [RFC 9964] — note the collision with the two above.
    pub:           -1,
    priv:          -2,

    // Symmetric [RFC 9053, Section 7.3] — and that is label −1 meaning a
    // third thing: the curve on an EC2 or OKP key, the public key on an AKP
    // one, and here the shared secret itself.
    k:             -1,
} as const;


/** Zero-pad a big-endian value to the given width, or refuse to shorten it. */
function padded(value: Uint8Array, width: number, what: string): Uint8Array {

    if (value.length === width)
        return value;

    if (value.length > width) {

        // Leading zeroes may be dropped; significant bytes may not.
        const excess = value.length - width;

        for (let index = 0; index < excess; index++) {
            if (value[index] !== 0)
                throw new CoseError(`The ${what} of a COSE key must be ${String(width)} bytes wide, but a ${String(value.length)}-byte value was given that does not fit!`);
        }

        return value.slice(excess);

    }

    const result = new Uint8Array(width);
    result.set(value, width - value.length);

    return result;

}


export interface CoseKeyParts {
    readonly keyIdentifier?:  Uint8Array | null;
    readonly algorithm?:      CoseAlgorithm | null;
}


interface CoseKeyFields {
    keyType:        number;
    keyIdentifier:  Uint8Array | null;
    algorithm:      CoseAlgorithm | null;
    keyOperations:  CborValue | null;
    curveId:        number | null;
    x:              Uint8Array | null;
    y:              Uint8Array | null;
    d:              Uint8Array | null;
    pub:            Uint8Array | null;
    priv:           Uint8Array | null;
    k:              Uint8Array | null;
    additional:     readonly CborEntry[];
}


export class CoseKey {

    public readonly keyType:        number;
    public readonly keyIdentifier:  Uint8Array | null;
    public readonly algorithm:      CoseAlgorithm | null;
    public readonly keyOperations:  CborValue | null;

    /** The curve identifier as it travels, also when it is not registered. */
    public readonly curveId:        number | null;

    /** EC2 and OKP: the coordinates and the private scalar. */
    public readonly x:              Uint8Array | null;
    public readonly y:              Uint8Array | null;
    public readonly d:              Uint8Array | null;

    /** AKP: the public key, and the private key — which is always the seed. */
    public readonly pub:            Uint8Array | null;
    public readonly priv:           Uint8Array | null;

    /** Symmetric: the shared secret. There is no public half of one. */
    public readonly k:              Uint8Array | null;

    /** Header parameters this implementation does not know, kept for the round trip. */
    public readonly additional:     readonly CborEntry[];


    private constructor(fields: CoseKeyFields) {
        this.keyType        = fields.keyType;
        this.keyIdentifier  = fields.keyIdentifier;
        this.algorithm      = fields.algorithm;
        this.keyOperations  = fields.keyOperations;
        this.curveId        = fields.curveId;
        this.x              = fields.x;
        this.y              = fields.y;
        this.d              = fields.d;
        this.pub            = fields.pub;
        this.priv           = fields.priv;
        this.k              = fields.k;
        this.additional     = fields.additional;
    }


    private get fields(): CoseKeyFields {
        return {
            keyType:        this.keyType,
            keyIdentifier:  this.keyIdentifier,
            algorithm:      this.algorithm,
            keyOperations:  this.keyOperations,
            curveId:        this.curveId,
            x:              this.x,
            y:              this.y,
            d:              this.d,
            pub:            this.pub,
            priv:           this.priv,
            k:              this.k,
            additional:     this.additional,
        };
    }

    private copy(overrides: Partial<CoseKeyFields>): CoseKey {
        return new CoseKey({ ...this.fields, ...overrides });
    }


    /** The curve of this key, or null when it names none or an unregistered one. */
    public get curve(): CoseCurve | null {
        return this.curveId === null ? null : curveById(this.curveId);
    }

    /**
     * Whether this key carries secret key material.
     *
     * A symmetric key is *always* secret — it has nothing else — which is why
     * `k` counts here beside the two private halves.
     */
    public get isPrivate(): boolean {
        return this.d !== null || this.priv !== null || this.k !== null;
    }


    /**
     * An elliptic curve key pair from its private scalar.
     *
     * The public point is recomputed rather than asked for, which is what the
     * examples of RFC 9052 do as well: a private COSE key always carries the
     * full pair, and the two halves cannot disagree.
     */
    public static fromPrivateScalar(curve: CoseCurve,
                                    d:     Uint8Array,
                                    parts: CoseKeyParts = {}): CoseKey {

        if (curve.keyType === KEY_TYPE_OKP)
            return CoseKey.fromOkpPrivateKey(curve, d, parts);

        const scalar       = padded(d, curve.orderSize ?? d.length, 'private key');
        const uncompressed = publicKeyFor(curve, scalar);
        const fieldSize    = curve.fieldSize ?? 0;

        return new CoseKey({
            ...empty(curve.keyType, parts),
            curveId:  curve.id,
            x:        uncompressed.slice(1, 1 + fieldSize),
            y:        uncompressed.slice(1 + fieldSize),
            d:        scalar,
        });

    }


    /**
     * An octet key pair from its private key.
     *
     * There is no `y`: an EdDSA public key is the whole of `x`.
     */
    public static fromOkpPrivateKey(curve: CoseCurve,
                                    d:     Uint8Array,
                                    parts: CoseKeyParts = {}): CoseKey {

        const width = curve.orderSize ?? d.length;

        if (d.length !== width)
            throw new CoseError(`The private key of a COSE key on the curve '${curve.name}' must be ${String(width)} bytes long, but was ${String(d.length)} bytes long!`);

        return new CoseKey({
            ...empty(KEY_TYPE_OKP, parts),
            curveId:  curve.id,
            x:        eddsaPublicKeyFor(curve, d),
            d,
        });

    }


    /**
     * An algorithm key pair from its seed.
     *
     * The private key of an ML-DSA COSE key is the 32-byte seed and nothing
     * else [RFC 9964] — not the expanded secret key, which is up to 4896 bytes
     * and derivable from it. The algorithm is not optional here: an ML-DSA
     * public key does not say which parameter set produced it, so a key that
     * did not name one could not be used, and could not even be identified,
     * since its thumbprint covers the algorithm.
     */
    public static fromAkpSeed(algorithm: CoseAlgorithm,
                              seed:      Uint8Array,
                              parts:     CoseKeyParts = {}): CoseKey {

        if (algorithm.parameterSet === null)
            throw new CoseError(`The COSE algorithm '${algorithm.name}' is not an algorithm key pair algorithm!`);

        if (seed.length !== MLDSA_SEED_SIZE)
            throw new CoseError(`The private key of an algorithm key pair is the seed and must be ${String(MLDSA_SEED_SIZE)} bytes long [RFC 9964], but was ${String(seed.length)} bytes long!`);

        return new CoseKey({
            ...empty(KEY_TYPE_AKP, { ...parts, algorithm }),
            pub:   mldsaPublicKeyFor(algorithm.parameterSet, seed),
            priv:  seed,
        });

    }


    /**
     * A public algorithm key pair, from the public key alone.
     *
     * This is the form a certificate hands over: a `SubjectPublicKeyInfo`
     * carries the public key and names the parameter set in its algorithm
     * identifier, and there is no seed to be had. The algorithm is required
     * for the same reason as in {@link fromAkpSeed} — the bytes do not say
     * which parameter set produced them, and the thumbprint covers `alg`.
     */
    public static fromAkpPublicKey(algorithm: CoseAlgorithm,
                                   pub:       Uint8Array,
                                   parts:     CoseKeyParts = {}): CoseKey {

        if (algorithm.parameterSet === null)
            throw new CoseError(`The COSE algorithm '${algorithm.name}' is not an algorithm key pair algorithm!`);

        const expected = MLDSA_SIZES[algorithm.parameterSet as MldsaParameterSet].publicKey;

        if (pub.length !== expected)
            throw new CoseError(`The public key of an '${algorithm.name}' algorithm key pair must be ${String(expected)} bytes long, but was ${String(pub.length)} bytes long!`);

        return new CoseKey({
            ...empty(KEY_TYPE_AKP, { ...parts, algorithm }),
            pub,
        });

    }


    /**
     * A symmetric key, which is a shared secret and nothing else.
     *
     * No length is enforced. RFC 9053 says an HMAC key SHOULD be as wide as
     * the hash output, which is advice about key management rather than a rule
     * about the primitive — RFC 2104 accepts any width and the published test
     * vectors of RFC 4231 include a four-byte key. What a caller must not do
     * is derive one from a password, and no length check would catch that.
     */
    public static fromSymmetricKey(k:     Uint8Array,
                                   parts: CoseKeyParts = {}): CoseKey {

        if (k.length === 0)
            throw new CoseError('A symmetric COSE key must carry a key value!');

        return new CoseKey({
            ...empty(KEY_TYPE_SYMMETRIC, parts),
            k,
        });

    }


    /** A public octet key pair, which is the whole of `x` and nothing else. */
    public static fromOkpPublicKey(curve: CoseCurve,
                                   x:     Uint8Array,
                                   parts: CoseKeyParts = {}): CoseKey {

        return new CoseKey({
            ...empty(KEY_TYPE_OKP, parts),
            curveId:  curve.id,
            x,
        });

    }


    /** A public elliptic curve key from its coordinates. */
    public static fromCoordinates(curve: CoseCurve,
                                  x:     Uint8Array,
                                  y:     Uint8Array,
                                  parts: CoseKeyParts = {}): CoseKey {

        const width = curve.fieldSize ?? x.length;

        return new CoseKey({
            ...empty(curve.keyType, parts),
            curveId:  curve.id,
            x:        padded(x, width, 'x coordinate'),
            y:        padded(y, width, 'y coordinate'),
        });

    }


    /**
     * Parse a COSE key.
     *
     * Widths are deliberately not checked here — only that the CBOR types are
     * what they claim to be. A key with a shortened coordinate is a real key
     * that a real implementation produced, and reading it is how one finds out
     * that it is wrong; the refusal belongs at the point where the key would
     * be used, where the error can say what was expected.
     *
     * A duplicate label takes its last value, which is what a lenient CBOR map
     * does everywhere else in COSE.
     */
    public static parse(input: CborValue | Uint8Array): CoseKey {

        const value = input instanceof Uint8Array ? decode(input) : input;

        if (value.type !== 'map')
            throw new CoseError(`A COSE key must be a CBOR map, but was a CBOR ${value.type}!`);

        // First the key type, because it decides what −1 and −2 mean. Reading
        // it in a pass of its own rather than relying on it arriving first
        // costs one loop and survives a map in any order.
        const keyType = CoseKey.readKeyType(value.entries);

        if (keyType === KEY_TYPE_AKP)
            return CoseKey.parseAkp(value.entries, keyType);

        if (keyType === KEY_TYPE_SYMMETRIC)
            return CoseKey.parseSymmetric(value.entries, keyType);

        return CoseKey.parseCurveKey(value.entries, keyType);

    }


    private static readKeyType(entries: readonly CborEntry[]): number {

        for (const [key, item] of entries) {

            if (key.type === 'int' && Number(key.value) === KeyLabel.keyType) {

                if (item.type !== 'int')
                    throw new CoseError('The key type of a COSE key must be an integer!');

                return Number(item.value);

            }

        }

        throw new CoseError('A COSE key must have a key type!');

    }


    private static parseCurveKey(entries: readonly CborEntry[], keyType: number): CoseKey {

        let keyIdentifier: Uint8Array | null    = null;
        let algorithm:     CoseAlgorithm | null = null;
        let keyOperations: CborValue | null     = null;
        let curveId:       number | null        = null;
        let x:             Uint8Array | null    = null;
        let yValue:        CborValue | null     = null;
        let d:             Uint8Array | null    = null;

        const additional: CborEntry[] = [];

        for (const [key, item] of entries) {

            if (key.type !== 'int') {
                additional.push([key, item]);
                continue;
            }

            switch (Number(key.value)) {

                case KeyLabel.keyType:
                    break;

                case KeyLabel.keyIdentifier:
                    keyIdentifier = bytesOf(item, 'The key identifier of a COSE key');
                    break;

                case KeyLabel.algorithm:
                    algorithm = algorithmFromCbor(item);
                    break;

                case KeyLabel.keyOperations:
                    if (item.type !== 'array')
                        throw new CoseError('The key operations of a COSE key must be an array!');
                    keyOperations = item;
                    break;

                case KeyLabel.curve:
                    if (item.type !== 'int')
                        throw new CoseError('The curve of a COSE key must be an integer!');
                    curveId = Number(item.value);
                    break;

                case KeyLabel.x:
                    x = bytesOf(item, 'The x coordinate of a COSE key');
                    break;

                case KeyLabel.y:
                    yValue = item;
                    break;

                case KeyLabel.d:
                    d = bytesOf(item, 'The private key of a COSE key');
                    break;

                default:
                    additional.push([key, item]);

            }

        }

        return new CoseKey({
            keyType,
            keyIdentifier,
            algorithm,
            keyOperations,
            curveId,
            x,
            y:     CoseKey.resolveY(yValue, x, curveId),
            d,
            pub:   null,
            priv:  null,
            k:     null,
            additional,
        });

    }


    private static parseSymmetric(entries: readonly CborEntry[], keyType: number): CoseKey {

        let keyIdentifier: Uint8Array | null    = null;
        let algorithm:     CoseAlgorithm | null = null;
        let keyOperations: CborValue | null     = null;
        let k:             Uint8Array | null    = null;

        const additional: CborEntry[] = [];

        for (const [key, item] of entries) {

            if (key.type !== 'int') {
                additional.push([key, item]);
                continue;
            }

            switch (Number(key.value)) {

                case KeyLabel.keyType:
                    break;

                case KeyLabel.keyIdentifier:
                    keyIdentifier = bytesOf(item, 'The key identifier of a COSE key');
                    break;

                case KeyLabel.algorithm:
                    algorithm = algorithmFromCbor(item);
                    break;

                case KeyLabel.keyOperations:
                    if (item.type !== 'array')
                        throw new CoseError('The key operations of a COSE key must be an array!');
                    keyOperations = item;
                    break;

                case KeyLabel.k:
                    k = bytesOf(item, 'The key value of a symmetric COSE key');
                    break;

                default:
                    additional.push([key, item]);
                    break;

            }

        }

        // "For symmetric keys, it is REQUIRED that 'k' be present in the
        // structure" [RFC 9053, Section 7.3] — and unlike a missing public
        // key there is nothing to recompute it from.
        if (k === null)
            throw new CoseError('A COSE key of key type Symmetric must carry its key value [RFC 9053, Section 7.3]!');

        return new CoseKey({
            keyType,
            keyIdentifier,
            algorithm,
            keyOperations,
            curveId: null,
            x:       null,
            y:       null,
            d:       null,
            pub:     null,
            priv:    null,
            k,
            additional,
        });

    }


    private static parseAkp(entries: readonly CborEntry[], keyType: number): CoseKey {

        let keyIdentifier: Uint8Array | null    = null;
        let algorithm:     CoseAlgorithm | null = null;
        let keyOperations: CborValue | null     = null;
        let pub:           Uint8Array | null    = null;
        let priv:          Uint8Array | null    = null;

        const additional: CborEntry[] = [];

        for (const [key, item] of entries) {

            if (key.type !== 'int') {
                additional.push([key, item]);
                continue;
            }

            switch (Number(key.value)) {

                case KeyLabel.keyType:
                    break;

                case KeyLabel.keyIdentifier:
                    keyIdentifier = bytesOf(item, 'The key identifier of a COSE key');
                    break;

                case KeyLabel.algorithm:
                    algorithm = algorithmFromCbor(item);
                    break;

                case KeyLabel.keyOperations:
                    if (item.type !== 'array')
                        throw new CoseError('The key operations of a COSE key must be an array!');
                    keyOperations = item;
                    break;

                case KeyLabel.pub:
                    pub = bytesOf(item, 'The public key of an algorithm key pair');
                    break;

                case KeyLabel.priv:
                    priv = bytesOf(item, 'The private key of an algorithm key pair');
                    break;

                default:
                    additional.push([key, item]);

            }

        }

        return new CoseKey({
            keyType,
            keyIdentifier,
            algorithm,
            keyOperations,
            curveId:  null,
            x:        null,
            y:        null,
            d:        null,
            pub,
            priv,
            k:     null,
            additional,
        });

    }


    /**
     * The y coordinate, which may travel as a byte string or as the parity bit
     * of a compressed point.
     */
    private static resolveY(value:   CborValue | null,
                            x:       Uint8Array | null,
                            curveId: number | null): Uint8Array | null {

        if (value === null)
            return null;

        if (value.type === 'bytes')
            return value.value;

        if (value.type === 'bool') {

            const curve = curveId === null ? null : curveById(curveId);

            if (curve === null)
                throw new CoseError('The y coordinate of a COSE key is a sign bit, which needs a known curve to be resolved!');

            if (x === null)
                throw new CoseError('The y coordinate of a COSE key is a sign bit, which needs the x coordinate to be resolved!');

            return decompressY(curve, x, value.value);

        }

        throw new CoseError('The y coordinate of a COSE key must be a byte string or a boolean sign bit!');

    }


    /**
     * A CBOR map holding this key.
     *
     * The labels are written in ascending encoded order — 1, 2, 3, 4, −1, −2,
     * −3, −4 — which happens to be exactly the deterministic order of
     * RFC 8949 Section 4.2.1, so a canonical re-encoding moves nothing.
     *
     * A key whose y arrived as a sign bit does *not* round-trip byte for byte:
     * y is always written as the byte string form, which every implementation
     * understands.
     */
    public toCbor(): CborValue {

        const entries: CborEntry[] = [
            [cbor.int(KeyLabel.keyType), cbor.int(this.keyType)],
        ];

        if (this.keyIdentifier !== null)
            entries.push([cbor.int(KeyLabel.keyIdentifier), cbor.bytes(this.keyIdentifier)]);

        if (this.algorithm !== null)
            entries.push([cbor.int(KeyLabel.algorithm), algorithmToCbor(this.algorithm)]);

        if (this.keyOperations !== null)
            entries.push([cbor.int(KeyLabel.keyOperations), this.keyOperations]);

        if (this.keyType === KEY_TYPE_AKP) {

            if (this.pub !== null)
                entries.push([cbor.int(KeyLabel.pub), cbor.bytes(this.pub)]);

            if (this.priv !== null)
                entries.push([cbor.int(KeyLabel.priv), cbor.bytes(this.priv)]);

        }

        // Encoding a symmetric key writes the secret out, always: there is no
        // half of it that can be published. RFC 9053 says as much — "care must
        // be taken that it is never transmitted accidentally or insecurely".
        else if (this.keyType === KEY_TYPE_SYMMETRIC) {

            if (this.k !== null)
                entries.push([cbor.int(KeyLabel.k), cbor.bytes(this.k)]);

        }

        else {

            if (this.curveId !== null)
                entries.push([cbor.int(KeyLabel.curve), cbor.int(this.curveId)]);

            if (this.x !== null)
                entries.push([cbor.int(KeyLabel.x), cbor.bytes(this.x)]);

            if (this.y !== null)
                entries.push([cbor.int(KeyLabel.y), cbor.bytes(this.y)]);

            if (this.d !== null)
                entries.push([cbor.int(KeyLabel.d), cbor.bytes(this.d)]);

        }

        entries.push(...this.additional);

        return cbor.map(entries);

    }


    /** The CBOR encoding of this key. */
    public toBytes(): Uint8Array {
        return encode(this.toCbor());
    }


    /**
     * This key without its private half.
     *
     * A symmetric key has no such form, and saying so is the point rather than
     * a limitation: RFC 9053 states outright that the structure "does not have
     * a form that contains only public members". Returning the key unchanged
     * here — which is what stripping `d` and `priv` from it would do — would
     * hand a caller the shared secret under a name promising the opposite.
     */
    public publicKey(): CoseKey {

        if (this.keyType === KEY_TYPE_SYMMETRIC)
            throw new CoseError('A COSE key of key type Symmetric has no public half [RFC 9053, Section 7.3]!');

        return this.copy({ d: null, priv: null });

    }


    /** A copy of this key carrying the given algorithm. */
    public withAlgorithm(algorithm: CoseAlgorithm): CoseKey {
        return this.copy({ algorithm });
    }


    private requireCurve(): CoseCurve {

        if (this.keyType !== KEY_TYPE_EC2 && this.keyType !== KEY_TYPE_OKP)
            throw new CoseError(`A COSE key of key type ${String(this.keyType)} has no elliptic curve!`);

        const curve = this.curve;

        if (curve === null)
            throw new CoseError(this.curveId === null
                ? 'This COSE key does not name an elliptic curve!'
                : `The elliptic curve ${String(this.curveId)} of this COSE key is not registered!`);

        return curve;

    }


    /**
     * The public key, in whatever form its key type gives it: `04 ‖ x ‖ y` for
     * EC2, the whole of `x` for OKP, `pub` for AKP.
     */
    public publicKeyBytes(): Uint8Array {

        if (this.keyType === KEY_TYPE_SYMMETRIC)
            throw new CoseError('A COSE key of key type Symmetric has no public key [RFC 9053, Section 7.3]!');

        if (this.keyType === KEY_TYPE_AKP) {

            if (this.pub === null)
                throw new CoseError('This COSE key carries no public key!');

            return this.pub;

        }

        const curve     = this.requireCurve();
        const fieldSize = curve.fieldSize ?? 0;

        if (this.x === null)
            throw new CoseError(`A COSE key on the curve '${curve.name}' needs its public key!`);

        if (this.keyType === KEY_TYPE_OKP) {

            if (this.x.length !== fieldSize)
                throw new CoseError(`The public key of a COSE key on the curve '${curve.name}' must be ${String(fieldSize)} bytes long, but was ${String(this.x.length)} bytes long!`);

            return this.x;

        }

        if (this.y === null)
            throw new CoseError(`A COSE key on the curve '${curve.name}' needs both of its coordinates!`);

        if (this.x.length !== fieldSize || this.y.length !== fieldSize)
            throw new CoseError(`The coordinates of a COSE key on the curve '${curve.name}' must be ${String(fieldSize)} bytes wide, including leading zeroes, but were ${String(this.x.length)} and ${String(this.y.length)} bytes wide!`);

        const uncompressed = new Uint8Array(1 + 2 * fieldSize);

        uncompressed[0] = 0x04;
        uncompressed.set(this.x, 1);
        uncompressed.set(this.y, 1 + fieldSize);

        if (!isOnCurve(curve, uncompressed))
            throw new CoseError(`The public key of this COSE key does not lie on the curve '${curve.name}'!`);

        return uncompressed;

    }


    /**
     * The secret this key holds: the scalar for EC2 and OKP, the seed for AKP,
     * the shared key itself for a symmetric one.
     */
    public privateKeyBytes(): Uint8Array {

        if (this.keyType === KEY_TYPE_SYMMETRIC) {

            if (this.k === null)
                throw new CoseError('This COSE key carries no key value!');

            return this.k;

        }

        if (this.keyType === KEY_TYPE_AKP) {

            if (this.priv === null)
                throw new CoseError('This COSE key carries no private key material!');

            if (this.priv.length !== MLDSA_SEED_SIZE)
                throw new CoseError(`The private key of an algorithm key pair is the seed and must be ${String(MLDSA_SEED_SIZE)} bytes long [RFC 9964], but was ${String(this.priv.length)} bytes long!`);

            return this.priv;

        }

        const curve     = this.requireCurve();
        const orderSize = curve.orderSize ?? 0;

        if (this.d === null)
            throw new CoseError('This COSE key carries no private key material!');

        if (this.d.length !== orderSize)
            throw new CoseError(`The private key of a COSE key on the curve '${curve.name}' must be ${String(orderSize)} bytes wide, including leading zeroes, but was ${String(this.d.length)} bytes wide!`);

        if (this.keyType === KEY_TYPE_EC2 && this.d.every(each => each === 0))
            throw new CoseError(`The private key of this COSE key is not within the group order of the curve '${curve.name}'!`);

        return this.d;

    }


    /**
     * The input of the COSE Key Thumbprint [RFC 9679, Section 3]: the required
     * parameters of this key, and nothing else, in deterministic encoding.
     *
     * Leaving out the optional parameters is what makes the thumbprint an
     * identity rather than a checksum — the public and the private half of one
     * key pair produce the same value, and adding a key identifier does not
     * change it.
     *
     * An AKP key is the exception that proves the rule: its algorithm *is*
     * required [RFC 9964], because an ML-DSA public key does not say which
     * parameter set produced it, and two keys of different strengths must not
     * be able to share an identity.
     */
    public thumbprintInput(): Uint8Array {

        if (this.keyType === KEY_TYPE_EC2) {

            if (this.curveId === null || this.x === null || this.y === null)
                throw new CoseError('The thumbprint of a COSE key of key type EC2 needs its curve and both of its coordinates!');

            return cbor.encode(cbor.map([
                [cbor.int(KeyLabel.keyType), cbor.int(this.keyType)],
                [cbor.int(KeyLabel.curve),   cbor.int(this.curveId)],
                [cbor.int(KeyLabel.x),       cbor.bytes(this.x)],
                [cbor.int(KeyLabel.y),       cbor.bytes(this.y)],
            ]), DETERMINISTIC);

        }

        if (this.keyType === KEY_TYPE_OKP) {

            if (this.curveId === null || this.x === null)
                throw new CoseError('The thumbprint of a COSE key of key type OKP needs its curve and its public key!');

            return cbor.encode(cbor.map([
                [cbor.int(KeyLabel.keyType), cbor.int(this.keyType)],
                [cbor.int(KeyLabel.curve),   cbor.int(this.curveId)],
                [cbor.int(KeyLabel.x),       cbor.bytes(this.x)],
            ]), DETERMINISTIC);

        }

        if (this.keyType === KEY_TYPE_AKP) {

            if (this.algorithm === null || this.pub === null)
                throw new CoseError('The thumbprint of a COSE key of key type AKP needs its algorithm and its public key!');

            return cbor.encode(cbor.map([
                [cbor.int(KeyLabel.keyType),   cbor.int(this.keyType)],
                [cbor.int(KeyLabel.algorithm), algorithmToCbor(this.algorithm)],
                [cbor.int(KeyLabel.pub),       cbor.bytes(this.pub)],
            ]), DETERMINISTIC);

        }

        if (this.keyType === KEY_TYPE_SYMMETRIC) {

            if (this.k === null)
                throw new CoseError('The thumbprint of a COSE key of key type Symmetric needs its key value!');

            // RFC 9679 Section 4.4 defines this, and Section 7 immediately
            // warns about it: the thumbprint of a symmetric key is a hash of
            // the secret, so a low-entropy one can simply be looked up in a
            // precomputed table. It is a usable identifier for a randomly
            // chosen key of at least 128 bits and MUST NOT be used for
            // passwords or anything like them.
            return cbor.encode(cbor.map([
                [cbor.int(KeyLabel.keyType), cbor.int(this.keyType)],
                [cbor.int(KeyLabel.k),       cbor.bytes(this.k)],
            ]), DETERMINISTIC);

        }

        throw new CoseError(`The thumbprint of a COSE key of key type ${String(this.keyType)} is not implemented!`);

    }


    /** The COSE Key Thumbprint [RFC 9679], untruncated. */
    public thumbprint(hash: DigestAlgorithm = 'sha256'): Uint8Array {
        return digest(hash, this.thumbprintInput());
    }


    /**
     * The leading bytes of the thumbprint, for use as a key identifier.
     *
     * Two properties make this worth preferring over a self-chosen prefix.
     * Everyone holding the public key can recompute it, so no registry is
     * needed beyond an agreement on its length. And because the thumbprint
     * covers the curve — or, for an algorithm key pair, the algorithm — a
     * signer who changes strength necessarily has a different key and
     * therefore a different identifier: a downgrade under an unchanged
     * identity is not expressible.
     */
    public thumbprintKeyIdentifier(length             = 8,
                                   hash:   DigestAlgorithm    = 'sha256'): Uint8Array {

        const value = this.thumbprint(hash);

        if (length < 1 || length > value.length)
            throw new CoseError(`A thumbprint key identifier must be between 1 and ${String(value.length)} bytes long, but ${String(length)} bytes were asked for!`);

        return value.slice(0, length);

    }


    /** A copy of this key whose key identifier is its own thumbprint. */
    public withThumbprintKeyIdentifier(length          = 8,
                                       hash:   DigestAlgorithm = 'sha256'): CoseKey {
        return this.copy({ keyIdentifier: this.thumbprintKeyIdentifier(length, hash) });
    }

}


/** The fields every key starts from, before its key type fills any in. */
function empty(keyType: number, parts: CoseKeyParts): CoseKeyFields {
    return {
        keyType,
        keyIdentifier:  parts.keyIdentifier ?? null,
        algorithm:      parts.algorithm     ?? null,
        keyOperations:  null,
        curveId:        null,
        x:              null,
        y:              null,
        d:              null,
        pub:            null,
        priv:           null,
        k:              null,
        additional:     [],
    };
}


function bytesOf(value: CborValue, what: string): Uint8Array {

    if (value.type !== 'bytes')
        throw new CoseError(`${what} must be a byte string!`);

    return value.value;

}
