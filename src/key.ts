/*
 * Copyright (c) 2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr COSE <https://github.com/Vanaheimr/COSE.TS>
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * A COSE key: elliptic curve (EC2), octet key pair (OKP), algorithm key pair
 * (AKP) or RSA [RFC 9052 Section 7, RFC 9964, RFC 8230].
 *
 * **The labels are not the same for all of them.** On an EC2 or OKP key, −1 is
 * the curve and −2 is the x coordinate; on an AKP key, −1 is the public key
 * and −2 is the private one; on an RSA key, −1 is the modulus and −2 the
 * public exponent. A parser that switches on the label alone reads an ML-DSA
 * public key as a curve identifier and says nothing. Everything here therefore
 * establishes the key type first and interprets the rest in its light.
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
import { isEcdhCurve, montgomeryPublicKeyFor } from './ecdh.ts';
import { CoseError }                          from './errors.ts';
import { MLDSA_SEED_SIZE, MLDSA_SIZES,
         mldsaPublicKeyFor }                  from './mldsa.ts';
import type { MldsaParameterSet }             from './mldsa.ts';
import type { RsaOtherPrime, RsaPrivateKey,
              RsaPublicKey }                 from './rsa.ts';


/** Key type 7, a key pair belonging to an algorithm rather than a curve. */
export const KEY_TYPE_AKP = 7;

/** Key type 4, a shared secret [RFC 9053, Section 7.3]. */
export const KEY_TYPE_SYMMETRIC = 4;

/** Key type 3, an RSA key [RFC 8230, Section 4]. */
export const KEY_TYPE_RSA = 3;


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

    // RSA [RFC 8230, Section 4], where −1 means a fourth thing. Note −3 and
    // −4 especially: the private exponent of an RSA key sits where the y
    // coordinate of an EC2 key does, and its first prime factor where that
    // key's private scalar does.
    n:             -1,
    e:             -2,
    rsaD:          -3,
    p:             -4,
    q:             -5,
    dP:            -6,
    dQ:            -7,
    qInv:          -8,
    other:         -9,

    // The three labels of a prime after the second. They are registered as
    // key type parameters of RSA like the eight above [RFC 8230, Section
    // 5.3], and they are the only ones here that never appear at the top
    // level of a key: "each of the primes is represented as a map containing
    // the fields 'r_i', 'd_i', and 't_i'", and `other` is the array of those
    // maps.
    rI:            -10,
    dI:            -11,
    tI:            -12,
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
    n:              Uint8Array | null;
    e:              Uint8Array | null;
    p:              Uint8Array | null;
    q:              Uint8Array | null;
    dP:             Uint8Array | null;
    dQ:             Uint8Array | null;
    qInv:           Uint8Array | null;
    other:          CborValue | null;
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

    /**
     * RSA: the modulus, the public exponent and five of the seven parameters
     * of a two-prime private key. The sixth is `d` above, which an EC2 key
     * uses for its scalar — one field, two labels, told apart by the key type
     * like everything else here.
     */
    public readonly n:              Uint8Array | null;
    public readonly e:              Uint8Array | null;
    public readonly p:              Uint8Array | null;
    public readonly q:              Uint8Array | null;
    public readonly dP:             Uint8Array | null;
    public readonly dQ:             Uint8Array | null;
    public readonly qInv:           Uint8Array | null;

    /**
     * RSA: the primes after the second, as they travel — an array of maps,
     * kept whole rather than taken apart.
     *
     * Each map carries r_i, d_i and t_i, and may carry something this
     * implementation has never heard of, which keeping the array whole is
     * what preserves. The three it computes with are read where the signing
     * key is assembled, the way `keyOperations` above is kept as it came and
     * read where it is used.
     */
    public readonly other:          CborValue | null;

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
        this.n              = fields.n;
        this.e              = fields.e;
        this.p              = fields.p;
        this.q              = fields.q;
        this.dP             = fields.dP;
        this.dQ             = fields.dQ;
        this.qInv           = fields.qInv;
        this.other          = fields.other;
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
            n:              this.n,
            e:              this.e,
            p:              this.p,
            q:              this.q,
            dP:             this.dP,
            dQ:             this.dQ,
            qInv:           this.qInv,
            other:          this.other,
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
     * There is no `y`: an EdDSA public key is the whole of `x`, and so is an
     * X25519 or X448 one. Which of the two computes it follows from the
     * curve — Ed25519 and X25519 share a field and not a public key.
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
            x:        isEcdhCurve(curve) ? montgomeryPublicKeyFor(curve, d)
                                         : eddsaPublicKeyFor(curve, d),
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


    /**
     * An RSA private key from the eight parameters of RFC 8230 Section 4, and
     * the primes after the second where there are any.
     *
     * All eight, because that is what a COSE key carries: "for private keys
     * with two primes ... all other fields MUST be present". A private key
     * without its CRT parameters is not a thing this format can hold, which is
     * why they are required here rather than recomputed. A key with further
     * primes carries all eight as well — "for private keys with more than two
     * primes, all fields MUST be present" — and the further primes beside
     * them, each in a map of its own.
     *
     * Every parameter is written in the fewest octets that represent it, and
     * leading zeroes a caller brought along — from a fixed-width buffer, as
     * most RSA interfaces hand them out — are dropped on the way in.
     */
    public static fromRsaPrivateKey(key:   RsaPrivateKey,
                                    parts: CoseKeyParts = {}): CoseKey {

        return new CoseKey({
            ...empty(KEY_TYPE_RSA, parts),
            n:     minimalInteger(key.n,    'modulus n'),
            e:     minimalInteger(key.e,    'public exponent e'),
            d:     minimalInteger(key.d,    'private exponent d'),
            p:     minimalInteger(key.p,    'prime factor p'),
            q:     minimalInteger(key.q,    'prime factor q'),
            dP:    minimalInteger(key.dP,   'CRT exponent dP'),
            dQ:    minimalInteger(key.dQ,   'CRT exponent dQ'),
            qInv:  minimalInteger(key.qInv, 'CRT coefficient qInv'),
            other: otherPrimesToCbor(key.other),
        });

    }


    /** An RSA public key: the modulus, the public exponent, and nothing else. */
    public static fromRsaPublicKey(n:     Uint8Array,
                                   e:     Uint8Array,
                                   parts: CoseKeyParts = {}): CoseKey {

        return new CoseKey({
            ...empty(KEY_TYPE_RSA, parts),
            n:  minimalInteger(n, 'modulus n'),
            e:  minimalInteger(e, 'public exponent e'),
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

        if (keyType === KEY_TYPE_RSA)
            return CoseKey.parseRsa(value.entries, keyType);

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
            n:     null,
            e:     null,
            p:     null,
            q:     null,
            dP:    null,
            dQ:    null,
            qInv:  null,
            other: null,
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
            n:       null,
            e:       null,
            p:       null,
            q:       null,
            dP:      null,
            dQ:      null,
            qInv:    null,
            other:   null,
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
            n:     null,
            e:     null,
            p:     null,
            q:     null,
            dP:    null,
            dQ:    null,
            qInv:  null,
            other: null,
            additional,
        });

    }


    private static parseRsa(entries: readonly CborEntry[], keyType: number): CoseKey {

        let keyIdentifier: Uint8Array | null    = null;
        let algorithm:     CoseAlgorithm | null = null;
        let keyOperations: CborValue | null     = null;
        let n:             Uint8Array | null    = null;
        let e:             Uint8Array | null    = null;
        let d:             Uint8Array | null    = null;
        let p:             Uint8Array | null    = null;
        let q:             Uint8Array | null    = null;
        let dP:            Uint8Array | null    = null;
        let dQ:            Uint8Array | null    = null;
        let qInv:          Uint8Array | null    = null;
        let other:         CborValue | null     = null;

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

                case KeyLabel.n:
                    n = rsaInteger(item, 'modulus n');
                    break;

                case KeyLabel.e:
                    e = rsaInteger(item, 'public exponent e');
                    break;

                case KeyLabel.rsaD:
                    d = rsaInteger(item, 'private exponent d');
                    break;

                case KeyLabel.p:
                    p = rsaInteger(item, 'prime factor p');
                    break;

                case KeyLabel.q:
                    q = rsaInteger(item, 'prime factor q');
                    break;

                case KeyLabel.dP:
                    dP = rsaInteger(item, 'CRT exponent dP');
                    break;

                case KeyLabel.dQ:
                    dQ = rsaInteger(item, 'CRT exponent dQ');
                    break;

                case KeyLabel.qInv:
                    qInv = rsaInteger(item, 'CRT coefficient qInv');
                    break;

                // Read for its shape and then kept as it came. The three
                // parameters inside each map are read where they are computed
                // with; what is refused here is the array being something
                // other than primes.
                case KeyLabel.other:
                    otherPrimesOf(item);
                    other = item;
                    break;

                default:
                    additional.push([key, item]);

            }

        }

        // "For public keys, the fields 'n' and 'e' MUST be present"
        // [RFC 8230, Section 4] — and a private key is a public key with more
        // parameters rather than instead of them, so this holds for both. The
        // CRT parameters are required of a private key by the same section and
        // are checked where they are used, which is the one place that can say
        // what was expected of them.
        if (n === null || e === null)
            throw new CoseError('A COSE key of key type RSA must carry its modulus n and its public exponent e [RFC 8230, Section 4]!');

        return new CoseKey({
            keyType,
            keyIdentifier,
            algorithm,
            keyOperations,
            curveId:  null,
            x:        null,
            y:        null,
            d,
            pub:      null,
            priv:     null,
            k:        null,
            n,
            e,
            p,
            q,
            dP,
            dQ,
            qInv,
            other,
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

        // The eight parameters of RFC 8230 Section 4 and the further primes
        // after them, in the order of their labels, which for negative
        // integers is also their encoded order.
        else if (this.keyType === KEY_TYPE_RSA) {

            if (this.n !== null)
                entries.push([cbor.int(KeyLabel.n), cbor.bytes(this.n)]);

            if (this.e !== null)
                entries.push([cbor.int(KeyLabel.e), cbor.bytes(this.e)]);

            if (this.d !== null)
                entries.push([cbor.int(KeyLabel.rsaD), cbor.bytes(this.d)]);

            if (this.p !== null)
                entries.push([cbor.int(KeyLabel.p), cbor.bytes(this.p)]);

            if (this.q !== null)
                entries.push([cbor.int(KeyLabel.q), cbor.bytes(this.q)]);

            if (this.dP !== null)
                entries.push([cbor.int(KeyLabel.dP), cbor.bytes(this.dP)]);

            if (this.dQ !== null)
                entries.push([cbor.int(KeyLabel.dQ), cbor.bytes(this.dQ)]);

            if (this.qInv !== null)
                entries.push([cbor.int(KeyLabel.qInv), cbor.bytes(this.qInv)]);

            if (this.other !== null)
                entries.push([cbor.int(KeyLabel.other), this.other]);

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
     *
     * An RSA key loses seven parameters rather than one, which is what RFC
     * 8230 Section 4 requires of a public key: "the fields 'n' and 'e' MUST be
     * present. All other fields defined in the following table below MUST be
     * absent." The seventh is the `other` array, which is in that table like
     * the rest and holds the most private thing in the key: a prime factor of
     * the modulus.
     */
    public publicKey(): CoseKey {

        if (this.keyType === KEY_TYPE_SYMMETRIC)
            throw new CoseError('A COSE key of key type Symmetric has no public half [RFC 9053, Section 7.3]!');

        return this.copy({ d: null, priv: null, p: null, q: null, dP: null, dQ: null, qInv: null, other: null });

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

        if (this.keyType === KEY_TYPE_RSA)
            throw new CoseError('The public key of a COSE key of key type RSA is a modulus and an exponent rather than one byte string: ask it for its verificationKey()!');

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

        if (this.keyType === KEY_TYPE_RSA)
            throw new CoseError('The private key of a COSE key of key type RSA is eight parameters rather than one byte string: ask it for its signingKey()!');

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
     * The private key material a signature algorithm is handed: one value for
     * EC2, OKP and AKP keys, and the eight parameters of RFC 8230 Section 4
     * for an RSA key.
     *
     * Two shapes rather than one, because an RSA signature needs the modulus
     * and the CRT parameters beside the private exponent — a scalar handed to
     * it would be a key only in the sense that it is a number.
     */
    public signingKey(): Uint8Array | RsaPrivateKey {
        return this.keyType === KEY_TYPE_RSA
                   ? rsaPrivateKeyOf(this)
                   : this.privateKeyBytes();
    }


    /** The public key material a verification is handed, in the same two shapes. */
    public verificationKey(): Uint8Array | RsaPublicKey {

        if (this.keyType !== KEY_TYPE_RSA)
            return this.publicKeyBytes();

        if (this.n === null || this.e === null)
            throw new CoseError('A COSE key of key type RSA verifies with its modulus n and its public exponent e [RFC 8230, Section 4]!');

        return { n: this.n, e: this.e };

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

        if (this.keyType === KEY_TYPE_RSA) {

            if (this.n === null || this.e === null)
                throw new CoseError('The thumbprint of a COSE key of key type RSA needs its modulus and its public exponent!');

            return cbor.encode(cbor.map([
                [cbor.int(KeyLabel.keyType), cbor.int(this.keyType)],
                [cbor.int(KeyLabel.n),       cbor.bytes(this.n)],
                [cbor.int(KeyLabel.e),       cbor.bytes(this.e)],
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
        n:              null,
        e:              null,
        p:              null,
        q:              null,
        dP:             null,
        dQ:             null,
        qInv:           null,
        other:          null,
        additional:     [],
    };
}


/**
 * Read an RSA key parameter: a byte string holding an unsigned big-endian
 * integer in "the minimum number of octets needed to represent the value"
 * [RFC 8230, Section 4].
 *
 * This is the one encoding rule the parser enforces rather than leaving to the
 * point of use, and the thumbprint is the reason: it is computed over these
 * bytes as they stand, so a modulus with a leading zero and the same modulus
 * without it would be two identities for one key. A leading zero is therefore
 * refused here rather than stripped — unlike on the way in from a caller,
 * where {@link minimalInteger} does strip it, because there the canonical form
 * is this library's to produce.
 */
function rsaInteger(value: CborValue, what: string): Uint8Array {

    const bytes = bytesOf(value, `The ${what} of an RSA key`);

    if (bytes.length === 0 || bytes[0] === 0x00)
        throw new CoseError(`The ${what} of an RSA key must be encoded in the minimum number of octets, without leading zeroes [RFC 8230, Section 4]!`);

    return bytes;

}


/** An RSA parameter in the fewest octets that represent it, zero refused. */
function minimalInteger(value: Uint8Array, what: string): Uint8Array {

    let first = 0;

    while (first < value.length && value[first] === 0x00)
        first++;

    if (first === value.length)
        throw new CoseError(`The ${what} of an RSA key must not be zero!`);

    return first === 0 ? value : value.slice(first);

}


/**
 * The primes after the second, out of the array they travel in.
 *
 * What this refuses is a key that claims the multi-prime form and does not
 * carry it. An empty array is such a key: RFC 8230 Section 4 lets a two-prime
 * key have no `other` field at all — "the fields 'other', 'r_i', 'd_i', and
 * 't_i' MUST be absent" — so an array of no primes is not the two-prime form
 * written differently. It is a key saying it has further primes and naming
 * none.
 */
function otherPrimesOf(value: CborValue): readonly RsaOtherPrime[] {

    if (value.type !== 'array')
        throw new CoseError('The further primes of a multi-prime RSA key must be an array of maps [RFC 8230, Section 4]!');

    if (value.items.length === 0)
        throw new CoseError('The further primes of a multi-prime RSA key must name at least one prime, or the field must be absent [RFC 8230, Section 4]!');

    return value.items.map((item, index) => {

        const which = `of prime ${String(3 + index)}`;

        if (item.type !== 'map')
            throw new CoseError(`The further primes of a multi-prime RSA key are maps, and the entry ${which} is not one [RFC 8230, Section 4]!`);

        const required = (label: number, what: string): Uint8Array => {

            const found = item.entries.find(([key]) => key.type === 'int' && Number(key.value) === label);

            if (found === undefined)
                throw new CoseError(`A prime of a multi-prime RSA key carries r_i, d_i and t_i [RFC 8230, Section 4], and the map ${which} carries no ${what}!`);

            return rsaInteger(found[1], `${what} ${which}`);

        };

        return {
            r:  required(KeyLabel.rI, 'prime factor r_i'),
            d:  required(KeyLabel.dI, 'exponent d_i'),
            t:  required(KeyLabel.tI, 'CRT coefficient t_i'),
        };

    });

}


/** The further primes of a caller's key, as the array they travel in. */
function otherPrimesToCbor(primes: readonly RsaOtherPrime[] | undefined): CborValue | null {

    if (primes === undefined || primes.length === 0)
        return null;

    return cbor.array(primes.map(prime => cbor.map([
        [cbor.int(KeyLabel.rI), cbor.bytes(minimalInteger(prime.r, 'prime factor r_i'))],
        [cbor.int(KeyLabel.dI), cbor.bytes(minimalInteger(prime.d, 'exponent d_i'))],
        [cbor.int(KeyLabel.tI), cbor.bytes(minimalInteger(prime.t, 'CRT coefficient t_i'))],
    ])));

}


/** The eight parameters of an RSA private key and its further primes, or what is missing. */
function rsaPrivateKeyOf(key: CoseKey): RsaPrivateKey {

    const named = [['modulus n',            key.n],
                   ['public exponent e',    key.e],
                   ['private exponent d',   key.d],
                   ['prime factor p',       key.p],
                   ['prime factor q',       key.q],
                   ['CRT exponent dP',      key.dP],
                   ['CRT exponent dQ',      key.dQ],
                   ['CRT coefficient qInv', key.qInv]] as const;

    const missing = named.filter(([, value]) => value === null).map(([name]) => name);

    if (missing.length > 0)
        throw new CoseError(`A COSE key of key type RSA signs with every parameter of a two-prime private key [RFC 8230, Section 4], and this one carries no ${missing.join(' and no ')}!`);

    return {
        n:     key.n!,
        e:     key.e!,
        d:     key.d!,
        p:     key.p!,
        q:     key.q!,
        dP:    key.dP!,
        dQ:    key.dQ!,
        qInv:  key.qInv!,
        other: key.other === null ? undefined : otherPrimesOf(key.other),
    };

}


function bytesOf(value: CborValue, what: string): Uint8Array {

    if (value.type !== 'bytes')
        throw new CoseError(`${what} must be a byte string!`);

    return value.value;

}
