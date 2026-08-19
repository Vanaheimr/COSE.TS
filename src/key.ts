/*
 * Copyright (c) 2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr COSE <https://github.com/Vanaheimr/COSE.TS>
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * A COSE key [RFC 9052, Section 7], of key type EC2.
 *
 * Coordinates and private keys are fixed-width byte strings whose **leading
 * zeroes must be preserved** [RFC 9053, Section 7.1.1]. A plain big-integer
 * serialization shortens them roughly one time in 256, and the resulting key
 * is rejected by other implementations — a bug that passes every test until
 * the day it does not. Every width is therefore checked on the way out of this
 * module, and every value is padded on the way in.
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
import { CoseError }                          from './errors.ts';


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
    curve:         -1,
    x:             -2,
    y:             -3,
    d:             -4,
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


export class CoseKey {

    public readonly keyType:        number;
    public readonly keyIdentifier:  Uint8Array | null;
    public readonly algorithm:      CoseAlgorithm | null;
    public readonly keyOperations:  CborValue | null;

    /** The curve identifier as it travels, also when it is not registered. */
    public readonly curveId:        number | null;

    public readonly x:              Uint8Array | null;
    public readonly y:              Uint8Array | null;
    public readonly d:              Uint8Array | null;

    /** Header parameters this implementation does not know, kept for the round trip. */
    public readonly additional:     readonly CborEntry[];


    private constructor(fields: {
        keyType:        number;
        keyIdentifier:  Uint8Array | null;
        algorithm:      CoseAlgorithm | null;
        keyOperations:  CborValue | null;
        curveId:        number | null;
        x:              Uint8Array | null;
        y:              Uint8Array | null;
        d:              Uint8Array | null;
        additional:     readonly CborEntry[];
    }) {
        this.keyType        = fields.keyType;
        this.keyIdentifier  = fields.keyIdentifier;
        this.algorithm      = fields.algorithm;
        this.keyOperations  = fields.keyOperations;
        this.curveId        = fields.curveId;
        this.x              = fields.x;
        this.y              = fields.y;
        this.d              = fields.d;
        this.additional     = fields.additional;
    }


    /** The curve of this key, or null when it names none or an unregistered one. */
    public get curve(): CoseCurve | null {
        return this.curveId === null ? null : curveById(this.curveId);
    }

    /** Whether this key carries private key material. */
    public get isPrivate(): boolean {
        return this.d !== null;
    }


    /**
     * A key pair from its private scalar.
     *
     * The public point is recomputed rather than asked for, which is what the
     * examples of RFC 9052 do as well: a private COSE key always carries the
     * full pair, and the two halves cannot disagree.
     */
    public static fromPrivateScalar(curve: CoseCurve,
                                    d:     Uint8Array,
                                    parts: CoseKeyParts = {}): CoseKey {

        const scalar       = padded(d, curve.orderSize ?? d.length, 'private key');
        const uncompressed = publicKeyFor(curve, scalar);
        const fieldSize    = curve.fieldSize ?? 0;

        return new CoseKey({
            keyType:        curve.keyType,
            keyIdentifier:  parts.keyIdentifier ?? null,
            algorithm:      parts.algorithm     ?? null,
            keyOperations:  null,
            curveId:        curve.id,
            x:              uncompressed.slice(1, 1 + fieldSize),
            y:              uncompressed.slice(1 + fieldSize),
            d:              scalar,
            additional:     [],
        });

    }


    /** A public key from its coordinates. */
    public static fromCoordinates(curve: CoseCurve,
                                  x:     Uint8Array,
                                  y:     Uint8Array,
                                  parts: CoseKeyParts = {}): CoseKey {

        const width = curve.fieldSize ?? x.length;

        return new CoseKey({
            keyType:        curve.keyType,
            keyIdentifier:  parts.keyIdentifier ?? null,
            algorithm:      parts.algorithm     ?? null,
            keyOperations:  null,
            curveId:        curve.id,
            x:              padded(x, width, 'x coordinate'),
            y:              padded(y, width, 'y coordinate'),
            d:              null,
            additional:     [],
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

        let keyType:       number | null        = null;
        let keyIdentifier: Uint8Array | null    = null;
        let algorithm:     CoseAlgorithm | null = null;
        let keyOperations: CborValue | null     = null;
        let curveId:       number | null        = null;
        let x:             Uint8Array | null    = null;
        let yValue:        CborValue | null     = null;
        let d:             Uint8Array | null    = null;

        const additional: CborEntry[] = [];

        for (const [key, item] of value.entries) {

            if (key.type !== 'int') {
                additional.push([key, item]);
                continue;
            }

            switch (Number(key.value)) {

                case KeyLabel.keyType:
                    if (item.type !== 'int')
                        throw new CoseError('The key type of a COSE key must be an integer!');
                    keyType = Number(item.value);
                    break;

                case KeyLabel.keyIdentifier:
                    if (item.type !== 'bytes')
                        throw new CoseError('The key identifier of a COSE key must be a byte string!');
                    keyIdentifier = item.value;
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
                    if (item.type !== 'bytes')
                        throw new CoseError('The x coordinate of a COSE key must be a byte string!');
                    x = item.value;
                    break;

                case KeyLabel.y:
                    yValue = item;
                    break;

                case KeyLabel.d:
                    if (item.type !== 'bytes')
                        throw new CoseError('The private key of a COSE key must be a byte string!');
                    d = item.value;
                    break;

                default:
                    additional.push([key, item]);

            }

        }

        if (keyType === null)
            throw new CoseError('A COSE key must have a key type!');

        return new CoseKey({
            keyType,
            keyIdentifier,
            algorithm,
            keyOperations,
            curveId,
            x,
            y:  CoseKey.resolveY(yValue, x, curveId),
            d,
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

        if (this.curveId !== null)
            entries.push([cbor.int(KeyLabel.curve), cbor.int(this.curveId)]);

        if (this.x !== null)
            entries.push([cbor.int(KeyLabel.x), cbor.bytes(this.x)]);

        if (this.y !== null)
            entries.push([cbor.int(KeyLabel.y), cbor.bytes(this.y)]);

        if (this.d !== null)
            entries.push([cbor.int(KeyLabel.d), cbor.bytes(this.d)]);

        entries.push(...this.additional);

        return cbor.map(entries);

    }


    /** The CBOR encoding of this key. */
    public toBytes(): Uint8Array {
        return encode(this.toCbor());
    }


    /** This key without its private half. */
    public publicKey(): CoseKey {

        return new CoseKey({
            keyType:        this.keyType,
            keyIdentifier:  this.keyIdentifier,
            algorithm:      this.algorithm,
            keyOperations:  this.keyOperations,
            curveId:        this.curveId,
            x:              this.x,
            y:              this.y,
            d:              null,
            additional:     this.additional,
        });

    }


    /** A copy of this key carrying the given algorithm. */
    public withAlgorithm(algorithm: CoseAlgorithm): CoseKey {

        return new CoseKey({
            keyType:        this.keyType,
            keyIdentifier:  this.keyIdentifier,
            algorithm,
            keyOperations:  this.keyOperations,
            curveId:        this.curveId,
            x:              this.x,
            y:              this.y,
            d:              this.d,
            additional:     this.additional,
        });

    }


    private requireEc2Curve(): CoseCurve {

        if (this.keyType !== KEY_TYPE_EC2)
            throw new CoseError(`Only COSE keys of key type EC2 are supported, but this one is of key type ${String(this.keyType)}!`);

        const curve = this.curve;

        if (curve === null)
            throw new CoseError(this.curveId === null
                ? 'This COSE key does not name an elliptic curve!'
                : `The elliptic curve ${String(this.curveId)} of this COSE key is not registered!`);

        return curve;

    }


    /**
     * The public point as `04 ‖ x ‖ y`, with both widths and the curve
     * membership checked.
     */
    public publicKeyBytes(): Uint8Array {

        const curve     = this.requireEc2Curve();
        const fieldSize = curve.fieldSize ?? 0;

        if (this.x === null || this.y === null)
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


    /** The private scalar, with its width checked. */
    public privateKeyBytes(): Uint8Array {

        const curve     = this.requireEc2Curve();
        const orderSize = curve.orderSize ?? 0;

        if (this.d === null)
            throw new CoseError('This COSE key carries no private key material!');

        if (this.d.length !== orderSize)
            throw new CoseError(`The private key of a COSE key on the curve '${curve.name}' must be ${String(orderSize)} bytes wide, including leading zeroes, but was ${String(this.d.length)} bytes wide!`);

        if (this.d.every(each => each === 0))
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
     * covers the curve, a signer who changes algorithm necessarily has a
     * different key and therefore a different identifier — an algorithm
     * downgrade under an unchanged identity is not expressible.
     */
    public thumbprintKeyIdentifier(length: number             = 8,
                                   hash:   DigestAlgorithm    = 'sha256'): Uint8Array {

        const value = this.thumbprint(hash);

        if (length < 1 || length > value.length)
            throw new CoseError(`A thumbprint key identifier must be between 1 and ${String(value.length)} bytes long, but ${String(length)} bytes were asked for!`);

        return value.slice(0, length);

    }


    /** A copy of this key whose key identifier is its own thumbprint. */
    public withThumbprintKeyIdentifier(length: number          = 8,
                                       hash:   DigestAlgorithm = 'sha256'): CoseKey {

        const identifier = this.thumbprintKeyIdentifier(length, hash);

        return new CoseKey({
            keyType:        this.keyType,
            keyIdentifier:  identifier,
            algorithm:      this.algorithm,
            keyOperations:  this.keyOperations,
            curveId:        this.curveId,
            x:              this.x,
            y:              this.y,
            d:              this.d,
            additional:     this.additional,
        });

    }

}
