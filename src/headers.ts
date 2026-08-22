/*
 * Copyright (c) 2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr COSE <https://github.com/Vanaheimr/COSE.TS>
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * A bucket of COSE header parameters [RFC 9052, Section 3].
 *
 * A signed COSE message carries two of them. The protected bucket is covered
 * by the signature; the unprotected bucket is not, and therefore must not be
 * trusted after a successful verification — the key identifier of nearly every
 * deployed message lives there, and so does anything an attacker on the path
 * would like to change.
 *
 * Buckets are immutable, because the serialization of a protected bucket is
 * part of a signature input and must not change after signing. `set` returns a
 * copy: an unprotected bucket does need to change after signing, since a
 * countersignature is added to a message that is already finished.
 */

import { algorithmFromCbor, algorithmToCbor }   from './algorithm.ts';
import type { CoseAlgorithm }                   from './algorithm.ts';
import { cbor, decode, encode, NO_BYTES }       from './cbor.ts';
import type { CborEntry, CborValue }            from './cbor.ts';
import { CoseError, notVerified, VERIFIED }     from './errors.ts';
import type { Verification }                    from './errors.ts';
import { HeaderLabel, headerLabelName,
         isUnderstood, label, sameLabel }       from './labels.ts';


export class CoseHeaders {

    /** The header parameters, in the order they were given or read. */
    public readonly parameters: readonly CborEntry[];


    public constructor(parameters: readonly CborEntry[] = []) {

        this.parameters = [...parameters];

        for (let index = 0; index < this.parameters.length; index++) {
            for (let other = 0; other < index; other++) {
                if (sameLabel(this.parameters[index]![0], this.parameters[other]![0]))
                    throw new CoseError(`The COSE header parameter '${headerLabelName(this.parameters[index]![0])}' was given more than once!`);
            }
        }

    }


    /**
     * A bucket without any header parameters. As a protected bucket it is
     * serialized as a zero-length byte string.
     */
    public static readonly empty = new CoseHeaders();


    /** How many header parameters this bucket holds. */
    public get count(): number {
        return this.parameters.length;
    }

    /** Whether this bucket has no header parameters at all. */
    public get isEmpty(): boolean {
        return this.parameters.length === 0;
    }


    /**
     * The bucket holding the two header parameters almost every signed COSE
     * message uses.
     */
    public static create(algorithm?:     CoseAlgorithm | null,
                         keyIdentifier?: Uint8Array | null): CoseHeaders {

        const parameters: CborEntry[] = [];

        if (algorithm !== undefined && algorithm !== null)
            parameters.push([label(HeaderLabel.algorithm), algorithmToCbor(algorithm)]);

        if (keyIdentifier !== undefined && keyIdentifier !== null)
            parameters.push([label(HeaderLabel.keyIdentifier), cbor.bytes(keyIdentifier)]);

        return new CoseHeaders(parameters);

    }


    /** Parse the given CBOR map as a bucket of header parameters. */
    public static parse(value: CborValue): CoseHeaders {

        if (value.type !== 'map')
            throw new CoseError(`A bucket of COSE header parameters must be a CBOR map, but was a CBOR ${value.type}!`);

        return new CoseHeaders(value.entries);

    }


    /**
     * Parse the serialized protected bucket of a COSE message.
     *
     * A zero-length byte string is an empty bucket and *not* an encoded empty
     * map. It is the one encoding that must never be "repaired" into `A0`,
     * because the signature covers these exact bytes [RFC 9052, Section 3].
     *
     * This is deliberately a separate function rather than an overload: a byte
     * array is also a perfectly good CBOR byte string, and the two readings of
     * the same argument mean very different things here.
     */
    public static parseProtected(protectedBytes: Uint8Array): CoseHeaders {

        if (protectedBytes.length === 0)
            return CoseHeaders.empty;

        return CoseHeaders.parse(decode(protectedBytes));

    }


    /** The value of the given header parameter, or null. */
    public get(labelValue: CborValue): CborValue | null {

        for (const [key, value] of this.parameters) {
            if (sameLabel(key, labelValue))
                return value;
        }

        return null;

    }

    /** Whether the given header parameter is present within this bucket. */
    public has(labelValue: CborValue): boolean {
        return this.get(labelValue) !== null;
    }


    /**
     * Return a copy in which the given header parameter is set, replacing it
     * in place when it is already present and appending it otherwise.
     */
    public set(labelValue: CborValue, value: CborValue): CoseHeaders {

        const updated: CborEntry[] = [];
        let   replaced             = false;

        for (const entry of this.parameters) {

            if (sameLabel(entry[0], labelValue)) {
                updated.push([labelValue, value]);
                replaced = true;
            }
            else
                updated.push(entry);

        }

        if (!replaced)
            updated.push([labelValue, value]);

        return new CoseHeaders(updated);

    }


    /** The cryptographic algorithm (label 1), or null when absent. */
    public get algorithm(): CoseAlgorithm | null {

        const value = this.get(label(HeaderLabel.algorithm));

        if (value?.type !== 'int')
            return null;

        return algorithmFromCbor(value);

    }

    /** The key identifier (label 4), or null when absent or not a byte string. */
    public get keyIdentifier(): Uint8Array | null {

        const value = this.get(label(HeaderLabel.keyIdentifier));

        return value !== null && value.type === 'bytes' ? value.value : null;

    }

    /** The content type (label 3), or null when absent. */
    public get contentType(): CborValue | null {
        return this.get(label(HeaderLabel.contentType));
    }

    /** The labels a recipient is required to understand (label 2), or null. */
    public get critical(): readonly CborValue[] | null {

        const value = this.get(label(HeaderLabel.critical));

        return value !== null && value.type === 'array' ? value.items : null;

    }


    /** A CBOR map holding these header parameters, in their own order. */
    public toCbor(): CborValue {
        return cbor.map(this.parameters);
    }


    /**
     * The serialization of this bucket for use as the PROTECTED bucket of a
     * COSE message: a zero-length byte string when the bucket is empty, and
     * the encoded map otherwise [RFC 9052, Section 3].
     *
     * These are the exact bytes a signature is computed over, so they have to
     * be transmitted and stored verbatim.
     */
    public toProtectedBytes(): Uint8Array {
        return this.isEmpty ? NO_BYTES : encode(this.toCbor());
    }

}


/**
 * Check the `crit` header parameter of a pair of buckets
 * [RFC 9052, Section 3.1].
 *
 * Every label listed there has to be present within the protected bucket and
 * has to be understood and processed by whoever is verifying, otherwise the
 * whole message is rejected. `alsoUnderstood` is how a caller that genuinely
 * processes a parameter says so — validating a certificate chain, for
 * instance — because what counts as understood is a property of the
 * verification being performed rather than of this library.
 */
export function verifyCriticalHeaderParameters(protectedHeader:   CoseHeaders,
                                               unprotectedHeader: CoseHeaders,
                                               alsoUnderstood:    readonly CborValue[] = []): Verification {

    if (unprotectedHeader.has(label(HeaderLabel.critical)))
        return notVerified('The "crit" header parameter must be placed within the protected header bucket!');

    const critical = protectedHeader.critical;

    if (critical === null) {

        if (protectedHeader.has(label(HeaderLabel.critical)))
            return notVerified('The "crit" header parameter must be an array of header parameter labels!');

        return VERIFIED;

    }

    if (critical.length === 0)
        return notVerified('The "crit" header parameter must list at least one header parameter label!');

    for (const each of critical) {

        if (!protectedHeader.has(each))
            return notVerified(`The "crit" header parameter lists '${headerLabelName(each)}', which is not present within the protected header bucket!`);

        if (!isUnderstood(each) && !alsoUnderstood.some(other => sameLabel(other, each)))
            return notVerified(`The "crit" header parameter demands that '${headerLabelName(each)}' be understood, which this implementation does not!`);

    }

    return VERIFIED;

}
