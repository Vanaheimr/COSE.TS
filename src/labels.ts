/*
 * Copyright (c) 2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr COSE <https://github.com/Vanaheimr/COSE.TS>
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * COSE header parameter labels [RFC 9052, Section 3.1].
 *
 * These are the labels of a *header bucket*, and they are not the labels of a
 * COSE key: label 3 is the content type here and the algorithm there, label 4
 * is the key identifier here and the key operations there. The two sets live
 * in separate modules for exactly that reason.
 */

import { cbor }       from './cbor.ts';
import type { CborValue } from './cbor.ts';


/** The header parameter labels this implementation knows by name. */
export const HeaderLabel = {

    /** The cryptographic algorithm [RFC 9052]. */
    algorithm:              1,

    /** The labels a recipient is required to understand [RFC 9052]. */
    critical:               2,

    /** The content type of the payload [RFC 9052]. */
    contentType:            3,

    /** The key identifier [RFC 9052]. */
    keyIdentifier:          4,

    /** The initialization vector [RFC 9052]. */
    iv:                     5,

    /** The partial initialization vector [RFC 9052]. */
    partialIv:              6,

    /** The countersignature of RFC 8152, superseded by label 11 [RFC 9338]. */
    counterSignature:       7,

    /** The countersignature that also covers the signature it signs [RFC 9338]. */
    counterSignatureV2:     11,

    /** The abbreviated countersignature, not implemented here [RFC 9338]. */
    counterSignature0V2:    12,

    /** An unordered bag of X.509 certificates [RFC 9360]. */
    x5Bag:                  32,

    /** An ordered X.509 certificate chain [RFC 9360]. */
    x5Chain:                33,

    /** The hash of an X.509 certificate [RFC 9360]. */
    x5T:                    34,

    /** A URI naming an X.509 certificate [RFC 9360]. */
    x5U:                    35,

} as const;


/** A header parameter label as it travels: an integer, or a text string. */
export const label = (value: number): CborValue =>
    cbor.int(value);


/**
 * The name of a header parameter label, for error messages.
 */
export function headerLabelName(value: CborValue): string {

    if (value.type === 'int') {

        switch (value.value) {
            case  1n: return 'alg';
            case  2n: return 'crit';
            case  3n: return 'content type';
            case  4n: return 'kid';
            case  5n: return 'IV';
            case  6n: return 'Partial IV';
            case  7n: return 'counter signature';
            case 11n: return 'counter signature version 2';
            case 12n: return 'counter signature 0 version 2';
            case 32n: return 'x5bag';
            case 33n: return 'x5chain';
            case 34n: return 'x5t';
            case 35n: return 'x5u';
        }

    }

    if (value.type === 'text')
        return value.value;

    return cbor.diagnostic(value);

}


/**
 * Whether this implementation understands and processes the given header
 * parameter, which is what the `crit` header parameter asks about
 * [RFC 9052, Section 3.1].
 *
 * Four labels, and deliberately not the X.509 ones. Whether a certificate
 * chain has been *understood* is a property of the verification being
 * performed rather than of the library: whoever verifies with a bare public
 * key has not looked at any certificate and must not claim otherwise. Callers
 * that do process one say so per call, through `alsoUnderstood`.
 */
export function isUnderstood(value: CborValue): boolean {

    return value.type === 'int' &&
           (value.value === 1n || value.value === 2n ||
            value.value === 3n || value.value === 4n);

}


/** Whether two header parameter labels are the same label. */
export function sameLabel(left: CborValue, right: CborValue): boolean {

    if (left.type === 'int'  && right.type === 'int')
        return left.value === right.value;

    if (left.type === 'text' && right.type === 'text')
        return left.value === right.value;

    return false;

}
