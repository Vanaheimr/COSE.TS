/*
 * Copyright (c) 2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr COSE <https://github.com/Vanaheimr/COSE.TS>
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * One signature of a multi-signer message [RFC 9052, Section 4.1], and the
 * very same structure once more as a countersignature [RFC 9338].
 *
 * <code>
 * COSE_Signature = [
 *     protected   : bstr .cbor header_map,
 *     unprotected : header_map,
 *     signature   : bstr
 * ]
 * </code>
 *
 * It carries header buckets of its own, which is what lets every party sign
 * with its own algorithm and its own key.
 */

import type { CoseAlgorithm }        from './algorithm.ts';
import { cbor, encode }              from './cbor.ts';
import type { CborValue }            from './cbor.ts';
import { CoseError }                 from './errors.ts';
import { CoseHeaders }               from './headers.ts';


export class CoseSignature {

    /** The serialized protected bucket, exactly as signed and as received. */
    public readonly protectedHeaderBytes:  Uint8Array;

    /** The protected header parameters, which this signature covers. */
    public readonly protectedHeader:       CoseHeaders;

    /** The unprotected header parameters, which it does not. */
    public readonly unprotectedHeader:     CoseHeaders;

    /** The signature: `r ‖ s`, never DER. */
    public readonly signature:             Uint8Array;


    public constructor(protectedHeaderBytes: Uint8Array,
                       unprotectedHeader:    CoseHeaders | null,
                       signature:            Uint8Array) {

        this.protectedHeaderBytes  = protectedHeaderBytes;
        this.protectedHeader       = CoseHeaders.parseProtected(protectedHeaderBytes);
        this.unprotectedHeader     = unprotectedHeader ?? CoseHeaders.empty;
        this.signature             = signature;

    }


    /**
     * The signature algorithm, taken from the protected bucket and only
     * otherwise from the unprotected one.
     */
    public get algorithm(): CoseAlgorithm | null {
        return this.protectedHeader.algorithm ?? this.unprotectedHeader.algorithm;
    }

    /** The key identifier, protected bucket first. */
    public get keyIdentifier(): Uint8Array | null {
        return this.protectedHeader.keyIdentifier ?? this.unprotectedHeader.keyIdentifier;
    }


    /** Parse a three-element COSE_Signature. */
    public static parse(value: CborValue): CoseSignature {

        if (value.type !== 'array')
            throw new CoseError(`A COSE_Signature must be a CBOR array, but was a CBOR ${value.type}!`);

        if (value.items.length !== 3)
            throw new CoseError(`A COSE_Signature must be a CBOR array of 3 elements, but had ${String(value.items.length)} element(s)!`);

        const [protectedBytes, unprotected, signature] = value.items;

        if (protectedBytes?.type !== 'bytes')
            throw new CoseError('The protected header bucket of a COSE_Signature must be a byte string!');

        if (unprotected === undefined)
            throw new CoseError('A COSE_Signature must carry an unprotected header bucket!');

        if (signature?.type !== 'bytes')
            throw new CoseError('The signature of a COSE_Signature must be a byte string!');

        return new CoseSignature(protectedBytes.value,
                                 CoseHeaders.parse(unprotected),
                                 signature.value);

    }


    /** A CBOR representation of this signature. */
    public toCbor(): CborValue {

        return cbor.array([
            cbor.bytes(this.protectedHeaderBytes),
            this.unprotectedHeader.toCbor(),
            cbor.bytes(this.signature),
        ]);

    }


    /** The CBOR encoding of this signature. */
    public toBytes(): Uint8Array {
        return encode(this.toCbor());
    }

}
