/*
 * Copyright (c) 2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr COSE <https://github.com/Vanaheimr/COSE.TS>
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * A COSE_Sign message [RFC 9052, Section 4.1]: one payload, several signers,
 * tagged with CBOR tag 98.
 *
 * <code>
 * COSE_Sign = [
 *     protected   : bstr .cbor header_map,
 *     unprotected : header_map,
 *     payload     : bstr / nil,
 *     signatures  : [ + COSE_Signature ]
 * ]
 * </code>
 *
 * The signatures are independent: each covers the body, its own header bucket
 * and the payload, but never another signature. Adding one therefore leaves
 * the existing ones byte-for-byte valid, and the second party never needs the
 * first party's key.
 *
 * Which of the two mechanisms to reach for is decided by one question: does
 * the party have something of its own to say? Several parties asserting *the
 * same* payload is this. A party that vouches for somebody else's signature
 * without adding a claim wants the countersignature of RFC 9338, which lives
 * on COSE_Sign1. A party with metadata of its own signs a new payload that
 * nests the old message.
 *
 * Its Sig_structure has **five** elements rather than four, with the protected
 * bucket of the individual signature between the body and the external data.
 */

import { signWith }                          from './algorithm.ts';
import type { CoseAlgorithm }                from './algorithm.ts';
import { cbor, decode, encode, NO_BYTES }    from './cbor.ts';
import type { CborValue }                    from './cbor.ts';
import { CoseError, notVerified }            from './errors.ts';
import type { Verification }                 from './errors.ts';
import { CoseHeaders,
         verifyCriticalHeaderParameters }    from './headers.ts';
import type { CoseKey }                      from './key.ts';
import { resolveAlgorithm, resolvePayload }  from './resolve.ts';
import { CoseSignature }                     from './signature.ts';
import { verifySignature }                   from './sign1.ts';
import type { Sign1Options, VerifyOptions }  from './sign1.ts';


/** The CBOR tag of a COSE_Sign message. */
export const COSE_SIGN_TAG = 98;

/** The context string of a COSE_Sign signature [RFC 9052, Section 4.4]. */
export const SIGNATURE_CONTEXT = 'Signature';


export class CoseSign {

    /** The serialized protected bucket of the body, exactly as signed. */
    public readonly protectedHeaderBytes:  Uint8Array;

    /** The protected header parameters of the body, which every signature covers. */
    public readonly protectedHeader:       CoseHeaders;

    /** The unprotected header parameters of the body, which none of them covers. */
    public readonly unprotectedHeader:     CoseHeaders;

    /** The signed payload, or null when it is detached. */
    public readonly payload:               Uint8Array | null;

    /** The signatures, in the order they travel. */
    public readonly signatures:            readonly CoseSignature[];

    /** Whether this message is wrapped within CBOR tag 98. */
    public readonly isTagged:              boolean;


    public constructor(protectedHeaderBytes: Uint8Array,
                       unprotectedHeader:    CoseHeaders | null,
                       payload:              Uint8Array | null,
                       signatures:           readonly CoseSignature[],
                       isTagged              = true) {

        if (signatures.length === 0)
            throw new CoseError('A COSE_Sign message must carry at least one signature!');

        this.protectedHeaderBytes  = protectedHeaderBytes;
        this.protectedHeader       = CoseHeaders.parseProtected(protectedHeaderBytes);
        this.unprotectedHeader     = unprotectedHeader ?? CoseHeaders.empty;
        this.payload               = payload;
        this.signatures            = [...signatures];
        this.isTagged              = isTagged;

    }


    /** Whether the payload is detached. */
    public get isDetached(): boolean {
        return this.payload === null;
    }


    /**
     * The encoded Sig_structure of one signature of a COSE_Sign message
     * [RFC 9052, Section 4.4]:
     *
     * <code>
     * Sig_structure = [
     *     context        : "Signature",
     *     body_protected : empty_or_serialized_map,
     *     sign_protected : empty_or_serialized_map,
     *     external_aad   : bstr,
     *     payload        : bstr
     * ]
     * </code>
     */
    public static toBeSigned(bodyProtectedHeaderBytes:      Uint8Array,
                             signatureProtectedHeaderBytes: Uint8Array,
                             payload:                       Uint8Array,
                             externalAad:                   Uint8Array | null = null): Uint8Array {

        return encode(cbor.array([
            cbor.text(SIGNATURE_CONTEXT),
            cbor.bytes(bodyProtectedHeaderBytes),
            cbor.bytes(signatureProtectedHeaderBytes),
            cbor.bytes(externalAad ?? NO_BYTES),
            cbor.bytes(payload),
        ]));

    }


    /** The encoded Sig_structure of one signature of this message. */
    public toBeSigned(signature: CoseSignature,
                      options: { externalAad?:     Uint8Array | null;
                                 detachedPayload?: Uint8Array | null } = {}): Uint8Array {

        const payload = resolvePayload(this.payload,
                                       options.detachedPayload ?? null,
                                       'this COSE_Sign message');

        if (!payload.ok)
            throw new CoseError(payload.reason);

        return CoseSign.toBeSigned(this.protectedHeaderBytes,
                                   signature.protectedHeaderBytes,
                                   payload.value,
                                   options.externalAad ?? null);

    }


    /**
     * Sign a payload, producing a message with one signature.
     *
     * The body's protected bucket stays empty: what a signer has to say about
     * its own signature — its algorithm, its key identifier — belongs to that
     * signature rather than to the body every other signer shares.
     */
    public static sign(payload: Uint8Array,
                       key:     CoseKey,
                       options: Sign1Options = {}): CoseSign {

        return new CoseSign(NO_BYTES,
                            CoseHeaders.empty,
                            options.detachPayload === true ? null : payload,
                            [signatureOver(NO_BYTES, payload, key, options)],
                            options.tagged ?? true);

    }


    /**
     * Return a copy of this message with one more signature.
     *
     * The existing signatures are untouched and stay valid, because no
     * signature ever covers another.
     */
    public addSignature(key: CoseKey,
                        options: Sign1Options & {
                            detachedPayload?: Uint8Array | null } = {}): CoseSign {

        const payload = resolvePayload(this.payload,
                                       options.detachedPayload ?? null,
                                       'this COSE_Sign message');

        if (!payload.ok)
            throw new CoseError(payload.reason);

        return new CoseSign(this.protectedHeaderBytes,
                            this.unprotectedHeader,
                            this.payload,
                            [...this.signatures,
                             signatureOver(this.protectedHeaderBytes, payload.value, key, options)],
                            this.isTagged);

    }


    /** Verify one signature of this message. */
    public verify(signature: CoseSignature,
                  key:       CoseKey,
                  options:   VerifyOptions = {}): Verification {

        if (!this.signatures.includes(signature))
            return notVerified('The given signature is not one of the signatures of this COSE_Sign message!');

        const bodyCritical = verifyCriticalHeaderParameters(this.protectedHeader,
                                                            this.unprotectedHeader,
                                                            options.alsoUnderstood ?? []);

        if (!bodyCritical.verified)
            return bodyCritical;

        const signatureCritical = verifyCriticalHeaderParameters(signature.protectedHeader,
                                                                 signature.unprotectedHeader,
                                                                 options.alsoUnderstood ?? []);

        if (!signatureCritical.verified)
            return signatureCritical;

        const algorithm = resolveAlgorithm(signature.protectedHeader,
                                           signature.unprotectedHeader,
                                           options.expectedAlgorithm ?? key.algorithm,
                                           'This signature of a COSE_Sign message');

        if (!algorithm.ok)
            return notVerified(algorithm.reason);

        const payload = resolvePayload(this.payload,
                                       options.detachedPayload ?? null,
                                       'this COSE_Sign message');

        if (!payload.ok)
            return notVerified(payload.reason);

        return verifySignature(algorithm.value,
                               key,
                               CoseSign.toBeSigned(this.protectedHeaderBytes,
                                                   signature.protectedHeaderBytes,
                                                   payload.value,
                                                   options.externalAad ?? null),
                               signature.signature);

    }


    /**
     * The first signature this key verifies, or null.
     *
     * Signatures are tried in wire order. A signature that states its
     * algorithm in the unprotected bucket only still needs an expected
     * algorithm to be accepted, here as everywhere else — which the key
     * supplies when it carries one, and otherwise nobody does.
     */
    public verifyAny(key:     CoseKey,
                     options: VerifyOptions = {}): CoseSignature | null {

        for (const signature of this.signatures) {
            if (this.verify(signature, key, options).verified)
                return signature;
        }

        return null;

    }


    /** Parse a COSE_Sign message, tagged or untagged. */
    public static parse(input: Uint8Array | CborValue): CoseSign {

        const value = input instanceof Uint8Array ? decode(input) : input;

        let isTagged = false;
        let message  = value;

        if (message.type === 'tag') {

            if (message.tag !== BigInt(COSE_SIGN_TAG))
                throw new CoseError(`A COSE_Sign message must be tagged with CBOR tag ${String(COSE_SIGN_TAG)}, but was tagged with CBOR tag ${String(message.tag)}!`);

            isTagged = true;
            message  = message.value;

        }

        if (message.type !== 'array')
            throw new CoseError(`A COSE_Sign message must be a CBOR array, but was a CBOR ${message.type}!`);

        if (message.items.length !== 4)
            throw new CoseError(`A COSE_Sign message must be a CBOR array of 4 elements, but had ${String(message.items.length)} element(s)!`);

        const [protectedBytes, unprotected, payload, signatures] = message.items;

        if (protectedBytes?.type !== 'bytes')
            throw new CoseError('The protected header bucket of a COSE_Sign message must be a byte string!');

        if (unprotected === undefined)
            throw new CoseError('A COSE_Sign message must carry an unprotected header bucket!');

        if (payload === undefined || (payload.type !== 'null' && payload.type !== 'bytes'))
            throw new CoseError('The payload of a COSE_Sign message must be a byte string, or null when it is detached!');

        if (signatures?.type !== 'array')
            throw new CoseError('The signatures of a COSE_Sign message must be a CBOR array!');

        return new CoseSign(protectedBytes.value,
                            CoseHeaders.parse(unprotected),
                            payload.type === 'bytes' ? payload.value : null,
                            signatures.items.map(each => CoseSignature.parse(each)),
                            isTagged);

    }


    /** A CBOR representation of this message. */
    public toCbor(): CborValue {

        const message = cbor.array([
            cbor.bytes(this.protectedHeaderBytes),
            this.unprotectedHeader.toCbor(),
            this.payload !== null ? cbor.bytes(this.payload) : cbor.nullValue,
            cbor.array(this.signatures.map(each => each.toCbor())),
        ]);

        return this.isTagged ? cbor.tag(COSE_SIGN_TAG, message) : message;

    }


    /** The CBOR encoding of this message. */
    public toBytes(): Uint8Array {
        return encode(this.toCbor());
    }

}


/** Sign one signature slot of a COSE_Sign message. */
function signatureOver(bodyProtectedHeaderBytes: Uint8Array,
                       payload:                  Uint8Array,
                       key:                      CoseKey,
                       options:                  Sign1Options): CoseSignature {

    const algorithm: CoseAlgorithm | null = key.algorithm;

    if (algorithm === null)
        throw new CoseError('The COSE key does not name the signature algorithm to use!');

    const keyIdentifier = options.keyIdentifier === undefined
                              ? key.keyIdentifier
                              : options.keyIdentifier;

    const protectedBytes = CoseHeaders.create(algorithm).toProtectedBytes();

    const signature = signWith(algorithm,
                               key.curve,
                               CoseSign.toBeSigned(bodyProtectedHeaderBytes,
                                                   protectedBytes,
                                                   payload,
                                                   options.externalAad ?? null),
                               key.privateKeyBytes());

    return new CoseSignature(protectedBytes,
                             keyIdentifier !== null
                                 ? CoseHeaders.create(null, keyIdentifier)
                                 : CoseHeaders.empty,
                             signature);

}
