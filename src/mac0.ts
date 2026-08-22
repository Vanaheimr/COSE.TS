/*
 * Copyright (c) 2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr COSE <https://github.com/Vanaheimr/COSE.TS>
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * A COSE_Mac0 message [RFC 9052, Section 6.2]: a payload authenticated with a
 * key both parties hold, tagged with CBOR tag 17.
 *
 * <code>
 * COSE_Mac0 = [
 *     protected   : bstr .cbor header_map,   ; covered by the tag
 *     unprotected : header_map,              ; NOT covered by the tag
 *     payload     : bstr / nil,              ; nil = detached
 *     tag         : bstr
 * ]
 * </code>
 *
 * It is the structural twin of `COSE_Sign1`, deliberately: four elements in
 * the same order, tag 17 against tag 18, and a MAC_structure that differs from
 * the Sig_structure in one string — `"MAC0"` where the other says
 * `"Signature1"`. Everything the signature code learned applies unchanged: the
 * protected bucket is kept verbatim, the CBOR tag is not covered, the payload
 * may be detached, external additional authenticated data is signed without
 * travelling.
 *
 * **What is not the same is what a verified message means.** A signature says
 * "the holder of that private key produced this", to anybody who cares to
 * check. A tag says "someone holding the shared key produced this", and only
 * to someone who holds that key too — because verifying one requires the very
 * key that creates one. Between two parties that is still useful: each knows
 * the other made it, having not made it themselves. Towards a third party it
 * is worth nothing at all, and a party that later denies having produced a
 * message cannot be contradicted with a tag.
 *
 * That is why a metrological record is *signed*. The customer, the operator
 * and the regulator all have to be able to check a reading, and none of them
 * may be able to manufacture one. A MAC belongs where the two ends of a link
 * already share a secret and want cheap tamper detection — eight bytes and one
 * hash, against sixty-four bytes and a curve multiplication — with the durable
 * evidence carried by a signature underneath.
 *
 * The `tag` field is an authentication tag and has nothing to do with the CBOR
 * tag 17 this message is wrapped in. RFC 9052 uses the word for both.
 */

import { macWith, verifyMacWith }            from './algorithm.ts';
import type { CoseAlgorithm }                from './algorithm.ts';
import { bytesEqual, cbor, decode,
         encode, NO_BYTES }                  from './cbor.ts';
import type { CborValue }                    from './cbor.ts';
import { CoseError, notVerified, VERIFIED }  from './errors.ts';
import type { Verification }                 from './errors.ts';
import { CoseHeaders,
         verifyCriticalHeaderParameters }    from './headers.ts';
import { KEY_TYPE_SYMMETRIC }                from './key.ts';
import type { CoseKey }                      from './key.ts';
import { HeaderLabel, label }                from './labels.ts';
import { canonicalizePayload }               from './payload.ts';
import { resolveAlgorithm, resolvePayload }  from './resolve.ts';


/** The CBOR tag of a COSE_Mac0 message. */
export const COSE_MAC0_TAG = 17;

/** The context string of a COSE_Mac0 authentication tag [RFC 9052, Section 6.3]. */
export const MAC0_CONTEXT = 'MAC0';


/** What a party computing an authentication tag may choose. */
export interface Mac0Options {

    /** A key identifier for the unprotected bucket, defaulting to the key's own. */
    readonly keyIdentifier?:  Uint8Array | null;

    /** Data authenticated along with the payload without travelling in the message. */
    readonly externalAad?:    Uint8Array | null;

    /** Whether to omit the payload from the message. */
    readonly detachPayload?:  boolean;

    /**
     * Whether to rewrite a CBOR payload in the deterministic encoding of
     * RFC 8949 §4.2.1 before authenticating it, so that a receiver who parses
     * and re-serializes the record arrives at the very bytes this tag covers.
     * Defaults to true. A payload that is not CBOR is authenticated as it is.
     */
    readonly canonicalizePayload?:  boolean;


    /** Whether to wrap the message within CBOR tag 17. Defaults to true. */
    readonly tagged?:         boolean;

}


/** What a party checking an authentication tag may have to supply. */
export interface Mac0VerifyOptions {

    /** The data that was authenticated along with the payload. */
    readonly externalAad?:        Uint8Array | null;

    /** The payload, when the message carries a detached one. */
    readonly detachedPayload?:    Uint8Array | null;

    /**
     * The algorithm the caller expects, required whenever the message states
     * its algorithm within the unprotected bucket only.
     */
    readonly expectedAlgorithm?:  CoseAlgorithm | null;

    /**
     * Header parameters the caller processes itself, and which a `crit`
     * header parameter may therefore demand.
     */
    readonly alsoUnderstood?:     readonly CborValue[];

}


export class CoseMac0 {

    /**
     * The serialized protected bucket, exactly as authenticated and as
     * received: a zero-length byte string when there are no protected header
     * parameters.
     */
    public readonly protectedHeaderBytes:  Uint8Array;

    /** The protected header parameters, which the authentication tag covers. */
    public readonly protectedHeader:       CoseHeaders;

    /**
     * The unprotected header parameters, which the tag does not cover and
     * which therefore must not be trusted after a successful verification.
     */
    public readonly unprotectedHeader:     CoseHeaders;

    /** The authenticated payload, or null when it is detached. */
    public readonly payload:               Uint8Array | null;

    /** The authentication tag — not the CBOR tag. */
    public readonly tag:                   Uint8Array;

    /**
     * Whether this message is wrapped within CBOR tag 17. The tag is not
     * covered by the authentication tag, but it is preserved so that a parsed
     * message re-encodes to the very same bytes.
     */
    public readonly isTagged:              boolean;


    public constructor(protectedHeaderBytes: Uint8Array,
                       unprotectedHeader:    CoseHeaders | null,
                       payload:              Uint8Array | null,
                       tag:                  Uint8Array,
                       isTagged              = true) {

        this.protectedHeaderBytes  = protectedHeaderBytes;
        this.protectedHeader       = CoseHeaders.parseProtected(protectedHeaderBytes);
        this.unprotectedHeader     = unprotectedHeader ?? CoseHeaders.empty;
        this.payload               = payload;
        this.tag                   = tag;
        this.isTagged              = isTagged;

    }


    /** Whether the payload is detached. */
    public get isDetached(): boolean {
        return this.payload === null;
    }

    /**
     * The MAC algorithm, taken from the protected bucket and only otherwise
     * from the unprotected one.
     */
    public get algorithm(): CoseAlgorithm | null {
        return this.protectedHeader.algorithm ?? this.unprotectedHeader.algorithm;
    }

    /** The key identifier, protected bucket first. */
    public get keyIdentifier(): Uint8Array | null {
        return this.protectedHeader.keyIdentifier ?? this.unprotectedHeader.keyIdentifier;
    }


    // ----------------------------------------------------- the MAC_structure

    /**
     * The encoded MAC_structure [RFC 9052, Section 6.3], which is the byte
     * string the MAC is actually computed over:
     *
     * <code>
     * MAC_structure = [
     *     context      : "MAC0",
     *     protected    : empty_or_serialized_map,
     *     external_aad : bstr,
     *     payload      : bstr
     * ]
     * </code>
     *
     * The full payload goes in here regardless of how it travels, so a
     * detached message and an attached one carry the very same tag.
     */
    public static toBeMaced(protectedHeaderBytes: Uint8Array,
                            payload:              Uint8Array,
                            externalAad:          Uint8Array | null = null): Uint8Array {

        return encode(cbor.array([
            cbor.text(MAC0_CONTEXT),
            cbor.bytes(protectedHeaderBytes),
            cbor.bytes(externalAad ?? NO_BYTES),
            cbor.bytes(payload),
        ]));

    }


    /** The encoded MAC_structure of this message. */
    public toBeMaced(options: { externalAad?:     Uint8Array | null;
                                detachedPayload?: Uint8Array | null } = {}): Uint8Array {

        const payload = resolvePayload(this.payload,
                                       options.detachedPayload ?? null,
                                       'this COSE_Mac0 message');

        if (!payload.ok)
            throw new CoseError(payload.reason);

        return CoseMac0.toBeMaced(this.protectedHeaderBytes,
                                  payload.value,
                                  options.externalAad ?? null);

    }


    // --------------------------------------------------------------- creating

    /**
     * Authenticate a payload, placing the algorithm within the protected
     * bucket and the key identifier within the unprotected one.
     */
    public static create(payload: Uint8Array,
                         key:     CoseKey,
                         options: Mac0Options = {}): CoseMac0 {

        const algorithm = requireMacAlgorithm(key);

        const keyIdentifier   = options.keyIdentifier === undefined
                                    ? key.keyIdentifier
                                    : options.keyIdentifier;

        const protectedHeader = new CoseHeaders([
            [label(HeaderLabel.algorithm), cbor.int(algorithm.id)],
        ]);

        return CoseMac0.createWithHeaders(payload, key, protectedHeader,
                                          keyIdentifier === null
                                              ? null
                                              : new CoseHeaders([[label(HeaderLabel.keyIdentifier),
                                                                  cbor.bytes(keyIdentifier)]]),
                                          options);

    }


    /** Authenticate a payload with header buckets the caller composed. */
    public static createWithHeaders(payload:            Uint8Array,
                                    key:                CoseKey,
                                    protectedHeader:    CoseHeaders,
                                    unprotectedHeader:  CoseHeaders | null = null,
                                    options:            Mac0Options = {}): CoseMac0 {

        const stated    = protectedHeader.algorithm;
        const algorithm = stated ?? requireMacAlgorithm(key);

        requireSymmetric(key, algorithm);

        const protectedBytes = protectedHeader.toProtectedBytes();

        // A MAC dies the same death as a signature: a receiver that decodes
        // the payload and encodes it again produces the deterministic
        // spelling, and a tag over another one no longer verifies. A detached
        // payload is the caller's to transmit, so rewriting it here would
        // authenticate bytes nobody holds.
        const authenticated = options.canonicalizePayload === false
                                  ? payload
                                  : canonicalizePayload(payload);

        if (options.detachPayload === true && !bytesEqual(authenticated, payload))
            throw new CoseError('The payload of this COSE_Mac0 message is detached, so canonicalizing it here would authenticate bytes that nobody holds: canonicalize the payload yourself (canonicalizePayload), authenticate and transmit those, or pass canonicalizePayload: false to authenticate the payload exactly as it is!');

        const tag = macWith(algorithm,
                            CoseMac0.toBeMaced(protectedBytes, authenticated, options.externalAad ?? null),
                            key.privateKeyBytes());

        return new CoseMac0(protectedBytes,
                            unprotectedHeader,
                            options.detachPayload === true ? null : authenticated,
                            tag,
                            options.tagged ?? true);

    }


    // ----------------------------------------------------------- verification

    /**
     * Verify the authentication tag of this message.
     *
     * A failed verification is not an exception — it is the expected outcome
     * of checking untrusted data — so the reason travels in the result. The
     * comparison itself is constant time, which matters here in a way it does
     * not for a signature: an early-returning compare would tell whoever is
     * guessing a tag how many of their leading bytes were right.
     */
    public verify(key: CoseKey, options: Mac0VerifyOptions = {}): Verification {

        const critical = verifyCriticalHeaderParameters(this.protectedHeader,
                                                        this.unprotectedHeader,
                                                        options.alsoUnderstood ?? []);

        if (!critical.verified)
            return critical;

        const algorithm = resolveAlgorithm(this.protectedHeader,
                                           this.unprotectedHeader,
                                           options.expectedAlgorithm ?? key.algorithm,
                                           'This COSE_Mac0 message');

        if (!algorithm.ok)
            return notVerified(algorithm.reason);

        const payload = resolvePayload(this.payload,
                                       options.detachedPayload ?? null,
                                       'this COSE_Mac0 message');

        if (!payload.ok)
            return notVerified(payload.reason);

        if (algorithm.value.family !== 'hmac')
            return notVerified(`The COSE algorithm '${algorithm.value.name}' is not a message authentication algorithm: a COSE_Mac0 message can not be authenticated with a signature algorithm!`);

        if (key.keyType !== KEY_TYPE_SYMMETRIC)
            return notVerified(`A COSE_Mac0 message needs a key of key type Symmetric [RFC 9053, Section 3.1], but a key of key type ${String(key.keyType)} was given!`);

        let verified: boolean;

        try {
            verified = verifyMacWith(algorithm.value,
                                     CoseMac0.toBeMaced(this.protectedHeaderBytes,
                                                        payload.value,
                                                        options.externalAad ?? null),
                                     this.tag,
                                     key.privateKeyBytes());
        }
        catch (exception) {
            return notVerified(exception instanceof Error ? exception.message : String(exception));
        }

        return verified
                   ? VERIFIED
                   : notVerified('The authentication tag is not the right one for this payload and this key!');

    }


    // ------------------------------------------------------- serialization

    /** Read a COSE_Mac0 message, tagged or not. */
    public static parse(input: Uint8Array | CborValue): CoseMac0 {

        const value = input instanceof Uint8Array ? decode(input) : input;

        let isTagged = false;
        let message  = value;

        if (message.type === 'tag') {

            if (message.tag !== BigInt(COSE_MAC0_TAG))
                throw new CoseError(`A COSE_Mac0 message must be tagged with CBOR tag ${String(COSE_MAC0_TAG)}, but was tagged with CBOR tag ${String(message.tag)}!`);

            isTagged = true;
            message  = message.value;

        }

        if (message.type !== 'array')
            throw new CoseError(`A COSE_Mac0 message must be a CBOR array, but was a CBOR ${message.type}!`);

        if (message.items.length !== 4)
            throw new CoseError(`A COSE_Mac0 message must be a CBOR array of 4 elements, but had ${String(message.items.length)} element(s)!`);

        const [protectedBytes, unprotected, payload, tag] = message.items;

        if (protectedBytes?.type !== 'bytes')
            throw new CoseError('The protected header bucket of a COSE_Mac0 message must be a byte string!');

        if (unprotected === undefined)
            throw new CoseError('A COSE_Mac0 message must carry an unprotected header bucket!');

        if (payload === undefined || (payload.type !== 'null' && payload.type !== 'bytes'))
            throw new CoseError('The payload of a COSE_Mac0 message must be a byte string, or null when it is detached!');

        if (tag?.type !== 'bytes')
            throw new CoseError('The authentication tag of a COSE_Mac0 message must be a byte string!');

        return new CoseMac0(protectedBytes.value,
                            CoseHeaders.parse(unprotected),
                            payload.type === 'bytes' ? payload.value : null,
                            tag.value,
                            isTagged);

    }


    /** The CBOR form of this message. */
    public toCbor(): CborValue {

        const message = cbor.array([
            cbor.bytes(this.protectedHeaderBytes),
            this.unprotectedHeader.toCbor(),
            this.payload !== null ? cbor.bytes(this.payload) : cbor.nullValue,
            cbor.bytes(this.tag),
        ]);

        return this.isTagged ? cbor.tag(COSE_MAC0_TAG, message) : message;

    }


    /** The CBOR encoding of this message. */
    public toBytes(): Uint8Array {
        return encode(this.toCbor());
    }


    /**
     * A copy of this message without its payload.
     *
     * The tag stays valid: it never covered the message, only the
     * MAC_structure, and the MAC_structure always holds the full payload.
     */
    public detach(): CoseMac0 {
        return new CoseMac0(this.protectedHeaderBytes, this.unprotectedHeader,
                            null, this.tag, this.isTagged);
    }

}


/** The MAC algorithm a key names, refusing a key that names something else. */
function requireMacAlgorithm(key: CoseKey): CoseAlgorithm {

    if (key.algorithm === null)
        throw new CoseError('A COSE_Mac0 message needs a MAC algorithm: either on the key or within the protected header bucket!');

    if (key.algorithm.family !== 'hmac')
        throw new CoseError(`The COSE algorithm '${key.algorithm.name}' is not a message authentication algorithm!`);

    return key.algorithm;

}


/**
 * The key checks of RFC 9053 Section 3.1.
 *
 * The second one is the one worth having. A key that names `HMAC 256/256`
 * being used to produce an `HMAC 256/64` tag is a truncation nobody asked for,
 * and it is exactly how a party talks itself into a weaker tag than the key
 * was issued for.
 */
function requireSymmetric(key: CoseKey, algorithm: CoseAlgorithm): void {

    if (algorithm.family !== 'hmac')
        throw new CoseError(`The COSE algorithm '${algorithm.name}' is not a message authentication algorithm!`);

    if (key.keyType !== KEY_TYPE_SYMMETRIC)
        throw new CoseError(`A COSE_Mac0 message needs a key of key type Symmetric [RFC 9053, Section 3.1], but a key of key type ${String(key.keyType)} was given!`);

    if (key.algorithm !== null && key.algorithm.id !== algorithm.id)
        throw new CoseError(`This message is to be authenticated with '${algorithm.name}', but the key names '${key.algorithm.name}' [RFC 9053, Section 3.1]!`);

}
