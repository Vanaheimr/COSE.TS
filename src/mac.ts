/*
 * Copyright (c) 2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr COSE <https://github.com/Vanaheimr/COSE.TS>
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * A COSE_Mac message [RFC 9052, Section 6.1]: a payload authenticated with a
 * content key that the message itself delivers to each recipient. CBOR tag 97.
 *
 * ```
 * COSE_Mac = [ Headers, payload : bstr / nil, tag : bstr, recipients : [+COSE_recipient] ]
 * ```
 *
 * Five elements where `COSE_Mac0` has four, and the fifth is the whole point:
 * `COSE_Mac0` assumes both parties already hold the key, while this solves the
 * distribution problem inside the message. The `MAC_structure` is the same
 * four-element structure either way, differing only in its context string —
 * `"MAC"` here, `"MAC0"` there.
 *
 * **A recipient list costs more than bytes.** Every recipient holds the same
 * content key, so with more than one of them the tag stops distinguishing them
 * at all: any recipient can produce a message the others will accept as coming
 * from the sender. A `COSE_Mac0` between two parties at least tells each of
 * them that the other made it, on the grounds that they did not make it
 * themselves; a `COSE_Mac` to three parties tells nobody anything of the kind.
 * RFC 9052 §8.2 states it outright — a MAC provides *"either no or very limited
 * data origination"* and *"cannot be used to prove the identity of the sender
 * to a third party"*.
 *
 * That is worth having in view before reaching for this structure. What it is
 * genuinely good at is cheap integrity for a group that already trusts one
 * another jointly — and if the question is who within that group said
 * something, the answer has to be a signature.
 *
 * The single-`direct`-recipient case is `COSE_Mac0` with extra ceremony: the
 * recipient structure carries an empty protected bucket, an empty ciphertext
 * and a key identifier, and nothing else. RFC 9052's Appendix C.5.1 is exactly
 * that, and it is why `COSE_Mac0` exists.
 */

import { macWith, verifyMacWith }            from './algorithm.ts';
import type { CoseAlgorithm }                from './algorithm.ts';
import { cbor, decode, encode, NO_BYTES }    from './cbor.ts';
import type { CborValue }                    from './cbor.ts';
import { CoseError, notVerified, VERIFIED }  from './errors.ts';
import type { Verification }                 from './errors.ts';
import { CoseHeaders,
         verifyCriticalHeaderParameters }    from './headers.ts';
import { KEY_TYPE_SYMMETRIC }                from './key.ts';
import type { CoseKey }                      from './key.ts';
import { HeaderLabel, label }                from './labels.ts';
import { CoseRecipient }                     from './recipient.ts';
import { resolveAlgorithm, resolvePayload }  from './resolve.ts';


/** The CBOR tag of a COSE_Mac message. */
export const COSE_MAC_TAG = 97;

/** The context string of a COSE_Mac authentication tag [RFC 9052, Section 6.3]. */
export const MAC_CONTEXT = 'MAC';


/** What a party authenticating may choose. */
export interface MacOptions {

    /** Data authenticated along with the payload without travelling in the message. */
    readonly externalAad?:    Uint8Array | null;

    /** Whether to omit the payload from the message. */
    readonly detachPayload?:  boolean;

    /** Whether to wrap the message within CBOR tag 97. Defaults to true. */
    readonly tagged?:         boolean;

}


/** What a party checking may have to supply. */
export interface MacVerifyOptions {

    /** The data that was authenticated along with the payload. */
    readonly externalAad?:        Uint8Array | null;

    /** The payload, when the message carries a detached one. */
    readonly detachedPayload?:    Uint8Array | null;

    /** The algorithm the caller expects. */
    readonly expectedAlgorithm?:  CoseAlgorithm | null;

    /** Header parameters the caller processes itself. */
    readonly alsoUnderstood?:     readonly CborValue[];

}


export class CoseMac {

    /** The serialized protected bucket, exactly as authenticated and received. */
    public readonly protectedHeaderBytes:  Uint8Array;

    /** The protected header parameters, which the authentication tag covers. */
    public readonly protectedHeader:       CoseHeaders;

    /** The unprotected header parameters, which it does not. */
    public readonly unprotectedHeader:     CoseHeaders;

    /** The authenticated payload, or null when it is detached. */
    public readonly payload:               Uint8Array | null;

    /** The authentication tag — not the CBOR tag. */
    public readonly tag:                   Uint8Array;

    /** How the content key reaches each party. */
    public readonly recipients:            readonly CoseRecipient[];

    /** Whether this message is wrapped within CBOR tag 97. */
    public readonly isTagged:              boolean;


    public constructor(protectedHeaderBytes: Uint8Array,
                       unprotectedHeader:    CoseHeaders | null,
                       payload:              Uint8Array | null,
                       tag:                  Uint8Array,
                       recipients:           readonly CoseRecipient[],
                       isTagged              = true) {

        if (recipients.length === 0)
            throw new CoseError('A COSE_Mac message must carry at least one recipient!');

        this.protectedHeaderBytes  = protectedHeaderBytes;
        this.protectedHeader       = CoseHeaders.parseProtected(protectedHeaderBytes);
        this.unprotectedHeader     = unprotectedHeader ?? CoseHeaders.empty;
        this.payload               = payload;
        this.tag                   = tag;
        this.recipients            = [...recipients];
        this.isTagged              = isTagged;

    }


    /** Whether the payload is detached. */
    public get isDetached(): boolean {
        return this.payload === null;
    }

    /** The MAC algorithm, protected bucket first. */
    public get algorithm(): CoseAlgorithm | null {
        return this.protectedHeader.algorithm ?? this.unprotectedHeader.algorithm;
    }


    /**
     * The encoded MAC_structure [RFC 9052, Section 6.3] with the `"MAC"`
     * context — the one difference from a COSE_Mac0's.
     */
    public static toBeMaced(protectedHeaderBytes: Uint8Array,
                            payload:              Uint8Array,
                            externalAad:          Uint8Array | null = null): Uint8Array {

        return encode(cbor.array([
            cbor.text(MAC_CONTEXT),
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
                                       'this COSE_Mac message');

        if (!payload.ok)
            throw new CoseError(payload.reason);

        return CoseMac.toBeMaced(this.protectedHeaderBytes,
                                 payload.value,
                                 options.externalAad ?? null);

    }


    /**
     * Authenticate a payload under a content key, and deliver that key to each
     * recipient.
     *
     * The content key is the caller's rather than generated here, for the same
     * reason as everywhere else in this package: a generated one would make the
     * message unreproducible, and whoever has a key management scheme has it
     * for a reason.
     */
    public static create(payload:     Uint8Array,
                         contentKey:  CoseKey,
                         recipients:  readonly CoseRecipient[],
                         options:     MacOptions = {}): CoseMac {

        const algorithm = contentKey.algorithm
                              ?? (() => { throw new CoseError('A COSE_Mac message needs a MAC algorithm on its content key!'); })();

        if (algorithm.family !== 'hmac')
            throw new CoseError(`The COSE algorithm '${algorithm.name}' is not a message authentication algorithm!`);

        if (contentKey.keyType !== KEY_TYPE_SYMMETRIC)
            throw new CoseError(`A COSE_Mac message needs a content key of key type Symmetric, but a key of key type ${String(contentKey.keyType)} was given!`);

        const protectedHeader = new CoseHeaders([
            [label(HeaderLabel.algorithm), cbor.int(algorithm.id)],
        ]);

        const protectedBytes = protectedHeader.toProtectedBytes();

        const tag = macWith(algorithm,
                            CoseMac.toBeMaced(protectedBytes, payload, options.externalAad ?? null),
                            contentKey.privateKeyBytes());

        return new CoseMac(protectedBytes,
                           null,
                           options.detachPayload === true ? null : payload,
                           tag,
                           recipients,
                           options.tagged ?? true);

    }


    /**
     * Verify this message with a key one of its recipients was built for.
     *
     * Every recipient is tried, because a party holding one key does not
     * generally know which entry in the list is theirs.
     */
    public verify(key: CoseKey, options: MacVerifyOptions = {}): Verification {

        const critical = verifyCriticalHeaderParameters(this.protectedHeader,
                                                        this.unprotectedHeader,
                                                        options.alsoUnderstood ?? []);

        if (!critical.verified)
            return critical;

        const algorithm = resolveAlgorithm(this.protectedHeader,
                                           this.unprotectedHeader,
                                           options.expectedAlgorithm ?? null,
                                           'This COSE_Mac message');

        if (!algorithm.ok)
            return notVerified(algorithm.reason);

        if (algorithm.value.family !== 'hmac')
            return notVerified(`The COSE algorithm '${algorithm.value.name}' is not a message authentication algorithm: a COSE_Mac message can not be authenticated with a signature algorithm!`);

        const payload = resolvePayload(this.payload,
                                       options.detachedPayload ?? null,
                                       'this COSE_Mac message');

        if (!payload.ok)
            return notVerified(payload.reason);

        if (key.keyType !== KEY_TYPE_SYMMETRIC)
            return notVerified(`A COSE_Mac message needs a key of key type Symmetric, but a key of key type ${String(key.keyType)} was given!`);

        const toBeMaced = CoseMac.toBeMaced(this.protectedHeaderBytes,
                                            payload.value,
                                            options.externalAad ?? null);

        let tried = 0;

        for (const recipient of this.recipients) {

            const contentKey = recipient.contentKey(key);

            if (contentKey === null)
                continue;

            tried++;

            try {
                if (verifyMacWith(algorithm.value, toBeMaced, this.tag, contentKey))
                    return VERIFIED;
            }
            catch {
                // A content key of the wrong width for this algorithm is
                // somebody else's recipient rather than a failure of ours.
                continue;
            }

        }

        return notVerified(tried === 0
                               ? 'None of the recipients of this COSE_Mac message yielded a content key for the given key!'
                               : 'A recipient yielded a content key, and the authentication tag is not the right one under it!');

    }


    // --------------------------------------------------------- serialization

    /** Read a COSE_Mac message, tagged or not. */
    public static parse(input: Uint8Array | CborValue): CoseMac {

        const value = input instanceof Uint8Array ? decode(input) : input;

        let isTagged = false;
        let message  = value;

        if (message.type === 'tag') {

            if (message.tag !== BigInt(COSE_MAC_TAG))
                throw new CoseError(`A COSE_Mac message must be tagged with CBOR tag ${String(COSE_MAC_TAG)}, but was tagged with CBOR tag ${String(message.tag)}!`);

            isTagged = true;
            message  = message.value;

        }

        if (message.type !== 'array')
            throw new CoseError(`A COSE_Mac message must be a CBOR array, but was a CBOR ${message.type}!`);

        if (message.items.length !== 5)
            throw new CoseError(`A COSE_Mac message must be a CBOR array of 5 elements, but had ${String(message.items.length)} element(s)!`);

        const [protectedBytes, unprotected, payload, tag, recipients] = message.items;

        if (protectedBytes?.type !== 'bytes')
            throw new CoseError('The protected header bucket of a COSE_Mac message must be a byte string!');

        if (unprotected === undefined)
            throw new CoseError('A COSE_Mac message must carry an unprotected header bucket!');

        if (payload === undefined || (payload.type !== 'null' && payload.type !== 'bytes'))
            throw new CoseError('The payload of a COSE_Mac message must be a byte string, or null when it is detached!');

        if (tag?.type !== 'bytes')
            throw new CoseError('The authentication tag of a COSE_Mac message must be a byte string!');

        if (recipients?.type !== 'array' || recipients.items.length === 0)
            throw new CoseError('A COSE_Mac message must carry a non-empty array of recipients!');

        return new CoseMac(protectedBytes.value,
                           CoseHeaders.parse(unprotected),
                           payload.type === 'bytes' ? payload.value : null,
                           tag.value,
                           recipients.items.map(each => CoseRecipient.parse(each)),
                           isTagged);

    }


    /** The CBOR form of this message. */
    public toCbor(): CborValue {

        const message = cbor.array([
            cbor.bytes(this.protectedHeaderBytes),
            this.unprotectedHeader.toCbor(),
            this.payload !== null ? cbor.bytes(this.payload) : cbor.nullValue,
            cbor.bytes(this.tag),
            cbor.array(this.recipients.map(each => each.toCbor())),
        ]);

        return this.isTagged ? cbor.tag(COSE_MAC_TAG, message) : message;

    }


    /** The CBOR encoding of this message. */
    public toBytes(): Uint8Array {
        return encode(this.toCbor());
    }


    public toString(): string {
        return `COSE_Mac${this.algorithm !== null ? ` ${this.algorithm.name}` : ''}, ${String(this.recipients.length)} recipient(s)`;
    }

}
