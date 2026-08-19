/*
 * Copyright (c) 2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr COSE <https://github.com/Vanaheimr/COSE.TS>
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * A COSE_recipient [RFC 9052, Section 5.1]: how a content key reaches one
 * party.
 *
 * ```
 * COSE_recipient = [
 *     Headers,
 *     ciphertext : bstr / nil,
 *     ? recipients : [+COSE_recipient]
 * ]
 * ```
 *
 * This is what separates `COSE_Encrypt` from `COSE_Encrypt0` and `COSE_Mac`
 * from `COSE_Mac0`. The bare forms assume both parties already hold the key;
 * the enveloped forms solve the distribution problem **inside the message**.
 * One content key protects the body, and one recipient structure per party
 * delivers that key by a route only that party can walk.
 *
 * Two routes are implemented here, and they are the two reachable from a
 * pre-shared secret:
 *
 *   - **`direct`** [RFC 9053, §6.1.1] — the recipient's key *is* the content
 *     key. Nothing is transported: the protected bucket and the ciphertext are
 *     both empty, and the structure exists only to name a key identifier.
 *   - **AES key wrap** [RFC 9053, §6.2.1, RFC 3394] — the content key is
 *     encrypted under a key-encryption key the recipient holds.
 *
 * Not implemented: ECDH key agreement and the HKDF-based key derivations. Both
 * need `COSE_KDF_Context` [RFC 9053, §5.2], a structure of its own carrying
 * PartyU and PartyV information and the supplementary public info — and one
 * whose fields, got subtly wrong, derive a key that agrees only with an
 * implementation making the same mistake. It is a piece of work in its own
 * right rather than a variation on this one.
 *
 * The `? recipients` at the end is not decoration: recipient structures nest,
 * so a key can be wrapped to a group whose key is in turn wrapped to its
 * members. Nesting is parsed and preserved here; building one is left to the
 * caller, who can pass nested recipients in.
 *
 * **What a recipient list costs in security, and it is not nothing.** Every
 * recipient of a `COSE_Mac` holds the same content key, so with more than one
 * of them a tag no longer even tells the recipients apart: any of them can
 * produce a message the others will accept as coming from the sender. RFC 9052
 * §8.2 puts it plainly — a MAC provides *"either no or very limited data
 * origination"*. For an encrypted message the same is true of its integrity
 * guarantee.
 */

import { algorithmToCbor, CoseAlgorithms }   from './algorithm.ts';
import type { CoseAlgorithm }                from './algorithm.ts';
import { aesKeyUnwrap, aesKeyWrap }          from './aes.ts';
import { cbor, NO_BYTES }                    from './cbor.ts';
import type { CborEntry, CborValue }         from './cbor.ts';
import { CoseError }                         from './errors.ts';
import { CoseHeaders }                       from './headers.ts';
import { KEY_TYPE_SYMMETRIC }                from './key.ts';
import type { CoseKey }                      from './key.ts';
import { HeaderLabel, label }                from './labels.ts';


/** What a party building a recipient structure may choose. */
export interface RecipientOptions {

    /** A key identifier for the unprotected bucket, defaulting to the key's own. */
    readonly keyIdentifier?:  Uint8Array | null;

    /** Recipient structures nested below this one. */
    readonly recipients?:     readonly CoseRecipient[];

}


export class CoseRecipient {

    /** The serialized protected bucket — empty for both implemented routes. */
    public readonly protectedHeaderBytes:  Uint8Array;

    /** The protected header parameters. */
    public readonly protectedHeader:       CoseHeaders;

    /** The unprotected header parameters, which is where `alg` and `kid` live here. */
    public readonly unprotectedHeader:     CoseHeaders;

    /** The wrapped content key, or a zero-length string for `direct`. */
    public readonly ciphertext:            Uint8Array;

    /** Recipient structures nested below this one. */
    public readonly recipients:            readonly CoseRecipient[];


    public constructor(protectedHeaderBytes: Uint8Array,
                       unprotectedHeader:    CoseHeaders | null,
                       ciphertext:           Uint8Array,
                       recipients:           readonly CoseRecipient[] = []) {

        this.protectedHeaderBytes  = protectedHeaderBytes;
        this.protectedHeader       = CoseHeaders.parseProtected(protectedHeaderBytes);
        this.unprotectedHeader     = unprotectedHeader ?? CoseHeaders.empty;
        this.ciphertext            = ciphertext;
        this.recipients            = [...recipients];

    }


    /** The recipient algorithm, protected bucket first. */
    public get algorithm(): CoseAlgorithm | null {
        return this.protectedHeader.algorithm ?? this.unprotectedHeader.algorithm;
    }

    /** The key identifier, protected bucket first. */
    public get keyIdentifier(): Uint8Array | null {
        return this.protectedHeader.keyIdentifier ?? this.unprotectedHeader.keyIdentifier;
    }


    // ---------------------------------------------------------- constructing

    /**
     * A `direct` recipient: the key it names *is* the content key.
     *
     * RFC 9053 §6.1.1 requires the protected bucket to be zero length, and
     * nothing is carried in the ciphertext either — so this structure conveys
     * a key identifier and an algorithm and no key material at all.
     */
    public static direct(key: CoseKey, options: RecipientOptions = {}): CoseRecipient {

        requireSymmetric(key, 'A direct recipient');

        return new CoseRecipient(NO_BYTES,
                                 headersFor(CoseAlgorithms.direct,
                                            options.keyIdentifier === undefined
                                                ? key.keyIdentifier
                                                : options.keyIdentifier),
                                 NO_BYTES,
                                 options.recipients ?? []);

    }


    /**
     * A key-wrap recipient: the content key, encrypted under the given
     * key-encryption key.
     *
     * The algorithm follows from the width of the *key-encryption* key rather
     * than from the content key, which is the direction people get wrong:
     * `A256KW` wraps a 128-bit content key perfectly well.
     */
    public static keyWrap(contentKey:        Uint8Array,
                          keyEncryptionKey:  CoseKey,
                          options:           RecipientOptions = {}): CoseRecipient {

        requireSymmetric(keyEncryptionKey, 'A key-wrap recipient');

        const kek       = keyEncryptionKey.privateKeyBytes();
        const algorithm = keyWrapAlgorithmFor(kek.length);

        if (keyEncryptionKey.algorithm !== null &&
            keyEncryptionKey.algorithm.id !== algorithm.id &&
            keyEncryptionKey.algorithm.family === 'keywrap')
            throw new CoseError(`The key-encryption key names '${keyEncryptionKey.algorithm.name}', but its ${String(kek.length)} bytes are '${algorithm.name}'!`);

        return new CoseRecipient(NO_BYTES,
                                 headersFor(algorithm,
                                            options.keyIdentifier === undefined
                                                ? keyEncryptionKey.keyIdentifier
                                                : options.keyIdentifier),
                                 aesKeyWrap(kek, contentKey),
                                 options.recipients ?? []);

    }


    // ------------------------------------------------------------ recovering

    /**
     * The content key this recipient carries, or null when the given key is
     * not the one it was built for.
     *
     * Null rather than an exception, and rather than a reason: a party holding
     * several keys tries them in turn, and "not this one" is the ordinary
     * answer rather than an error. For key wrap it is also the *only* honest
     * answer — RFC 3394's integrity check is what distinguishes a wrong key
     * from a right one, and saying more about which would say something about
     * the key.
     */
    public contentKey(key: CoseKey): Uint8Array | null {

        const algorithm = this.algorithm;

        if (algorithm === null)
            return null;

        if (key.keyType !== KEY_TYPE_SYMMETRIC)
            return null;

        if (algorithm.family === 'direct') {

            // "When this algorithm is used, the 'protected' field MUST be zero
            // length" [RFC 9053, §6.1.1] — and a non-empty ciphertext would be
            // key material this route is not supposed to carry.
            if (this.protectedHeaderBytes.length !== 0 || this.ciphertext.length !== 0)
                return null;

            return key.privateKeyBytes();

        }

        if (algorithm.family === 'keywrap')
            return aesKeyUnwrap(key.privateKeyBytes(), this.ciphertext);

        return null;

    }


    // --------------------------------------------------------- serialization

    /** Read a COSE_recipient. */
    public static parse(value: CborValue): CoseRecipient {

        if (value.type !== 'array')
            throw new CoseError(`A COSE_recipient must be a CBOR array, but was a CBOR ${value.type}!`);

        if (value.items.length !== 3 && value.items.length !== 4)
            throw new CoseError(`A COSE_recipient must be a CBOR array of 3 or 4 elements, but had ${String(value.items.length)} element(s)!`);

        const [protectedBytes, unprotected, ciphertext, nested] = value.items;

        if (protectedBytes?.type !== 'bytes')
            throw new CoseError('The protected header bucket of a COSE_recipient must be a byte string!');

        if (unprotected === undefined)
            throw new CoseError('A COSE_recipient must carry an unprotected header bucket!');

        if (ciphertext === undefined || (ciphertext.type !== 'bytes' && ciphertext.type !== 'null'))
            throw new CoseError('The ciphertext of a COSE_recipient must be a byte string, or null!');

        let recipients: CoseRecipient[] = [];

        if (nested !== undefined) {

            if (nested.type !== 'array' || nested.items.length === 0)
                throw new CoseError('The nested recipients of a COSE_recipient must be a non-empty CBOR array!');

            recipients = nested.items.map(each => CoseRecipient.parse(each));

        }

        return new CoseRecipient(protectedBytes.value,
                                 CoseHeaders.parse(unprotected),
                                 ciphertext.type === 'bytes' ? ciphertext.value : NO_BYTES,
                                 recipients);

    }


    /** The CBOR form of this recipient. */
    public toCbor(): CborValue {

        const items = [cbor.bytes(this.protectedHeaderBytes),
                       this.unprotectedHeader.toCbor(),
                       cbor.bytes(this.ciphertext)];

        if (this.recipients.length > 0)
            items.push(cbor.array(this.recipients.map(each => each.toCbor())));

        return cbor.array(items);

    }


    public toString(): string {
        return `${this.algorithm?.name ?? 'unknown'} recipient, ${String(this.ciphertext.length)} bytes`;
    }

}


/** The key-wrap algorithm a key-encryption key of the given width belongs to. */
export function keyWrapAlgorithmFor(keySize: number): CoseAlgorithm {

    switch (keySize) {
        case 16: return CoseAlgorithms.A128KW;
        case 24: return CoseAlgorithms.A192KW;
        case 32: return CoseAlgorithms.A256KW;
    }

    throw new CoseError(`AES key wrap needs a key-encryption key of 16, 24 or 32 bytes, but a ${String(keySize)}-byte key was given!`);

}


function requireSymmetric(key: CoseKey, what: string): void {

    if (key.keyType !== KEY_TYPE_SYMMETRIC)
        throw new CoseError(`${what} needs a COSE key of key type Symmetric, but a key of key type ${String(key.keyType)} was given!`);

}


/**
 * The unprotected bucket of a recipient: its algorithm, and its key identifier
 * when there is one.
 *
 * Both live in the *unprotected* bucket, which is what the published examples
 * do and what `direct` requires — its protected bucket must be zero length, so
 * there is nowhere else for the algorithm to go.
 */
function headersFor(algorithm: CoseAlgorithm, keyIdentifier: Uint8Array | null): CoseHeaders {

    const parameters: CborEntry[] = [
        [label(HeaderLabel.algorithm), algorithmToCbor(algorithm)],
    ];

    if (keyIdentifier !== null)
        parameters.push([label(HeaderLabel.keyIdentifier), cbor.bytes(keyIdentifier)]);

    return new CoseHeaders(parameters);

}
