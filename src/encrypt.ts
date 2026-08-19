/*
 * Copyright (c) 2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr COSE <https://github.com/Vanaheimr/COSE.TS>
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * The encrypted COSE structures [RFC 9052, Section 5]: `COSE_Encrypt0`
 * (CBOR tag 16) and `COSE_Encrypt` (CBOR tag 96), with AES-GCM.
 *
 * ```
 * COSE_Encrypt0 = [ Headers, ciphertext : bstr / nil ]
 * COSE_Encrypt  = [ Headers, ciphertext : bstr / nil, recipients : [+COSE_recipient] ]
 * ```
 *
 * Three things about these differ from everything else in this package, and
 * all three catch people out.
 *
 * **The `Enc_structure` has three elements, not four.** It is
 * `[context, protected, external_aad]` — no payload. That is not an oversight:
 * the payload is what is being *encrypted*, and the `Enc_structure` is what is
 * merely *authenticated* alongside it. It becomes the AEAD's additional data,
 * so the recipient rebuilds it from the message rather than receiving it.
 *
 * **The authentication tag is not a field.** AES-GCM's 16-byte tag is appended
 * to the ciphertext and travels inside the same byte string. An implementation
 * giving it a field of its own interoperates with nothing.
 *
 * **The nonce is public and must never repeat.** It travels in the `iv` header
 * parameter, in the clear, and that is fine — what is not fine is using one
 * twice with the same key. GCM fails catastrophically on nonce reuse: two
 * messages under one nonce leak the XOR of their plaintexts *and* the
 * authentication subkey, which lets an attacker forge afterwards. The nonce is
 * therefore never generated here. The caller passes it, because only the
 * caller knows whether it has been used before.
 *
 * And the point worth keeping in view: an encrypted message says nothing about
 * *who* sent it. AEAD integrity means "whoever holds this key wrote this",
 * which with several recipients means any of them. RFC 9052 §8.3 says as much:
 * content encryption provides *"either no or very limited data origination"*.
 * A signed payload inside an encrypted envelope is how one gets both.
 */

import { aesGcmDecrypt, aesGcmEncrypt,
         GCM_NONCE_SIZE }                    from './aes.ts';
import { algorithmToCbor }                   from './algorithm.ts';
import type { CoseAlgorithm }                from './algorithm.ts';
import { cbor, decode, encode, NO_BYTES }    from './cbor.ts';
import type { CborEntry, CborValue }         from './cbor.ts';
import { CoseError, notDecrypted }           from './errors.ts';
import type { Decryption }                   from './errors.ts';
import { CoseHeaders,
         verifyCriticalHeaderParameters }    from './headers.ts';
import { KEY_TYPE_SYMMETRIC }                from './key.ts';
import type { CoseKey }                      from './key.ts';
import { HeaderLabel, label }                from './labels.ts';
import { CoseRecipient }                     from './recipient.ts';


/** The CBOR tag of a COSE_Encrypt0 message. */
export const COSE_ENCRYPT0_TAG = 16;

/** The CBOR tag of a COSE_Encrypt message. */
export const COSE_ENCRYPT_TAG = 96;

/** The context string of a COSE_Encrypt0 [RFC 9052, Section 5.3]. */
export const ENCRYPT0_CONTEXT = 'Encrypt0';

/** The context string of the body of a COSE_Encrypt. */
export const ENCRYPT_CONTEXT = 'Encrypt';


/**
 * The encoded `Enc_structure` [RFC 9052, Section 5.3]:
 *
 * ```
 * Enc_structure = [ context, protected : empty_or_serialized_map, external_aad : bstr ]
 * ```
 */
export function encStructure(context:              string,
                             protectedHeaderBytes: Uint8Array,
                             externalAad:          Uint8Array | null = null): Uint8Array {

    return encode(cbor.array([
        cbor.text(context),
        cbor.bytes(protectedHeaderBytes),
        cbor.bytes(externalAad ?? NO_BYTES),
    ]));

}


/** What a party encrypting may choose. */
export interface EncryptOptions {

    /**
     * The nonce, which is required.
     *
     * There is no default and there will not be one. A nonce reused with the
     * same key breaks AES-GCM outright, and this package has no way of knowing
     * which nonces a caller has already spent.
     */
    readonly iv:               Uint8Array;

    /** A key identifier for the unprotected bucket, defaulting to the key's own. */
    readonly keyIdentifier?:   Uint8Array | null;

    /** Data authenticated along with the payload without travelling in the message. */
    readonly externalAad?:     Uint8Array | null;

    /** Whether to omit the ciphertext from the message. */
    readonly detachPayload?:   boolean;

    /** Whether to wrap the message within its CBOR tag. Defaults to true. */
    readonly tagged?:          boolean;

}


/** What a party decrypting may have to supply. */
export interface DecryptOptions {

    /** The data that was authenticated along with the payload. */
    readonly externalAad?:        Uint8Array | null;

    /** The ciphertext, when the message carries a detached one. */
    readonly detachedCiphertext?: Uint8Array | null;

    /** The algorithm the caller expects. */
    readonly expectedAlgorithm?:  CoseAlgorithm | null;

    /** Header parameters the caller processes itself. */
    readonly alsoUnderstood?:     readonly CborValue[];

}


/** Everything the two encrypted structures share. */
abstract class CoseEncryptedBase {

    /** The serialized protected bucket, exactly as authenticated and received. */
    public readonly protectedHeaderBytes:  Uint8Array;

    /** The protected header parameters, which the AEAD tag covers. */
    public readonly protectedHeader:       CoseHeaders;

    /** The unprotected header parameters, which it does not. */
    public readonly unprotectedHeader:     CoseHeaders;

    /** The ciphertext with the AEAD tag appended, or null when detached. */
    public readonly ciphertext:            Uint8Array | null;

    /** Whether this message is wrapped within its CBOR tag. */
    public readonly isTagged:              boolean;


    protected constructor(protectedHeaderBytes: Uint8Array,
                          unprotectedHeader:    CoseHeaders | null,
                          ciphertext:           Uint8Array | null,
                          isTagged:             boolean) {

        this.protectedHeaderBytes  = protectedHeaderBytes;
        this.protectedHeader       = CoseHeaders.parseProtected(protectedHeaderBytes);
        this.unprotectedHeader     = unprotectedHeader ?? CoseHeaders.empty;
        this.ciphertext            = ciphertext;
        this.isTagged              = isTagged;

    }


    /** The content encryption algorithm, protected bucket first. */
    public get algorithm(): CoseAlgorithm | null {
        return this.protectedHeader.algorithm ?? this.unprotectedHeader.algorithm;
    }

    /** The key identifier, protected bucket first. */
    public get keyIdentifier(): Uint8Array | null {
        return this.protectedHeader.keyIdentifier ?? this.unprotectedHeader.keyIdentifier;
    }

    /** The nonce, from either bucket. It travels in the clear and must never repeat. */
    public get iv(): Uint8Array | null {

        const value = this.protectedHeader.get(label(HeaderLabel.iv)) ??
                      this.unprotectedHeader.get(label(HeaderLabel.iv));

        if (value === null)
            return null;

        if (value.type !== 'bytes')
            throw new CoseError('The initialization vector of a COSE message must be a byte string!');

        return value.value;

    }

    /** Whether the ciphertext is detached. */
    public get isDetached(): boolean {
        return this.ciphertext === null;
    }


    /**
     * Decrypt with a content encryption key that has already been established.
     *
     * The shared half of both structures: `COSE_Encrypt0` uses it with the key
     * the caller passed, `COSE_Encrypt` with the one a recipient yielded.
     */
    protected decryptWith(contentKey:  Uint8Array,
                          context:     string,
                          options:     DecryptOptions): Decryption {

        const critical = verifyCriticalHeaderParameters(this.protectedHeader,
                                                        this.unprotectedHeader,
                                                        options.alsoUnderstood ?? []);

        if (!critical.verified)
            return notDecrypted(critical.reason);

        const algorithm = options.expectedAlgorithm ?? this.protectedHeader.algorithm
                                                    ?? this.unprotectedHeader.algorithm;

        if (algorithm === null)
            return notDecrypted('This COSE message does not state its content encryption algorithm: pass the expected algorithm explicitly!');

        const stated = this.algorithm;

        if (stated !== null && stated.id !== algorithm.id)
            return notDecrypted(`This COSE message was encrypted with the algorithm '${stated.name}', but the algorithm '${algorithm.name}' was expected!`);

        if (algorithm.family !== 'aesgcm')
            return notDecrypted(`The COSE algorithm '${algorithm.name}' is not a content encryption algorithm this implementation supports!`);

        if (algorithm.keySize !== null && contentKey.length !== algorithm.keySize)
            return notDecrypted(`The algorithm '${algorithm.name}' needs a ${String(algorithm.keySize)}-byte key, but the content key is ${String(contentKey.length)} bytes long!`);

        let nonce: Uint8Array | null;

        try {
            nonce = this.iv;
        }
        catch (exception) {
            return notDecrypted(exception instanceof Error ? exception.message : String(exception));
        }

        if (nonce === null)
            return notDecrypted('This COSE message carries no initialization vector!');

        if (nonce.length !== GCM_NONCE_SIZE)
            return notDecrypted(`AES-GCM within COSE uses a ${String(GCM_NONCE_SIZE)}-byte nonce, but this message carries a ${String(nonce.length)}-byte one!`);

        const carried = this.ciphertext;
        const given   = options.detachedCiphertext ?? null;

        if (carried !== null && given !== null)
            return notDecrypted('This COSE message carries its ciphertext, and a detached ciphertext was supplied as well!');

        const body = carried ?? given;

        if (body === null)
            return notDecrypted('This COSE message carries a detached ciphertext, which has to be supplied in order to decrypt it!');

        const plaintext = aesGcmDecrypt(contentKey, nonce, body,
                                        encStructure(context,
                                                     this.protectedHeaderBytes,
                                                     options.externalAad ?? null));

        return plaintext === null
                   ? notDecrypted('The ciphertext does not authenticate under this key: it was altered, or the key, the nonce or the additional data is not the right one!')
                   : { decrypted: true, plaintext };

    }

}


/**
 * A COSE_Encrypt0 message: encrypted for a recipient who already holds the key.
 */
export class CoseEncrypt0 extends CoseEncryptedBase {

    public constructor(protectedHeaderBytes: Uint8Array,
                       unprotectedHeader:    CoseHeaders | null,
                       ciphertext:           Uint8Array | null,
                       isTagged              = true) {
        super(protectedHeaderBytes, unprotectedHeader, ciphertext, isTagged);
    }


    /** The encoded Enc_structure of this message. */
    public toBeEncrypted(externalAad: Uint8Array | null = null): Uint8Array {
        return encStructure(ENCRYPT0_CONTEXT, this.protectedHeaderBytes, externalAad);
    }


    /** Encrypt a payload, with the algorithm in the protected bucket. */
    public static encrypt(plaintext: Uint8Array,
                          key:       CoseKey,
                          options:   EncryptOptions): CoseEncrypt0 {

        const algorithm = requireAesGcm(key);

        const keyIdentifier = options.keyIdentifier === undefined
                                  ? key.keyIdentifier
                                  : options.keyIdentifier;

        const unprotected: CborEntry[] = [[label(HeaderLabel.iv), cbor.bytes(options.iv)]];

        if (keyIdentifier !== null)
            unprotected.push([label(HeaderLabel.keyIdentifier), cbor.bytes(keyIdentifier)]);

        return CoseEncrypt0.encryptWithHeaders(
                   plaintext, key,
                   new CoseHeaders([[label(HeaderLabel.algorithm), algorithmToCbor(algorithm)]]),
                   new CoseHeaders(unprotected),
                   options);

    }


    /** Encrypt a payload with header buckets the caller composed. */
    public static encryptWithHeaders(plaintext:          Uint8Array,
                                     key:                CoseKey,
                                     protectedHeader:    CoseHeaders,
                                     unprotectedHeader:  CoseHeaders | null,
                                     options:            EncryptOptions): CoseEncrypt0 {

        const algorithm = protectedHeader.algorithm ?? requireAesGcm(key);

        requireUsable(key, algorithm);

        const protectedBytes = protectedHeader.toProtectedBytes();

        const ciphertext = aesGcmEncrypt(key.privateKeyBytes(),
                                         options.iv,
                                         plaintext,
                                         encStructure(ENCRYPT0_CONTEXT, protectedBytes,
                                                      options.externalAad ?? null));

        return new CoseEncrypt0(protectedBytes,
                                unprotectedHeader,
                                options.detachPayload === true ? null : ciphertext,
                                options.tagged ?? true);

    }


    /** Decrypt this message with the key it was encrypted for. */
    public decrypt(key: CoseKey, options: DecryptOptions = {}): Decryption {

        if (key.keyType !== KEY_TYPE_SYMMETRIC)
            return notDecrypted(`A COSE_Encrypt0 message needs a key of key type Symmetric, but a key of key type ${String(key.keyType)} was given!`);

        return this.decryptWith(key.privateKeyBytes(), ENCRYPT0_CONTEXT, options);

    }


    /** Read a COSE_Encrypt0 message, tagged or not. */
    public static parse(input: Uint8Array | CborValue): CoseEncrypt0 {

        const { isTagged, items } = untag(input, COSE_ENCRYPT0_TAG, 3, 'COSE_Encrypt0');

        const [protectedBytes, unprotected, ciphertext] = items;

        return new CoseEncrypt0(bytesOfProtected(protectedBytes, 'COSE_Encrypt0'),
                                CoseHeaders.parse(unprotected!),
                                ciphertextOf(ciphertext!, 'COSE_Encrypt0'),
                                isTagged);

    }


    /** The CBOR form of this message. */
    public toCbor(): CborValue {

        const message = cbor.array([
            cbor.bytes(this.protectedHeaderBytes),
            this.unprotectedHeader.toCbor(),
            this.ciphertext !== null ? cbor.bytes(this.ciphertext) : cbor.nullValue,
        ]);

        return this.isTagged ? cbor.tag(COSE_ENCRYPT0_TAG, message) : message;

    }


    /** The CBOR encoding of this message. */
    public toBytes(): Uint8Array {
        return encode(this.toCbor());
    }


    public toString(): string {
        return `COSE_Encrypt0${this.algorithm !== null ? ` ${this.algorithm.name}` : ''}, ${String(this.ciphertext?.length ?? 0)} bytes`;
    }

}


/**
 * A COSE_Encrypt message: encrypted once, with the content key delivered to
 * each recipient in a structure of its own.
 */
export class CoseEncrypt extends CoseEncryptedBase {

    /** How the content key reaches each party. */
    public readonly recipients: readonly CoseRecipient[];


    public constructor(protectedHeaderBytes: Uint8Array,
                       unprotectedHeader:    CoseHeaders | null,
                       ciphertext:           Uint8Array | null,
                       recipients:           readonly CoseRecipient[],
                       isTagged              = true) {

        super(protectedHeaderBytes, unprotectedHeader, ciphertext, isTagged);

        if (recipients.length === 0)
            throw new CoseError('A COSE_Encrypt message must carry at least one recipient!');

        this.recipients = [...recipients];

    }


    /** The encoded Enc_structure of this message. */
    public toBeEncrypted(externalAad: Uint8Array | null = null): Uint8Array {
        return encStructure(ENCRYPT_CONTEXT, this.protectedHeaderBytes, externalAad);
    }


    /**
     * Encrypt a payload under a content key, and deliver that key to each
     * recipient.
     *
     * The content key is the caller's, not this method's, for the same reason
     * the nonce is: generating one here would make the message
     * unreproducible, and a caller who has a key management scheme has one for
     * a reason.
     */
    public static encrypt(plaintext:   Uint8Array,
                          contentKey:  CoseKey,
                          recipients:  readonly CoseRecipient[],
                          options:     EncryptOptions): CoseEncrypt {

        const algorithm      = requireAesGcm(contentKey);

        requireUsable(contentKey, algorithm);

        const protectedHeader = new CoseHeaders([
            [label(HeaderLabel.algorithm), algorithmToCbor(algorithm)],
        ]);

        const protectedBytes  = protectedHeader.toProtectedBytes();

        const ciphertext = aesGcmEncrypt(contentKey.privateKeyBytes(),
                                         options.iv,
                                         plaintext,
                                         encStructure(ENCRYPT_CONTEXT, protectedBytes,
                                                      options.externalAad ?? null));

        return new CoseEncrypt(protectedBytes,
                               new CoseHeaders([[label(HeaderLabel.iv), cbor.bytes(options.iv)]]),
                               options.detachPayload === true ? null : ciphertext,
                               recipients,
                               options.tagged ?? true);

    }


    /**
     * Decrypt this message with a key one of its recipients was built for.
     *
     * Every recipient is tried, because a party holding one key does not
     * generally know which entry in the list is theirs. A recipient that does
     * not yield a key is not an error — it is somebody else's.
     */
    public decrypt(key: CoseKey, options: DecryptOptions = {}): Decryption {

        if (key.keyType !== KEY_TYPE_SYMMETRIC)
            return notDecrypted(`A COSE_Encrypt message needs a key of key type Symmetric, but a key of key type ${String(key.keyType)} was given!`);

        let tried = 0;

        for (const recipient of this.recipients) {

            const contentKey = recipient.contentKey(key);

            if (contentKey === null)
                continue;

            tried++;

            const result = this.decryptWith(contentKey, ENCRYPT_CONTEXT, options);

            if (result.decrypted)
                return result;

        }

        return notDecrypted(tried === 0
                                ? 'None of the recipients of this COSE_Encrypt message yielded a content key for the given key!'
                                : 'A recipient yielded a content key, but the ciphertext did not authenticate under it!');

    }


    /** Read a COSE_Encrypt message, tagged or not. */
    public static parse(input: Uint8Array | CborValue): CoseEncrypt {

        const { isTagged, items } = untag(input, COSE_ENCRYPT_TAG, 4, 'COSE_Encrypt');


        const [protectedBytes, unprotected, ciphertext, recipients] = items;

        if (recipients?.type !== 'array' || recipients.items.length === 0)
            throw new CoseError('A COSE_Encrypt message must carry a non-empty array of recipients!');

        return new CoseEncrypt(bytesOfProtected(protectedBytes, 'COSE_Encrypt'),
                               CoseHeaders.parse(unprotected!),
                               ciphertextOf(ciphertext!, 'COSE_Encrypt'),
                               recipients.items.map(each => CoseRecipient.parse(each)),
                               isTagged);

    }


    /** The CBOR form of this message. */
    public toCbor(): CborValue {

        const message = cbor.array([
            cbor.bytes(this.protectedHeaderBytes),
            this.unprotectedHeader.toCbor(),
            this.ciphertext !== null ? cbor.bytes(this.ciphertext) : cbor.nullValue,
            cbor.array(this.recipients.map(each => each.toCbor())),
        ]);

        return this.isTagged ? cbor.tag(COSE_ENCRYPT_TAG, message) : message;

    }


    /** The CBOR encoding of this message. */
    public toBytes(): Uint8Array {
        return encode(this.toCbor());
    }


    public toString(): string {
        return `COSE_Encrypt${this.algorithm !== null ? ` ${this.algorithm.name}` : ''}, ${String(this.recipients.length)} recipient(s)`;
    }

}


// ---------------------------------------------------------------- helpers ---

function untag(input:    Uint8Array | CborValue,
               tag:      number,
               elements: number,
               what:     string): { isTagged: boolean; items: readonly (CborValue | undefined)[] } {

    const value = input instanceof Uint8Array ? decode(input) : input;

    let isTagged = false;
    let message  = value;

    if (message.type === 'tag') {

        if (message.tag !== BigInt(tag))
            throw new CoseError(`A ${what} message must be tagged with CBOR tag ${String(tag)}, but was tagged with CBOR tag ${String(message.tag)}!`);

        isTagged = true;
        message  = message.value;

    }

    if (message.type !== 'array')
        throw new CoseError(`A ${what} message must be a CBOR array, but was a CBOR ${message.type}!`);

    if (message.items.length !== elements)
        throw new CoseError(`A ${what} message must be a CBOR array of ${String(elements)} elements, but had ${String(message.items.length)} element(s)!`);

    return { isTagged, items: message.items };

}


function bytesOfProtected(value: CborValue | undefined, what: string): Uint8Array {

    if (value?.type !== 'bytes')
        throw new CoseError(`The protected header bucket of a ${what} message must be a byte string!`);

    return value.value;

}


function ciphertextOf(value: CborValue, what: string): Uint8Array | null {

    if (value.type === 'null')
        return null;

    if (value.type !== 'bytes')
        throw new CoseError(`The ciphertext of a ${what} message must be a byte string, or null when it is detached!`);

    return value.value;

}


/** The AES-GCM algorithm a key names, refusing a key that names something else. */
function requireAesGcm(key: CoseKey): CoseAlgorithm {

    if (key.algorithm === null)
        throw new CoseError('An encrypted COSE message needs a content encryption algorithm: either on the key or within the protected header bucket!');

    if (key.algorithm.family !== 'aesgcm')
        throw new CoseError(`The COSE algorithm '${key.algorithm.name}' is not a content encryption algorithm this implementation supports!`);

    return key.algorithm;

}


/**
 * The key checks of RFC 9053 Section 4.1.
 *
 * The width check is the one that earns its place: `A128GCM` and `A256GCM` are
 * one cipher and two identifiers, so a key of the wrong width is not a
 * different strength but a different algorithm, and letting it through would
 * silently produce a message nobody can read.
 */
function requireUsable(key: CoseKey, algorithm: CoseAlgorithm): void {

    if (algorithm.family !== 'aesgcm')
        throw new CoseError(`The COSE algorithm '${algorithm.name}' is not a content encryption algorithm this implementation supports!`);

    if (key.keyType !== KEY_TYPE_SYMMETRIC)
        throw new CoseError(`An encrypted COSE message needs a key of key type Symmetric [RFC 9053, Section 4.1], but a key of key type ${String(key.keyType)} was given!`);

    if (key.algorithm !== null && key.algorithm.id !== algorithm.id)
        throw new CoseError(`This message is to be encrypted with '${algorithm.name}', but the key names '${key.algorithm.name}' [RFC 9053, Section 4.1]!`);

    const width = key.privateKeyBytes().length;

    if (algorithm.keySize !== null && width !== algorithm.keySize)
        throw new CoseError(`The algorithm '${algorithm.name}' needs a ${String(algorithm.keySize)}-byte key, but a ${String(width)}-byte key was given!`);

}
