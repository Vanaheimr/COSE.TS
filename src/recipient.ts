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
 * Four routes are implemented here. Two of them start from a secret both
 * parties already hold:
 *
 *   - **`direct`** [RFC 9053, §6.1.1] — the recipient's key *is* the content
 *     key. Nothing is transported: the protected bucket and the ciphertext are
 *     both empty, and the structure exists only to name a key identifier.
 *   - **AES key wrap** [RFC 9053, §6.2.1, RFC 3394] — the content key is
 *     encrypted under a key-encryption key the recipient holds.
 *
 * The other two need nothing shared at all, only the recipient's public key
 * [RFC 9053, §6.3]; how the key is agreed is told in `ecdh.ts`:
 *
 *   - **ECDH-ES + HKDF** — the agreed key *is* the content key, so a message
 *     may carry only this one recipient.
 *   - **ECDH-ES + AES key wrap** — the agreed key wraps the content key, so
 *     every recipient gets the same content key through a key of their own.
 *
 * Not implemented: the static-static variants (ECDH-SS), in which the sender
 * agrees the key with a long-lived key of its own rather than with one made
 * for the message. What they add is that the recipient learns who sent it,
 * and a signature inside the envelope says that already — to everybody, not
 * only to the recipient.
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
import { KEY_TYPE_EC2, KEY_TYPE_OKP }        from './curve.ts';
import type { CoseCurve }                    from './curve.ts';
import { ecdhSharedSecret, hkdfDerive,
         isEcdhCurve, kdfContext }           from './ecdh.ts';
import type { PartyInfo }                    from './ecdh.ts';
import type { DigestAlgorithm }              from './ecdsa.ts';
import { CoseError }                         from './errors.ts';
import { CoseHeaders }                       from './headers.ts';
import { CoseKey, KEY_TYPE_SYMMETRIC }       from './key.ts';
import { HeaderLabel, label }                from './labels.ts';


/** What a party building a recipient structure may choose. */
export interface RecipientOptions {

    /** A key identifier for the unprotected bucket, defaulting to the key's own. */
    readonly keyIdentifier?:  Uint8Array | null;

    /** Recipient structures nested below this one. */
    readonly recipients?:     readonly CoseRecipient[];

}


/**
 * What a sender agreeing a key by ECDH-ES may add: an HKDF salt, and what the
 * two parties say about themselves in the KDF context. All of it travels in
 * the recipient's unprotected bucket, so the recipient rebuilds the same
 * derivation without being told anything out of band.
 */
export interface EcdhRecipientOptions extends RecipientOptions {

    /** The HKDF salt (header parameter -20); absent by default. */
    readonly salt?:     Uint8Array | null;

    /** The sender's PartyU information (header parameters -21 to -23). */
    readonly partyU?:   PartyInfo;

    /** The recipient's PartyV information (header parameters -24 to -26). */
    readonly partyV?:   PartyInfo;

}


/**
 * A recipient structure for direct key agreement, and the content key it
 * agreed — which the caller encrypts or authenticates with, and which never
 * travels.
 */
export interface AgreedRecipient {
    readonly recipient:   CoseRecipient;
    readonly contentKey:  CoseKey;
}


export class CoseRecipient {

    /** The serialized protected bucket — empty for `direct` and key wrap. */
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


    /**
     * An ECDH-ES recipient with direct key agreement [RFC 9053, §6.3]: the
     * key agreed with the recipient's public key *is* the content key.
     *
     * Returns the structure and the content key together, because the second
     * is what the message is then encrypted or authenticated with:
     *
     * ```typescript
     * const { recipient, contentKey } =
     *     CoseRecipient.ecdhDirect(theirPublicKey, ephemeralKey, CoseAlgorithms.A128GCM);
     *
     * const message = CoseEncrypt.encrypt(plaintext, contentKey, [recipient], { iv });
     * ```
     *
     * `contentAlgorithm` is part of the derivation — the content key is
     * derived *for* it — so it has to be the algorithm of the message.
     * `ephemeralKey` is a private key on the recipient's curve, made for this
     * one message; reusing it hands every message to the same recipient the
     * same content key.
     */
    public static ecdhDirect(recipientKey:      CoseKey,
                             ephemeralKey:      CoseKey,
                             contentAlgorithm:  CoseAlgorithm,
                             options:           EcdhRecipientOptions & {
                                                    readonly algorithm?: CoseAlgorithm } = {}): AgreedRecipient {

        const algorithm = options.algorithm ?? CoseAlgorithms.ECDH_ES_HKDF_256;

        if (algorithm.family !== 'ecdh-direct')
            throw new CoseError(`The COSE algorithm '${algorithm.name}' is not a direct ECDH key agreement algorithm!`);

        const keyLength      = contentKeySizeOf(contentAlgorithm);
        const protectedBytes = protectedFor(algorithm);
        const secret         = agree(ephemeralKey, recipientKey);

        const contentKey = hkdfDerive(hashOf(algorithm),
                                      secret,
                                      kdfContext({ algorithmId:     contentAlgorithm.id,
                                                   keyLength,
                                                   protectedBytes,
                                                   ...partiesOf(options) }),
                                      keyLength,
                                      options.salt ?? null);

        return {
            recipient:   new CoseRecipient(protectedBytes,
                                           ecdhHeadersFor(ephemeralKey, options, recipientKey),
                                           NO_BYTES,
                                           options.recipients ?? []),
            contentKey:  CoseKey.fromSymmetricKey(contentKey, { algorithm: contentAlgorithm }),
        };

    }


    /**
     * An ECDH-ES recipient with key wrap [RFC 9053, §6.3]: the key agreed
     * with the recipient's public key wraps the content key.
     *
     * `algorithm` is one of `ECDH-ES + A128KW`, `+ A192KW` or `+ A256KW`, and
     * names the width of the key-encryption key, which is agreed rather than
     * held. Unlike direct agreement, any number of these may share a message:
     * each recipient unwraps the one content key with a key of its own.
     */
    public static ecdhKeyWrap(contentKey:    Uint8Array,
                              recipientKey:  CoseKey,
                              ephemeralKey:  CoseKey,
                              algorithm:     CoseAlgorithm,
                              options:       EcdhRecipientOptions = {}): CoseRecipient {

        if (algorithm.family !== 'ecdh-keywrap' || algorithm.keySize === null)
            throw new CoseError(`The COSE algorithm '${algorithm.name}' is not an ECDH key agreement with key wrap!`);

        const protectedBytes = protectedFor(algorithm);
        const secret         = agree(ephemeralKey, recipientKey);

        const keyEncryptionKey = hkdfDerive(hashOf(algorithm),
                                            secret,
                                            kdfContext({ algorithmId:     keyWrapAlgorithmFor(algorithm.keySize).id,
                                                         keyLength:       algorithm.keySize,
                                                         protectedBytes,
                                                         ...partiesOf(options) }),
                                            algorithm.keySize,
                                            options.salt ?? null);

        return new CoseRecipient(protectedBytes,
                                 ecdhHeadersFor(ephemeralKey, options, recipientKey),
                                 aesKeyWrap(keyEncryptionKey, contentKey),
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
     *
     * `contentAlgorithm` is the algorithm of the enclosing message. Only
     * direct key agreement needs it, because there the content key is derived
     * *for* that algorithm; the enclosing message passes it in.
     */
    public contentKey(key:              CoseKey,
                      contentAlgorithm: CoseAlgorithm | null = null): Uint8Array | null {

        const algorithm = this.algorithm;

        if (algorithm === null)
            return null;

        if (algorithm.family === 'ecdh-direct' || algorithm.family === 'ecdh-keywrap')
            return this.agreedContentKey(algorithm, key, contentAlgorithm);

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


    /**
     * The content key of an ECDH-ES recipient, agreed between the given
     * private key and the ephemeral key the sender left in the headers.
     *
     * Null for every way of not being this recipient's key: a key without a
     * private half, one on another curve, an ephemeral key that is missing or
     * not a point, and — for direct agreement — a call that does not say
     * which content algorithm the key is for, since the derivation depends on
     * it and a guess would derive a key for the wrong one.
     */
    private agreedContentKey(algorithm:        CoseAlgorithm,
                             key:              CoseKey,
                             contentAlgorithm: CoseAlgorithm | null): Uint8Array | null {

        if ((key.keyType !== KEY_TYPE_EC2 && key.keyType !== KEY_TYPE_OKP) || !key.isPrivate)
            return null;

        const ephemeralValue = this.parameter(HeaderLabel.ephemeralKey);

        if (ephemeralValue === null)
            return null;

        let secret:   Uint8Array;
        let salt:     Uint8Array | null;
        let parties:  { partyU: PartyInfo; partyV: PartyInfo };

        try {

            const ephemeral = CoseKey.parse(ephemeralValue);

            if (ephemeral.keyType !== key.keyType || ephemeral.curveId !== key.curveId)
                return null;

            secret   = agree(key, ephemeral);
            salt     = this.bytesParameter(HeaderLabel.salt);
            parties  = {
                partyU: this.partyInfo(HeaderLabel.partyUIdentity, HeaderLabel.partyUNonce, HeaderLabel.partyUOther),
                partyV: this.partyInfo(HeaderLabel.partyVIdentity, HeaderLabel.partyVNonce, HeaderLabel.partyVOther),
            };

        }
        catch {
            return null;
        }

        if (algorithm.family === 'ecdh-direct') {

            // The agreed key is the content key: nothing to unwrap, and
            // nothing that may pretend to be something to unwrap.
            if (contentAlgorithm === null || this.ciphertext.length !== 0)
                return null;

            let keyLength: number;

            try {
                keyLength = contentKeySizeOf(contentAlgorithm);
            }
            catch {
                return null;
            }

            return hkdfDerive(hashOf(algorithm),
                              secret,
                              kdfContext({ algorithmId:     contentAlgorithm.id,
                                           keyLength,
                                           protectedBytes:  this.protectedHeaderBytes,
                                           ...parties }),
                              keyLength,
                              salt);

        }

        if (algorithm.keySize === null)
            return null;

        const keyEncryptionKey = hkdfDerive(hashOf(algorithm),
                                            secret,
                                            kdfContext({ algorithmId:     keyWrapAlgorithmFor(algorithm.keySize).id,
                                                         keyLength:       algorithm.keySize,
                                                         protectedBytes:  this.protectedHeaderBytes,
                                                         ...parties }),
                                            algorithm.keySize,
                                            salt);

        return aesKeyUnwrap(keyEncryptionKey, this.ciphertext);

    }


    /** A header parameter of this recipient, protected bucket first. */
    private parameter(labelValue: number): CborValue | null {
        return this.protectedHeader.get(label(labelValue))
            ?? this.unprotectedHeader.get(label(labelValue));
    }


    /** A byte-string header parameter, or null when absent; any other type is refused. */
    private bytesParameter(labelValue: number): Uint8Array | null {

        const value = this.parameter(labelValue);

        if (value === null)
            return null;

        if (value.type !== 'bytes')
            throw new CoseError('An ECDH header parameter that must be a byte string was not!');

        return value.value;

    }


    private partyInfo(identity: number, nonce: number, other: number): PartyInfo {

        const nonceValue = this.parameter(nonce);

        if (nonceValue !== null && nonceValue.type !== 'bytes' && nonceValue.type !== 'int')
            throw new CoseError('A party nonce must be a byte string or an integer!');

        return {
            identity:  this.bytesParameter(identity),
            nonce:     nonceValue === null         ? null
                     : nonceValue.type === 'bytes' ? nonceValue.value
                     :                               Number(nonceValue.value),
            other:     this.bytesParameter(other),
        };

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


/**
 * Whether a message with these recipients may be built: one that agrees its
 * content key directly with a recipient may have only that recipient
 * [RFC 9053, §6.3], since every other recipient would have to be handed the
 * key that recipient agreed — which is the one thing ECDH-ES is there to
 * keep from anybody else.
 */
export function requireRecipientsCompatible(recipients: readonly CoseRecipient[], what: string): void {

    if (recipients.length > 1 && recipients.some(each => each.algorithm?.family === 'ecdh-direct'))
        throw new CoseError(`${what} with a direct ECDH key agreement recipient may have only that one recipient!`);

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


// ------------------------------------------------------------------- ECDH ---

/**
 * The raw ECDH secret of a private key and a public key, after checking that
 * the two can agree one at all: both on the same curve, and that curve one
 * this build agrees keys on.
 */
function agree(privateKey: CoseKey, publicKey: CoseKey): Uint8Array {

    const curve = requireAgreementCurve(privateKey, 'The private key');

    if (requireAgreementCurve(publicKey, 'The public key').id !== curve.id)
        throw new CoseError(`ECDH needs both keys on the same curve, but they are on '${curve.name}' and '${publicKey.curve?.name ?? 'an unknown curve'}'!`);

    if (!privateKey.isPrivate)
        throw new CoseError('ECDH needs the private half of the ephemeral key, which this key does not carry!');

    return ecdhSharedSecret(curve, privateKey.privateKeyBytes(), publicKey.publicKeyBytes());

}


function requireAgreementCurve(key: CoseKey, what: string): CoseCurve {

    const curve = key.keyType === KEY_TYPE_EC2 || key.keyType === KEY_TYPE_OKP ? key.curve : null;

    if (curve === null || !isEcdhCurve(curve))
        throw new CoseError(`${what} is not on a curve this implementation agrees keys on!`);

    return curve;

}


/**
 * The width of the key a content algorithm needs, in bytes: what AES-GCM or
 * ChaCha20/Poly1305 names, and for HMAC the width of its hash — which is what the published
 * examples derive for `HMAC 512/512`, and what RFC 9053 Section 3.1 asks an
 * HMAC key to be.
 */
function contentKeySizeOf(algorithm: CoseAlgorithm): number {

    if ((algorithm.family === 'aesgcm' || algorithm.family === 'chacha20poly1305') && algorithm.keySize !== null)
        return algorithm.keySize;

    if (algorithm.family === 'hmac' && algorithm.hash !== null)
        return HASH_SIZES[algorithm.hash];

    throw new CoseError(`The COSE algorithm '${algorithm.name}' is not a content algorithm a key can be agreed for!`);

}


const HASH_SIZES: Readonly<Record<DigestAlgorithm, number>> = { sha256: 32, sha384: 48, sha512: 64 };


function hashOf(algorithm: CoseAlgorithm): DigestAlgorithm {

    if (algorithm.hash === null)
        throw new CoseError(`The COSE algorithm '${algorithm.name}' names no HKDF hash!`);

    return algorithm.hash;

}


/**
 * The protected bucket of an ECDH-ES recipient: the algorithm, and nothing
 * else. It is input to the derivation, so whatever is in it binds the key —
 * and the algorithm is the one thing that must be bound, or a recipient could
 * be re-read as a different variant of itself.
 */
function protectedFor(algorithm: CoseAlgorithm): Uint8Array {

    return new CoseHeaders([[label(HeaderLabel.algorithm), algorithmToCbor(algorithm)]])
               .toProtectedBytes();

}


/**
 * The unprotected bucket of an ECDH-ES recipient: the ephemeral public key
 * first, then whatever the sender adds to the KDF context, then the key
 * identifier of the recipient key — the order of the published examples.
 */
function ecdhHeadersFor(ephemeralKey:  CoseKey,
                        options:       EcdhRecipientOptions,
                        recipientKey:  CoseKey): CoseHeaders {

    const parameters: CborEntry[] = [
        [label(HeaderLabel.ephemeralKey), ephemeralPublicKey(ephemeralKey)],
    ];

    const bytes = (labelValue: number, value: Uint8Array | null | undefined): void => {
        if (value instanceof Uint8Array)
            parameters.push([label(labelValue), cbor.bytes(value)]);
    };

    const nonce = (labelValue: number, value: Uint8Array | number | null | undefined): void => {
        if (typeof value === 'number')
            parameters.push([label(labelValue), cbor.int(value)]);
        else
            bytes(labelValue, value);
    };

    bytes(HeaderLabel.salt,           options.salt);
    bytes(HeaderLabel.partyUIdentity, options.partyU?.identity);
    nonce(HeaderLabel.partyUNonce,    options.partyU?.nonce);
    bytes(HeaderLabel.partyUOther,    options.partyU?.other);
    bytes(HeaderLabel.partyVIdentity, options.partyV?.identity);
    nonce(HeaderLabel.partyVNonce,    options.partyV?.nonce);
    bytes(HeaderLabel.partyVOther,    options.partyV?.other);

    const keyIdentifier = options.keyIdentifier === undefined
                              ? recipientKey.keyIdentifier
                              : options.keyIdentifier;

    if (keyIdentifier !== null)
        parameters.push([label(HeaderLabel.keyIdentifier), cbor.bytes(keyIdentifier)]);

    return new CoseHeaders(parameters);

}


/**
 * The ephemeral key as it travels: its key type, curve and public part, and
 * nothing more — no key identifier, no algorithm, and above all no private
 * half, whatever the key handed in carries.
 */
function ephemeralPublicKey(key: CoseKey): CborValue {

    const curve      = requireAgreementCurve(key, 'The ephemeral key');
    const publicKey  = key.publicKeyBytes();

    if (key.keyType === KEY_TYPE_OKP)
        return cbor.map([
            [cbor.int(1),  cbor.int(KEY_TYPE_OKP)],
            [cbor.int(-1), cbor.int(curve.id)],
            [cbor.int(-2), cbor.bytes(publicKey)],
        ]);

    const fieldSize = curve.fieldSize ?? 0;

    return cbor.map([
        [cbor.int(1),  cbor.int(KEY_TYPE_EC2)],
        [cbor.int(-1), cbor.int(curve.id)],
        [cbor.int(-2), cbor.bytes(publicKey.slice(1, 1 + fieldSize))],
        [cbor.int(-3), cbor.bytes(publicKey.slice(1 + fieldSize))],
    ]);

}


function partiesOf(options: EcdhRecipientOptions): { partyU?: PartyInfo; partyV?: PartyInfo } {
    return {
        ...(options.partyU !== undefined ? { partyU: options.partyU } : {}),
        ...(options.partyV !== undefined ? { partyV: options.partyV } : {}),
    };
}
