/*
 * Copyright (c) 2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr COSE <https://github.com/Vanaheimr/COSE.TS>
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * A COSE_Sign1 message [RFC 9052, Section 4.2]: a payload signed by a single
 * signer, tagged with CBOR tag 18.
 *
 * <code>
 * COSE_Sign1 = [
 *     protected   : bstr .cbor header_map,   ; covered by the signature
 *     unprotected : header_map,              ; NOT covered by the signature
 *     payload     : bstr / nil,              ; nil = detached
 *     signature   : bstr
 * ]
 * </code>
 *
 * What is actually signed is never the message, but the Sig_structure
 * `["Signature1", protected, external_aad, payload]` [RFC 9052, Section 4.4].
 * The CBOR tag is therefore *not* covered by the signature, and the same
 * message with and without tag 18 carries the very same signature bytes.
 *
 * The serialized protected bucket is kept verbatim, because a re-serialization
 * differing in a single byte — a non-preferred integer head, a different map
 * order — would invalidate every signature made over the original bytes.
 */

import { signWith, verifyWith }              from './algorithm.ts';
import type { CoseAlgorithm }                from './algorithm.ts';
import { bytesEqual, cbor, decode, encode,
         NO_BYTES }                          from './cbor.ts';
import type { CborValue }                    from './cbor.ts';
import { CoseError, notVerified, VERIFIED }  from './errors.ts';
import type { NotVerified, Verification }    from './errors.ts';
import { CoseHeaders,
         verifyCriticalHeaderParameters }    from './headers.ts';
import type { CoseKey }                      from './key.ts';
import { HeaderLabel, label }                from './labels.ts';
import { canonicalizePayload }               from './payload.ts';
import { resolveAlgorithm, resolvePayload }  from './resolve.ts';
import { CoseSignature }                     from './signature.ts';
import { CoseCertificateChain,
         CoseCertificateHash }               from './x5chain.ts';
import type { X509Certificate }              from './x509.ts';


/** The CBOR tag of a COSE_Sign1 message. */
export const COSE_SIGN1_TAG = 18;

/** The context string of a COSE_Sign1 signature [RFC 9052, Section 4.4]. */
export const SIGNATURE_CONTEXT = 'Signature1';

/**
 * The context string of a countersignature that also covers the signature it
 * countersigns [RFC 9338, Section 3.3].
 */
export const COUNTERSIGNATURE_CONTEXT = 'CounterSignatureV2';


/** What a signer may choose beyond the payload and the key. */
export interface Sign1Options {

    /** A key identifier for the unprotected bucket, defaulting to the key's own. */
    readonly keyIdentifier?:  Uint8Array | null;

    /** Data signed along with the payload without travelling in the message. */
    readonly externalAad?:    Uint8Array | null;

    /** Whether to omit the payload from the message. */
    readonly detachPayload?:  boolean;

    /** Whether to wrap the message within CBOR tag 18. Defaults to true. */
    readonly tagged?:         boolean;

    /**
     * Whether to rewrite a CBOR payload in the deterministic encoding of
     * RFC 8949 Section 4.2.1 before signing it, so that a receiver who parses
     * and re-serializes the record arrives at the very bytes the signature
     * covers. Defaults to true. A payload that is not CBOR is signed as it is.
     */
    readonly canonicalizePayload?:  boolean;

}


/** What a verifier may have to supply. */
export interface VerifyOptions {

    /** The data that was signed along with the payload. */
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


/** What a verifier working from a certificate chain may supply beyond that. */
export interface CertificateChainVerifyOptions extends VerifyOptions {

    /**
     * The instant to check the certificates' validity periods at, now by
     * default. Worth passing whenever the answer has to be reproducible: an
     * archived message re-checked years later is checked against the
     * certificates of its own time, not of today.
     */
    readonly at?:  Date;

}


/**
 * The outcome of verifying against a certificate chain.
 *
 * A success names the certificate whose key verified, because "it verified" is
 * only half of what the caller asked: the other half is *who*, and a chain
 * exists precisely to answer that.
 */
export type CertificateChainVerification =
    | { readonly verified: true; readonly signer: X509Certificate }
    | NotVerified;


export class CoseSign1 {

    /**
     * The serialized protected bucket, exactly as signed and as received: a
     * zero-length byte string when there are no protected header parameters.
     */
    public readonly protectedHeaderBytes:  Uint8Array;

    /** The protected header parameters, which the signature covers. */
    public readonly protectedHeader:       CoseHeaders;

    /**
     * The unprotected header parameters, which the signature does not cover
     * and which therefore must not be trusted after a successful verification.
     */
    public readonly unprotectedHeader:     CoseHeaders;

    /** The signed payload, or null when it is detached. */
    public readonly payload:               Uint8Array | null;

    /** The signature: `r ‖ s`, each half zero-padded, never DER. */
    public readonly signature:             Uint8Array;

    /**
     * Whether this message is wrapped within CBOR tag 18. The tag is not
     * covered by the signature, but it is preserved so that a parsed message
     * re-encodes to the very same bytes.
     */
    public readonly isTagged:              boolean;


    public constructor(protectedHeaderBytes: Uint8Array,
                       unprotectedHeader:    CoseHeaders | null,
                       payload:              Uint8Array | null,
                       signature:            Uint8Array,
                       isTagged              = true) {

        this.protectedHeaderBytes  = protectedHeaderBytes;
        this.protectedHeader       = CoseHeaders.parseProtected(protectedHeaderBytes);
        this.unprotectedHeader     = unprotectedHeader ?? CoseHeaders.empty;
        this.payload               = payload;
        this.signature             = signature;
        this.isTagged              = isTagged;

    }


    /** Whether the payload is detached. */
    public get isDetached(): boolean {
        return this.payload === null;
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


    // ---------------------------------------------------------------- signing

    /**
     * The encoded Sig_structure of a COSE_Sign1 message
     * [RFC 9052, Section 4.4], which is the byte string an ECDSA signer
     * actually signs:
     *
     * <code>
     * Sig_structure = [
     *     context      : "Signature1",
     *     protected    : empty_or_serialized_map,
     *     external_aad : bstr,
     *     payload      : bstr
     * ]
     * </code>
     *
     * This is public on purpose. Whenever the signing key does not live in
     * this process — a meter, a smart card, a hardware security module — this
     * is the input to hand over.
     */
    public static toBeSigned(protectedHeaderBytes: Uint8Array,
                             payload:              Uint8Array,
                             externalAad:          Uint8Array | null = null): Uint8Array {

        return encode(cbor.array([
            cbor.text(SIGNATURE_CONTEXT),
            cbor.bytes(protectedHeaderBytes),
            cbor.bytes(externalAad ?? NO_BYTES),
            cbor.bytes(payload),
        ]));

    }


    /** The encoded Sig_structure of this message. */
    public toBeSigned(options: { externalAad?:     Uint8Array | null;
                                 detachedPayload?: Uint8Array | null } = {}): Uint8Array {

        const payload = resolvePayload(this.payload,
                                       options.detachedPayload ?? null,
                                       'this COSE_Sign1 message');

        if (!payload.ok)
            throw new CoseError(payload.reason);

        return CoseSign1.toBeSigned(this.protectedHeaderBytes,
                                    payload.value,
                                    options.externalAad ?? null);

    }


    /**
     * Sign a payload, placing the algorithm within the protected bucket and
     * the key identifier within the unprotected one — the layout of the
     * examples of RFC 9052 and of virtually every deployed COSE message.
     */
    public static sign(payload: Uint8Array,
                       key:     CoseKey,
                       options: Sign1Options = {}): CoseSign1 {

        const algorithm = key.algorithm;

        if (algorithm === null)
            throw new CoseError('The COSE key does not name the signature algorithm to use!');

        const keyIdentifier = options.keyIdentifier === undefined
                                  ? key.keyIdentifier
                                  : options.keyIdentifier;

        return CoseSign1.signWithHeaders(payload,
                                         key,
                                         CoseHeaders.create(algorithm),
                                         keyIdentifier !== null
                                             ? CoseHeaders.create(null, keyIdentifier)
                                             : CoseHeaders.empty,
                                         options);

    }


    /**
     * Sign a payload with the algorithm taken from the application context
     * rather than from the message: the protected bucket stays empty and only
     * the key identifier travels.
     *
     * This is the leanest signed COSE message there is, and for a protocol
     * that already agrees on its algorithm it is also the safest arrangement:
     * an algorithm that is not in the message cannot be tampered with on the
     * way, whereas one within the unprotected bucket can. The price is that
     * agility becomes a property of the profile rather than of the message.
     */
    public static signWithApplicationAlgorithm(payload: Uint8Array,
                                               key:     CoseKey,
                                               options: Sign1Options = {}): CoseSign1 {

        const algorithm = key.algorithm;

        if (algorithm === null)
            throw new CoseError('The COSE key does not name the signature algorithm to use!');

        const keyIdentifier = options.keyIdentifier === undefined
                                  ? key.keyIdentifier
                                  : options.keyIdentifier;

        return CoseSign1.signWithHeaders(payload,
                                         key,
                                         CoseHeaders.empty,
                                         keyIdentifier !== null
                                             ? CoseHeaders.create(null, keyIdentifier)
                                             : CoseHeaders.empty,
                                         options,
                                         algorithm);

    }


    /**
     * Sign a payload with full control over both header buckets.
     *
     * The signature algorithm is taken from the protected bucket, because an
     * algorithm that is not covered by the signature could be changed by
     * anyone on the way.
     */
    public static signWithHeaders(payload:               Uint8Array,
                                  key:                   CoseKey,
                                  protectedHeader:       CoseHeaders,
                                  unprotectedHeader:     CoseHeaders | null = null,
                                  options:               Sign1Options       = {},
                                  applicationAlgorithm:  CoseAlgorithm | null = null): CoseSign1 {

        const stated = protectedHeader.algorithm;

        if (applicationAlgorithm !== null && stated !== null && stated.id !== applicationAlgorithm.id)
            throw new CoseError(`The protected header bucket names the algorithm '${stated.name}', but the application context names '${applicationAlgorithm.name}'!`);

        const algorithm = stated ?? applicationAlgorithm;

        if (algorithm === null)
            throw new CoseError('Neither the protected header bucket nor the application context names the signature algorithm!');

        const protectedBytes = protectedHeader.toProtectedBytes();

        const signed         = options.canonicalizePayload === false
                                   ? payload
                                   : canonicalizePayload(payload);

        // A detached payload is the caller's to transmit, so it is the
        // caller's bytes a verifier will be handed. Quietly signing a
        // different spelling of them would produce a message that can never
        // verify, and the only hint would be a failed check somewhere else.
        if (options.detachPayload === true && !bytesEqual(signed, payload))
            throw new CoseError('The payload of this COSE_Sign1 message is detached, so canonicalizing it here would sign bytes that nobody holds: canonicalize the payload yourself (canonicalizePayload), sign and transmit those, or pass canonicalizePayload: false to sign the payload exactly as it is!');

        const signature = signWith(algorithm,
                                   key.curve,
                                   CoseSign1.toBeSigned(protectedBytes, signed, options.externalAad ?? null),
                                   key.privateKeyBytes());

        return new CoseSign1(protectedBytes,
                             unprotectedHeader,
                             options.detachPayload === true ? null : signed,
                             signature,
                             options.tagged ?? true);

    }


    // ----------------------------------------------------------- verification

    /**
     * Verify the signature of this message.
     *
     * A failed verification is not an exception — it is the expected outcome
     * of checking untrusted data — so the reason travels in the result.
     */
    public verify(key: CoseKey, options: VerifyOptions = {}): Verification {

        const critical = verifyCriticalHeaderParameters(this.protectedHeader,
                                                        this.unprotectedHeader,
                                                        options.alsoUnderstood ?? []);

        if (!critical.verified)
            return critical;

        const algorithm = resolveAlgorithm(this.protectedHeader,
                                           this.unprotectedHeader,
                                           options.expectedAlgorithm ?? key.algorithm,
                                           'This COSE_Sign1 message');

        if (!algorithm.ok)
            return notVerified(algorithm.reason);

        const payload = resolvePayload(this.payload,
                                       options.detachedPayload ?? null,
                                       'this COSE_Sign1 message');

        if (!payload.ok)
            return notVerified(payload.reason);

        return verifySignature(algorithm.value,
                               key,
                               CoseSign1.toBeSigned(this.protectedHeaderBytes,
                                                    payload.value,
                                                    options.externalAad ?? null),
                               this.signature);

    }


    // -------------------------------------------------- X.509 [RFC 9360]

    /**
     * The certificate chain of this message, from either header bucket.
     *
     * A chain that travels in a message is untrusted input, and reading one
     * says nothing at all about it — {@link verifyWithCertificateChain} has to
     * walk it to an anchor first. Throws when the parameter is present but is
     * not a `COSE_X509`, rather than pretending there is none.
     */
    public get certificateChain(): CoseCertificateChain | null {

        const value = this.protectedHeader.get(label(HeaderLabel.x5Chain)) ??
                      this.unprotectedHeader.get(label(HeaderLabel.x5Chain));

        if (value === null)
            return null;

        return CoseCertificateChain.fromCbor(value);

    }


    /**
     * The certificate thumbprint of this message, from either header bucket.
     *
     * Throws when the parameter is present but is not a `COSE_CertHash`.
     */
    public get certificateThumbprint(): CoseCertificateHash | null {

        const value = this.protectedHeader.get(label(HeaderLabel.x5T)) ??
                      this.unprotectedHeader.get(label(HeaderLabel.x5T));

        if (value === null)
            return null;

        return CoseCertificateHash.fromCbor(value);

    }


    /**
     * Verify this message against a certificate chain rather than against a
     * public key somebody handed over: the chain travels within the message,
     * is walked to one of the given trust anchors, and the key of its
     * end-entity certificate is then the key the signature has to verify with.
     *
     * That last step is what turns a chain into an answer. A chain that
     * validates beautifully says nothing whatsoever about the message it
     * arrived with unless the key it ends in is the key that signed, so the
     * two are never checked apart from one another here.
     *
     * The X.509 header parameters become understood *by this call* rather than
     * by the library, which is why a `crit` demanding `x5chain` is accepted
     * here and refused by {@link verify}: whoever verifies with a bare public
     * key has not looked at any certificate and must not claim otherwise.
     */
    public verifyWithCertificateChain(trustAnchors: readonly X509Certificate[],
                                      options:      CertificateChainVerifyOptions = {}): CertificateChainVerification {

        const understood = [...(options.alsoUnderstood ?? []),
                            label(HeaderLabel.x5Chain),
                            label(HeaderLabel.x5T)];

        const critical = verifyCriticalHeaderParameters(this.protectedHeader,
                                                        this.unprotectedHeader,
                                                        understood);

        if (!critical.verified)
            return critical;

        let chain:      CoseCertificateChain | null;
        let thumbprint: CoseCertificateHash  | null;

        try {
            chain       = this.certificateChain;
            thumbprint  = this.certificateThumbprint;
        }
        catch (exception) {
            return notVerified(exception instanceof Error ? exception.message : String(exception));
        }

        if (chain === null)
            return notVerified('This COSE_Sign1 message carries no certificate chain!');

        if (thumbprint !== null) {

            const names = thumbprint.matches(chain.endEntity);

            if (!names.verified)
                return names;

        }

        const validated = chain.validate(trustAnchors, { at: options.at });

        if (!validated.verified)
            return validated;

        // Whether the certified key is one this algorithm can verify with is
        // the algorithm's question and not this one's: an EdDSA or an ML-DSA
        // certificate is as good a binding as an elliptic curve one.
        const signed = this.verify(chain.publicKey(),
                                   { ...options, alsoUnderstood: understood });

        if (!signed.verified)
            return signed;

        return { verified: true, signer: chain.endEntity };

    }


    // ------------------------------------------------------- countersignatures

    /**
     * The countersignatures of this message [RFC 9338], which live in the
     * unprotected bucket under label 11.
     *
     * A message carrying one holds it bare; a message carrying several holds
     * an array of them. The two shapes are told apart by the kind of the first
     * element, because a bare countersignature starts with its protected
     * bucket, a byte string, whereas an array of them starts with an array.
     */
    public get countersignatures(): readonly CoseSignature[] {

        const value = this.unprotectedHeader.get(label(HeaderLabel.counterSignatureV2));

        if (value === null)
            return [];

        if (value.type !== 'array')
            throw new CoseError('The countersignature header parameter must be a COSE_Countersignature or an array of them!');

        if (value.items.length > 0 && value.items[0]!.type === 'array')
            return value.items.map(each => CoseSignature.parse(each));

        return [CoseSignature.parse(value)];

    }


    /**
     * The encoded Countersign_structure [RFC 9338, Section 3.3].
     *
     * Six elements rather than four, and the difference is not cosmetic. It
     * names the body's protected bucket *and* the countersigner's, and its
     * last element carries the signature being countersigned — which is what
     * makes this "I vouch for that signature" rather than "I signed the same
     * thing". The countersignature of RFC 8152 covered the payload but not the
     * signature, so it never actually attested to having seen it.
     *
     * `other_fields` is an array holding the one signature, not a bare byte
     * string.
     */
    public static toBeCountersigned(bodyProtectedHeaderBytes:             Uint8Array,
                                    countersignatureProtectedHeaderBytes: Uint8Array,
                                    payload:                              Uint8Array,
                                    signature:                            Uint8Array,
                                    externalAad:                          Uint8Array | null = null): Uint8Array {

        return encode(cbor.array([
            cbor.text(COUNTERSIGNATURE_CONTEXT),
            cbor.bytes(bodyProtectedHeaderBytes),
            cbor.bytes(countersignatureProtectedHeaderBytes),
            cbor.bytes(externalAad ?? NO_BYTES),
            cbor.bytes(payload),
            cbor.array([cbor.bytes(signature)]),
        ]));

    }


    /** The encoded Countersign_structure of one countersignature of this message. */
    public toBeCountersigned(countersignature: CoseSignature,
                             options: { externalAad?:     Uint8Array | null;
                                        detachedPayload?: Uint8Array | null } = {}): Uint8Array {

        const payload = resolvePayload(this.payload,
                                       options.detachedPayload ?? null,
                                       'this COSE_Sign1 message');

        if (!payload.ok)
            throw new CoseError(payload.reason);

        return CoseSign1.toBeCountersigned(this.protectedHeaderBytes,
                                           countersignature.protectedHeaderBytes,
                                           payload.value,
                                           this.signature,
                                           options.externalAad ?? null);

    }


    /**
     * Return a copy of this message with one more countersignature.
     *
     * Countersignatures live in the unprotected bucket, which no signature
     * covers, so this leaves the body signature, the protected bucket and the
     * payload byte-identical: the message stays valid for everybody, including
     * readers that ignore label 11 entirely.
     */
    public addCountersignature(key: CoseKey,
                               options: Sign1Options & {
                                   detachedPayload?: Uint8Array | null } = {}): CoseSign1 {

        const algorithm = key.algorithm;

        if (algorithm === null)
            throw new CoseError('The COSE key does not name the signature algorithm to use!');

        const keyIdentifier = options.keyIdentifier === undefined
                                  ? key.keyIdentifier
                                  : options.keyIdentifier;

        const protectedBytes = CoseHeaders.create(algorithm).toProtectedBytes();

        const payload = resolvePayload(this.payload,
                                       options.detachedPayload ?? null,
                                       'this COSE_Sign1 message');

        if (!payload.ok)
            throw new CoseError(payload.reason);

        const signature = signWith(algorithm,
                                   key.curve,
                                   CoseSign1.toBeCountersigned(this.protectedHeaderBytes,
                                                               protectedBytes,
                                                               payload.value,
                                                               this.signature,
                                                               options.externalAad ?? null),
                                   key.privateKeyBytes());

        const added = new CoseSignature(protectedBytes,
                                        keyIdentifier !== null
                                            ? CoseHeaders.create(null, keyIdentifier)
                                            : CoseHeaders.empty,
                                        signature);

        const all = [...this.countersignatures, added];

        return new CoseSign1(this.protectedHeaderBytes,
                             this.unprotectedHeader.set(
                                 label(HeaderLabel.counterSignatureV2),
                                 all.length === 1
                                     ? all[0]!.toCbor()
                                     : cbor.array(all.map(each => each.toCbor()))),
                             this.payload,
                             this.signature,
                             this.isTagged);

    }


    /**
     * Verify one countersignature of this message.
     *
     * This says nothing about whether the body signature itself is valid —
     * that is a separate question with a separate key, and answering both at
     * once would hide which of the two failed.
     */
    public verifyCountersignature(countersignature: CoseSignature,
                                  key:              CoseKey,
                                  options:          VerifyOptions = {}): Verification {

        const critical = verifyCriticalHeaderParameters(countersignature.protectedHeader,
                                                        countersignature.unprotectedHeader,
                                                        options.alsoUnderstood ?? []);

        if (!critical.verified)
            return critical;

        const algorithm = resolveAlgorithm(countersignature.protectedHeader,
                                           countersignature.unprotectedHeader,
                                           options.expectedAlgorithm ?? key.algorithm,
                                           'This countersignature');

        if (!algorithm.ok)
            return notVerified(algorithm.reason);

        const payload = resolvePayload(this.payload,
                                       options.detachedPayload ?? null,
                                       'this COSE_Sign1 message');

        if (!payload.ok)
            return notVerified(payload.reason);

        return verifySignature(algorithm.value,
                               key,
                               CoseSign1.toBeCountersigned(this.protectedHeaderBytes,
                                                           countersignature.protectedHeaderBytes,
                                                           payload.value,
                                                           this.signature,
                                                           options.externalAad ?? null),
                               countersignature.signature);

    }


    // ------------------------------------------------------ reading & writing

    /**
     * Parse a COSE_Sign1 message.
     *
     * Both the tagged and the untagged form are accepted; which one it was is
     * remembered, as the CBOR tag is not covered by the signature but is part
     * of the bytes on the wire.
     */
    public static parse(input: Uint8Array | CborValue): CoseSign1 {

        const value = input instanceof Uint8Array ? decode(input) : input;

        let isTagged = false;
        let message  = value;

        if (message.type === 'tag') {

            if (message.tag !== BigInt(COSE_SIGN1_TAG))
                throw new CoseError(`A COSE_Sign1 message must be tagged with CBOR tag ${String(COSE_SIGN1_TAG)}, but was tagged with CBOR tag ${String(message.tag)}!`);

            isTagged = true;
            message  = message.value;

        }

        if (message.type !== 'array')
            throw new CoseError(`A COSE_Sign1 message must be a CBOR array, but was a CBOR ${message.type}!`);

        if (message.items.length !== 4)
            throw new CoseError(`A COSE_Sign1 message must be a CBOR array of 4 elements, but had ${String(message.items.length)} element(s)!`);

        const [protectedBytes, unprotected, payload, signature] = message.items;

        if (protectedBytes?.type !== 'bytes')
            throw new CoseError('The protected header bucket of a COSE_Sign1 message must be a byte string!');

        if (unprotected === undefined)
            throw new CoseError('A COSE_Sign1 message must carry an unprotected header bucket!');

        if (payload === undefined || (payload.type !== 'null' && payload.type !== 'bytes'))
            throw new CoseError('The payload of a COSE_Sign1 message must be a byte string, or null when it is detached!');

        if (signature?.type !== 'bytes')
            throw new CoseError('The signature of a COSE_Sign1 message must be a byte string!');

        return new CoseSign1(protectedBytes.value,
                             CoseHeaders.parse(unprotected),
                             payload.type === 'bytes' ? payload.value : null,
                             signature.value,
                             isTagged);

    }


    /** A CBOR representation of this message. */
    public toCbor(): CborValue {

        const message = cbor.array([
            cbor.bytes(this.protectedHeaderBytes),
            this.unprotectedHeader.toCbor(),
            this.payload !== null ? cbor.bytes(this.payload) : cbor.nullValue,
            cbor.bytes(this.signature),
        ]);

        return this.isTagged ? cbor.tag(COSE_SIGN1_TAG, message) : message;

    }


    /** The CBOR encoding of this message. */
    public toBytes(): Uint8Array {
        return encode(this.toCbor());
    }


    /**
     * A copy of this message without its payload, e.g. because the payload
     * travels elsewhere.
     *
     * The signature stays valid: it never covered the message, only the
     * Sig_structure.
     */
    public detach(): CoseSign1 {
        return new CoseSign1(this.protectedHeaderBytes, this.unprotectedHeader,
                             null, this.signature, this.isTagged);
    }


    /** A copy of this message carrying the given payload again. */
    public attach(payload: Uint8Array): CoseSign1 {

        if (this.payload !== null && !bytesEqual(this.payload, payload))
            throw new CoseError('This COSE_Sign1 message already carries a different payload!');

        return new CoseSign1(this.protectedHeaderBytes, this.unprotectedHeader,
                             payload, this.signature, this.isTagged);

    }

}


/**
 * The last step every verification shares: the arithmetic, and the two ways of
 * failing that are not a wrong signature.
 */
function verifySignature(algorithm:  CoseAlgorithm,
                         key:        CoseKey,
                         toBeSigned: Uint8Array,
                         signature:  Uint8Array): Verification {

    let publicKey: Uint8Array;

    try {
        publicKey = key.publicKeyBytes();
    }
    catch (cause) {
        return notVerified(cause instanceof Error ? cause.message : String(cause));
    }

    try {
        return verifyWith(algorithm, key.curve, toBeSigned, signature, publicKey)
                   ? VERIFIED
                   : notVerified('The signature is not valid for this payload and this key!');
    }
    catch (cause) {
        return notVerified(cause instanceof Error ? cause.message : String(cause));
    }

}


export { verifySignature };
