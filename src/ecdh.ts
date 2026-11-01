/*
 * Copyright (c) 2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr COSE <https://github.com/Vanaheimr/COSE.TS>
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * ECDH key agreement and the HKDF key derivation over it, as COSE uses them
 * for ECDH-ES [RFC 9053, Sections 5 and 6.3].
 *
 * The point of the whole construction is that a sender can encrypt to a party
 * whose **public** key is all it knows. It makes a key pair for this one
 * message — the ephemeral key, "ES" for ephemeral-static — combines its
 * private half with the recipient's public key, and sends the ephemeral public
 * half along. The recipient combines that with its own private key and arrives
 * at the same secret. Nobody else can.
 *
 * That secret is not used as a key. It is a point coordinate, not a uniformly
 * random string, and the same pair of keys always yields the same one. HKDF
 * turns it into a key, and `COSE_KDF_Context` is what it is turned *for*:
 * the algorithm the key will serve, its length, the protected bucket of the
 * recipient, and — when the parties name themselves — who they are. Two
 * derivations that differ in any of these produce unrelated keys, so a key
 * agreed for one purpose cannot be replayed for another.
 *
 * Three fields of that context are where implementations disagree, and every
 * one of them is settled here against the published examples of the COSE
 * working group:
 *
 *   - **`AlgorithmID` names what the derived key is for**, not how it was
 *     derived. With ECDH-ES + HKDF-256 the derived key *is* the content key,
 *     so it is the content algorithm (`A128GCM`, `HMAC 256/256`); with
 *     ECDH-ES + A128KW the derived key wraps the content key, so it is
 *     `A128KW`. Never the ECDH algorithm itself.
 *   - **`keyDataLength` is in bits.**
 *   - **`protected` is the recipient's protected bucket** as it travels, which
 *     is where the ECDH algorithm is named — so a recipient structure whose
 *     algorithm is rewritten derives a different key.
 *
 * The ephemeral private key is the caller's, never drawn here, for the reason
 * the nonce and the content key are: nothing in this package uses randomness,
 * so every message it writes can be written again, byte for byte. Making a
 * fresh ephemeral key for every message is the caller's duty, and a reused one
 * makes every message to the same recipient share its key-encryption key.
 */

import { x25519 }               from '@noble/curves/ed25519.js';
import { x448 }                 from '@noble/curves/ed448.js';
import { hkdf }                 from '@noble/hashes/hkdf.js';

import { cbor, encode, NO_BYTES } from './cbor.ts';
import type { CborValue }       from './cbor.ts';
import { CoseCurves, KEY_TYPE_EC2,
         KEY_TYPE_OKP }         from './curve.ts';
import type { CoseCurve }       from './curve.ts';
import { ecdhSecret, HASHES,
         isImplemented }        from './ecdsa.ts';
import type { DigestAlgorithm } from './ecdsa.ts';
import { CoseError }            from './errors.ts';


/** The two Montgomery curves of RFC 7748, by COSE curve identifier. */
const MONTGOMERY: Readonly<Record<number, typeof x25519>> = {
    [CoseCurves.X25519.id]: x25519,
    [CoseCurves.X448.id]:   x448,
};


/**
 * Whether this build can agree a key on the given curve: every EC2 curve it
 * computes with, and X25519 and X448.
 *
 * Ed25519 and Ed448 are not among them. They share their fields with X25519
 * and X448 and a key can be converted between the two, but COSE registers
 * them as separate curves and a signing key used for key agreement is a key
 * used for two purposes.
 */
export function isEcdhCurve(curve: CoseCurve): boolean {

    if (curve.keyType === KEY_TYPE_EC2)
        return isImplemented(curve);

    return curve.keyType === KEY_TYPE_OKP && curve.id in MONTGOMERY;

}


/** The public key of an X25519 or X448 private key. */
export function montgomeryPublicKeyFor(curve: CoseCurve, privateKey: Uint8Array): Uint8Array {
    return montgomery(curve).getPublicKey(privateKey);
}


/**
 * The raw ECDH secret of a private key and a public key on the same curve.
 *
 * For EC2 the public key is `04 ‖ x ‖ y` and the secret is the x coordinate
 * of the product, padded to the field. For X25519 and X448 both keys are the
 * u-coordinates of RFC 7748 and so is the secret.
 *
 * A failure is a `CoseError` either way. noble refuses a point that is not on
 * the curve, and refuses an X25519 or X448 product that is all zeroes — the
 * result of a public key of small order, which RFC 7748 Section 6.1 says to
 * check for, since any secret computed from it is known to everybody.
 */
export function ecdhSharedSecret(curve:       CoseCurve,
                                 privateKey:  Uint8Array,
                                 publicKey:   Uint8Array): Uint8Array {

    try {

        if (curve.keyType === KEY_TYPE_EC2)
            return ecdhSecret(curve, privateKey, publicKey);

        return montgomery(curve).getSharedSecret(privateKey, publicKey);

    }
    catch (exception) {

        if (exception instanceof CoseError)
            throw exception;

        throw new CoseError(`No key could be agreed on the curve '${curve.name}': ${exception instanceof Error ? exception.message : String(exception)}`);

    }

}


function montgomery(curve: CoseCurve): typeof x25519 {

    const implementation = curve.keyType === KEY_TYPE_OKP ? MONTGOMERY[curve.id] : undefined;

    if (implementation === undefined)
        throw new CoseError(`The curve '${curve.name}' is not a key agreement curve this implementation supports!`);

    return implementation;

}


// ------------------------------------------------------------ KDF context ---

/**
 * What one party says about itself in a `COSE_KDF_Context` [RFC 9053,
 * Section 5.2]: who it is, a nonce, and anything else both sides agree on.
 *
 * Every field is optional and travels as `nil` when absent, which is what all
 * of the published examples do. When present they travel in the header
 * parameters -21 to -26 of the recipient structure, so that the receiving
 * side can rebuild the same context — and a sender naming a PartyV identity
 * binds the derived key to the party it meant, at no cost to anybody else.
 */
export interface PartyInfo {
    readonly identity?:  Uint8Array | null;
    readonly nonce?:     Uint8Array | number | null;
    readonly other?:     Uint8Array | null;
}


/** The parts of a `COSE_KDF_Context`, as this implementation builds it. */
export interface KdfContextParts {

    /**
     * The algorithm the derived key is for: the content algorithm for direct
     * key agreement, the key-wrap algorithm otherwise.
     */
    readonly algorithmId:     number;

    /** The length of the derived key, in **bytes** — written as bits. */
    readonly keyLength:       number;

    /** The protected bucket of the recipient structure, as it travels. */
    readonly protectedBytes:  Uint8Array;

    readonly partyU?:         PartyInfo;
    readonly partyV?:         PartyInfo;

}


/**
 * The encoded `COSE_KDF_Context`:
 *
 * ```
 * COSE_KDF_Context = [
 *     AlgorithmID : int / tstr,
 *     PartyUInfo  : [ identity : bstr / nil, nonce : bstr / int / nil, other : bstr / nil ],
 *     PartyVInfo  : [ identity : bstr / nil, nonce : bstr / int / nil, other : bstr / nil ],
 *     SuppPubInfo : [ keyDataLength : uint, protected : empty_or_serialized_map ]
 * ]
 * ```
 *
 * `SuppPubInfo` has an optional `other` and the context an optional
 * `SuppPrivInfo`, both mutually agreed values outside the message; neither is
 * written here, and no header parameter carries either.
 */
export function kdfContext(parts: KdfContextParts): Uint8Array {

    return encode(cbor.array([
        cbor.int(parts.algorithmId),
        partyInfo(parts.partyU),
        partyInfo(parts.partyV),
        cbor.array([
            cbor.int(parts.keyLength * 8),
            cbor.bytes(parts.protectedBytes),
        ]),
    ]));

}


function partyInfo(party: PartyInfo | undefined): CborValue {

    const bytesOrNil = (value: Uint8Array | null | undefined): CborValue =>
        value instanceof Uint8Array ? cbor.bytes(value) : cbor.nullValue;

    const nonce = party?.nonce;

    return cbor.array([
        bytesOrNil(party?.identity),
        typeof nonce === 'number' ? cbor.int(nonce) : bytesOrNil(nonce),
        bytesOrNil(party?.other),
    ]);

}


/**
 * HKDF [RFC 5869] over a raw ECDH secret, as RFC 9053 Section 5.1 uses it:
 * the secret is the input keying material, the encoded `COSE_KDF_Context` is
 * the info, and an absent salt is the empty one — which HKDF reads as a
 * hash's width of zeroes, exactly as the RFC asks.
 */
export function hkdfDerive(hash:    DigestAlgorithm,
                           secret:  Uint8Array,
                           context: Uint8Array,
                           length:  number,
                           salt:    Uint8Array | null = null): Uint8Array {

    return hkdf(HASHES[hash], secret, salt ?? NO_BYTES, context, length);

}
