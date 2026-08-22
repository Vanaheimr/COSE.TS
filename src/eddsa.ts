/*
 * Copyright (c) 2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr COSE <https://github.com/Vanaheimr/COSE.TS>
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * EdDSA [RFC 8032], as COSE uses it [RFC 9053, Section 2.2].
 *
 * The difference from ECDSA that matters here is that there is **no separate
 * digest**. PureEdDSA hashes the message itself, twice, as part of signing, so
 * the Sig_structure goes to the signer whole. Handing it a SHA-512 digest
 * instead would produce a signature that is perfectly valid for the *digest*
 * and that no other implementation would ever accept.
 *
 * The second difference is a gift: EdDSA is deterministic by construction. The
 * nonce is derived from the private key and the message [RFC 8032, Section
 * 5.1.6], with no option to draw it at random, so two implementations signing
 * the same bytes with the same key necessarily produce the same signature. The
 * cross-signing suite compares those bytes without needing any of the
 * arrangements ECDSA needs.
 *
 * Keys are octet key pairs (kty = OKP): a public key is the whole of `x`, and
 * there is no `y` to go with it.
 */

import { ed25519 }                from '@noble/curves/ed25519.js';
import { ed448 }                  from '@noble/curves/ed448.js';

import { CoseCurves }             from './curve.ts';
import type { CoseCurve }         from './curve.ts';
import { CoseError }              from './errors.ts';


/** What this module needs from an EdDSA implementation. */
interface EddsaCurve {
    sign(message: Uint8Array, privateKey: Uint8Array): Uint8Array;
    verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean;
    getPublicKey(privateKey: Uint8Array): Uint8Array;
}


const IMPLEMENTED: Readonly<Record<string, EddsaCurve>> = {
    'Ed25519': ed25519,
    'Ed448':   ed448,
};


/** Whether this build can sign and verify on the given EdDSA curve. */
export const isEddsaCurve = (curve: CoseCurve): boolean =>
    curve.name in IMPLEMENTED;


function implementationOf(curve: CoseCurve): EddsaCurve {

    const implementation = IMPLEMENTED[curve.name];

    if (implementation === undefined)
        throw new CoseError(`The curve '${curve.name}' is not an EdDSA signature curve this implementation supports!`);

    return implementation;

}


/** The signature width of an EdDSA curve, in bytes. */
export function eddsaSignatureSize(curve: CoseCurve): number {

    if (curve.id === CoseCurves.Ed25519.id) return 64;
    if (curve.id === CoseCurves.Ed448.id)   return 114;

    throw new CoseError(`The curve '${curve.name}' has no EdDSA signature size!`);

}


/**
 * Sign the Sig_structure itself — not a digest of it.
 */
export function eddsaSign(curve:      CoseCurve,
                          message:    Uint8Array,
                          privateKey: Uint8Array): Uint8Array {

    return implementationOf(curve).sign(message, privateKey);

}


/** Verify an EdDSA signature over the Sig_structure. */
export function eddsaVerify(curve:     CoseCurve,
                            signature: Uint8Array,
                            message:   Uint8Array,
                            publicKey: Uint8Array): boolean {

    const expected = eddsaSignatureSize(curve);

    if (signature.length !== expected)
        throw new CoseError(`An EdDSA signature on the curve '${curve.name}' must be ${String(expected)} bytes wide, but was ${String(signature.length)} bytes wide!`);

    try {
        return implementationOf(curve).verify(signature, message, publicKey);
    }
    catch {
        // A public key that is not a valid point, or a malformed signature.
        // Untrusted input is allowed to be nonsense; it is not a verification.
        return false;
    }

}


/** The public key belonging to an EdDSA private key. */
export function eddsaPublicKeyFor(curve: CoseCurve, privateKey: Uint8Array): Uint8Array {
    return implementationOf(curve).getPublicKey(privateKey);
}
