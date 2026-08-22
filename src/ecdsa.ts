/*
 * Copyright (c) 2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr COSE <https://github.com/Vanaheimr/COSE.TS>
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * The second and last seam: everything that computes a hash or touches a
 * private key lives here.
 *
 * Two things about ECDSA in COSE are easy to get wrong and both are settled in
 * this module.
 *
 * **The signature is `r ‖ s`, not DER.** Each component is zero-padded to the
 * width of the group order [RFC 9053, Section 2.1] — 64 bytes on P-256, 132 on
 * P-521. Most general-purpose signing APIs hand out DER by default, and a DER
 * signature in a COSE message fails verification everywhere with an error that
 * looks like a bad encoder.
 *
 * **Low-S normalization is a policy, not a rule.** Every ECDSA signature has a
 * valid twin `(r, n − s)`, and several libraries reject the second by default
 * under the anti-malleability convention Bitcoin established. COSE imposes no
 * such thing, and a meter that signs without normalizing produces perfectly
 * valid signatures that a low-S verifier refuses. Verification here therefore
 * passes `lowS: false`, which accepts both forms.
 *
 * Signing is deterministic (RFC 6979): the nonce is derived from the private
 * key and the message rather than drawn at random. That makes a published
 * example recomputable, and it matters rather more for a device with no
 * dependable source of randomness, where a repeated nonce hands over the
 * private key.
 */

import { ecdsa, weierstrass }                           from '@noble/curves/abstract/weierstrass.js';
import { sha256, sha384, sha512 }                       from '@noble/hashes/sha2.js';
import type { CHash }                                   from '@noble/hashes/utils.js';
import { p256, p384, p521 }                             from '@noble/curves/nist.js';
import { brainpoolP256r1, brainpoolP384r1,
         brainpoolP512r1 }                              from '@noble/curves/misc.js';
import { secp256k1 }                                    from '@noble/curves/secp256k1.js';

import { CoseError }                                    from './errors.ts';
import type { CoseCurve }                               from './curve.ts';


/**
 * brainpoolP320r1 [RFC 5639, Section 3.4].
 *
 * The one curve of the COSE registry the underlying library does not ship —
 * the three other brainpool curves it does — so it is defined here from its
 * published domain parameters. Nothing about that is exotic: a Weierstrass
 * curve *is* these seven numbers, and the library's own brainpool definitions
 * are written exactly this way.
 *
 * Transcribing 320-bit constants is the kind of task that fails silently, so
 * they are checked three times over: `weierstrass()` refuses a generator that
 * is not on the curve, `tests/brainpool.test.ts` checks that the order really
 * is the order, and the conformance suite signs with them and compares the
 * bytes against Bouncy Castle's own brainpoolP320r1. A single wrong digit
 * survives none of the three.
 *
 * SHA-384 goes with a 320-bit curve, which looks like a mistake and is what
 * RFC 9864 registers for `ESB320`. It matters twice over here: it is the
 * message digest, and it is the hash the RFC 6979 nonce is derived with.
 */
const brainpoolP320r1 = /* @__PURE__ */ ecdsa(weierstrass({
    p:  BigInt('0xd35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27'),
    a:  BigInt('0x3ee30b568fbab0f883ccebd46d3f3bb8a2a73513f5eb79da66190eb085ffa9f492f375a97d860eb4'),
    b:  BigInt('0x520883949dfdbc42d3ad198640688a6fe13f41349554b49acc31dccd884539816f5eb4ac8fb1f1a6'),
    n:  BigInt('0xd35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311'),
    Gx: BigInt('0x43bd7e9afb53d8b85289bcc48ee5bfe6f20137d10a087eb6e7871e2a10a599c710af8d0d39e20611'),
    Gy: BigInt('0x14fdd05545ec1cc8ab4093247f77275e0743ffed117182eaa9c77877aaac6ac7d35245d1692e8ee1'),
    h:  BigInt(1),
}), sha384);


/** The digest algorithms COSE signature algorithms use. */
export type DigestAlgorithm = 'sha256' | 'sha384' | 'sha512';

/** The implementation behind each digest name — shared with the HMAC in `hmac.ts`. */
export const HASHES: Record<DigestAlgorithm, CHash> = { sha256, sha384, sha512 };


/** What this module needs from an elliptic curve implementation. */
interface EcdsaCurve {
    sign(message: Uint8Array, privateKey: Uint8Array,
         options?: { prehash?: boolean; lowS?: boolean }): Uint8Array;
    verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array,
           options?: { prehash?: boolean; lowS?: boolean }): boolean;
    getPublicKey(privateKey: Uint8Array, isCompressed?: boolean): Uint8Array;
    Point: {
        fromBytes(bytes: Uint8Array): { toBytes(isCompressed: boolean): Uint8Array };
    };
}


/**
 * The curves this build can compute with, by COSE curve name — which is every
 * EC2 curve the COSE registry has.
 */
const IMPLEMENTED: Readonly<Record<string, EcdsaCurve>> = {
    'P-256':            p256            as unknown as EcdsaCurve,
    'P-384':            p384            as unknown as EcdsaCurve,
    'P-521':            p521            as unknown as EcdsaCurve,
    'secp256k1':        secp256k1       as unknown as EcdsaCurve,
    'brainpoolP256r1':  brainpoolP256r1 as unknown as EcdsaCurve,
    'brainpoolP320r1':  brainpoolP320r1 as unknown as EcdsaCurve,
    'brainpoolP384r1':  brainpoolP384r1 as unknown as EcdsaCurve,
    'brainpoolP512r1':  brainpoolP512r1 as unknown as EcdsaCurve,
};


/** Whether this build can sign and verify on the given curve. */
export const isImplemented = (curve: CoseCurve): boolean =>
    curve.name in IMPLEMENTED;


function implementationOf(curve: CoseCurve): EcdsaCurve {

    const implementation = IMPLEMENTED[curve.name];

    if (implementation === undefined)
        throw new CoseError(`The elliptic curve '${curve.name}' is registered by COSE, but this build does not implement it!`);

    return implementation;

}


/** The message digest an algorithm signs over. */
export const digest = (algorithm: DigestAlgorithm, data: Uint8Array): Uint8Array =>
    HASHES[algorithm](data);


/**
 * Sign the given digest, returning the COSE wire form `r ‖ s`.
 *
 * `prehash: false` says the input already *is* the digest — the caller hashed
 * the Sig_structure, because which digest to use is a property of the COSE
 * algorithm rather than of the curve.
 *
 * `lowS: false` is the load-bearing one. The underlying library normalizes `s`
 * to its low form by default, and COSE does not: RFC 6979 publishes the
 * un-normalized values, and so does every implementation that follows it. With
 * normalization on, this library would produce signatures that verify
 * everywhere and are nevertheless *different bytes* from the ones the C#
 * reference implementation produces for the same key and the same message —
 * which would quietly destroy the one property that makes a deterministic
 * signature worth having.
 */
export function sign(curve:      CoseCurve,
                     messageHash: Uint8Array,
                     privateKey:  Uint8Array): Uint8Array {

    return implementationOf(curve).sign(messageHash, privateKey,
                                        { prehash: false, lowS: false });

}


/**
 * Verify a `r ‖ s` signature over the given digest.
 *
 * A signature of the wrong width is refused before it reaches the curve, with
 * an error that names the likely cause: nearly every such signature is a DER
 * encoding that was never converted.
 */
export function verify(curve:       CoseCurve,
                       signature:   Uint8Array,
                       messageHash: Uint8Array,
                       publicKey:   Uint8Array): boolean {

    const expected = (curve.orderSize ?? 0) * 2;

    if (signature.length !== expected)
        throw new CoseError(`An ECDSA signature on the curve '${curve.name}' must be ${expected} bytes wide — the concatenated components r and s, each zero-padded to the width of the group order [RFC 9053, Section 2.1] — but was ${signature.length} bytes wide. A signature of a length such as this one is usually a DER encoding that was never converted!`);

    try {
        return implementationOf(curve).verify(signature, messageHash, publicKey,
                                              { prehash: false, lowS: false });
    }
    catch {
        // A public key that is not on the curve, or a component out of range.
        // Untrusted input is allowed to be nonsense; it is not a verification.
        return false;
    }

}


/**
 * The uncompressed public key `04 ‖ x ‖ y` belonging to a private key.
 */
export function publicKeyFor(curve: CoseCurve, privateKey: Uint8Array): Uint8Array {
    return implementationOf(curve).getPublicKey(privateKey, false);
}


/**
 * Recover the y coordinate of a point from its x coordinate and the parity of
 * its y [RFC 9052, Section 7.1.1].
 *
 * A COSE key may carry `y` as a boolean rather than as a byte string, which
 * halves the size of the key. There are two points with any given x, and the
 * boolean says which of the two: the sign bit is the parity of y.
 */
export function decompressY(curve: CoseCurve, x: Uint8Array, oddY: boolean): Uint8Array {

    const fieldSize  = curve.fieldSize ?? 0;
    const compressed = new Uint8Array(1 + x.length);

    compressed[0] = oddY ? 0x03 : 0x02;
    compressed.set(x, 1);

    const uncompressed = implementationOf(curve).Point.fromBytes(compressed).toBytes(false);

    return uncompressed.slice(1 + fieldSize);

}


/**
 * Whether the point `04 ‖ x ‖ y` lies on the curve.
 *
 * A public key that does not is not merely useless: handing one to a
 * verification is how invalid-curve attacks start.
 */
export function isOnCurve(curve: CoseCurve, uncompressed: Uint8Array): boolean {

    try {
        implementationOf(curve).Point.fromBytes(uncompressed);
        return true;
    }
    catch {
        return false;
    }

}
