/*
 * Copyright (c) 2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr COSE <https://github.com/Vanaheimr/COSE.TS>
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * ML-DSA [FIPS 204], as COSE uses it [RFC 9964].
 *
 * The post-quantum signature scheme, and the one place in this library where
 * the numbers stop being small: a ML-DSA-87 signature is 4627 bytes over a
 * metrological reading of about thirty. That ratio is an argument for CBOR
 * rather than against ML-DSA — base64 in JSON would add a third again to the
 * largest field in the message, and a byte string in CBOR costs two or three
 * bytes of head and nothing else.
 *
 * Three things about it differ from every other algorithm here.
 *
 * **It is pure.** Algorithm 2 of FIPS 204 takes the message, not a digest of
 * it, exactly as EdDSA does.
 *
 * **The private key is the 32-byte seed**, not the expanded secret key. RFC
 * 9964 requires it: "the `priv` parameter MUST be the seed and MUST have a
 * length of 32 bytes". The expanded key is derived here on every use, which is
 * the price of a key that is 32 bytes on the wire instead of up to 4896.
 *
 * **Signing is randomized by default**, and the specification does not say it
 * must not be. FIPS 204 also defines a deterministic variant, in which the
 * per-signature randomness is 32 zero bytes; this module always uses it. Two
 * implementations that both do so produce identical signature bytes, which is
 * what lets the cross-signing suite compare them rather than merely check that
 * each accepts the other's.
 */

import { ml_dsa44, ml_dsa65, ml_dsa87 }  from '@noble/post-quantum/ml-dsa.js';

import { CoseError }                     from './errors.ts';


/** What this module needs from an ML-DSA implementation. */
interface MldsaScheme {
    keygen(seed: Uint8Array): { publicKey: Uint8Array; secretKey: Uint8Array };
    sign(message: Uint8Array, secretKey: Uint8Array,
         options?: { extraEntropy?: Uint8Array | false }): Uint8Array;
    verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean;
}


/** The three parameter sets RFC 9964 registers. */
export const MLDSA_PARAMETER_SETS = ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'] as const;

export type MldsaParameterSet = typeof MLDSA_PARAMETER_SETS[number];


const IMPLEMENTED: Readonly<Record<string, MldsaScheme>> = {
    'ML-DSA-44': ml_dsa44 as unknown as MldsaScheme,
    'ML-DSA-65': ml_dsa65 as unknown as MldsaScheme,
    'ML-DSA-87': ml_dsa87 as unknown as MldsaScheme,
};


/** The sizes RFC 9964 prints, in bytes. */
export const MLDSA_SIZES: Readonly<Record<MldsaParameterSet,
                                          { publicKey: number; signature: number }>> = {
    'ML-DSA-44': { publicKey: 1312, signature: 2420 },
    'ML-DSA-65': { publicKey: 1952, signature: 3309 },
    'ML-DSA-87': { publicKey: 2592, signature: 4627 },
};


/** The length of an ML-DSA private key, which is always the seed. */
export const MLDSA_SEED_SIZE = 32;


function schemeOf(parameterSet: string): MldsaScheme {

    const scheme = IMPLEMENTED[parameterSet];

    if (scheme === undefined)
        throw new CoseError(`'${parameterSet}' is not an ML-DSA parameter set this implementation supports!`);

    return scheme;

}


/** Whether the given name is a parameter set this build can compute with. */
export const isMldsaParameterSet = (parameterSet: string): boolean =>
    parameterSet in IMPLEMENTED;


/**
 * The public key belonging to a seed.
 *
 * Deriving rather than storing it is what keeps `priv` at 32 bytes: the
 * expanded secret key of ML-DSA-87 is 4896.
 */
export function mldsaPublicKeyFor(parameterSet: string, seed: Uint8Array): Uint8Array {

    requireSeed(seed);

    return schemeOf(parameterSet).keygen(seed).publicKey;

}


/**
 * Sign the Sig_structure itself, deterministically.
 *
 * `extraEntropy: false` selects the deterministic variant of FIPS 204, in
 * which the per-signature randomness is 32 zero bytes rather than drawn.
 */
export function mldsaSign(parameterSet: string,
                          message:      Uint8Array,
                          seed:         Uint8Array): Uint8Array {

    requireSeed(seed);

    const scheme = schemeOf(parameterSet);

    return scheme.sign(message, scheme.keygen(seed).secretKey, { extraEntropy: false });

}


/** Verify an ML-DSA signature over the Sig_structure. */
export function mldsaVerify(parameterSet: string,
                            signature:    Uint8Array,
                            message:      Uint8Array,
                            publicKey:    Uint8Array): boolean {

    const sizes = MLDSA_SIZES[parameterSet as MldsaParameterSet];

    if (sizes !== undefined && signature.length !== sizes.signature)
        throw new CoseError(`An ${parameterSet} signature must be ${String(sizes.signature)} bytes wide, but was ${String(signature.length)} bytes wide!`);

    try {
        return schemeOf(parameterSet).verify(signature, message, publicKey);
    }
    catch {
        return false;
    }

}


function requireSeed(seed: Uint8Array): void {

    if (seed.length !== MLDSA_SEED_SIZE)
        throw new CoseError(`The private key of an ML-DSA COSE key is the seed and must be ${String(MLDSA_SEED_SIZE)} bytes long [RFC 9964], but was ${String(seed.length)} bytes long!`);

}
