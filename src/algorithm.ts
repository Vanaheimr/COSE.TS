/*
 * Copyright (c) 2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr COSE <https://github.com/Vanaheimr/COSE.TS>
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * The COSE algorithm registry [IANA, "COSE Algorithms"].
 *
 * The registry has two generations of ECDSA entries and the difference is the
 * point of RFC 9864. `ES256` names a digest and leaves the curve to the key,
 * so one identifier covers several curves and a verifier learns which one only
 * from the key it was handed; the fully-specified `ESP256` names both. The
 * older three are kept here — they are what nearly every deployed message
 * carries — and are marked deprecated.
 *
 * `ESB320` pairs a 320-bit curve with SHA-384, which looks like a typo and is
 * not: it is what RFC 9864 registers.
 */

import { CoseError }                     from './errors.ts';
import { cbor }                          from './cbor.ts';
import type { CborValue }                from './cbor.ts';
import { CoseCurves }                    from './curve.ts';
import type { CoseCurve }                from './curve.ts';
import { digest, sign, verify }          from './ecdsa.ts';
import type { DigestAlgorithm }          from './ecdsa.ts';


/** An algorithm in the COSE registry. */
export interface CoseAlgorithm {

    /** The IANA identifier, as it travels in the `alg` header parameter. */
    readonly id:           number;

    /** The registered name, e.g. `ES256`. Case sensitive. */
    readonly name:         string;

    /** The registered description. */
    readonly description:  string;

    /** The message digest, or null for an algorithm that defines none. */
    readonly hash:         DigestAlgorithm | null;

    /** The curve this algorithm is defined on, or null when it leaves it to the key. */
    readonly curve:        CoseCurve | null;

    /** Whether this implementation can sign and verify with it. */
    readonly signing:      boolean;

    /** Whether the registry marks it deprecated. */
    readonly deprecated:   boolean;

}


interface AlgorithmSpec {
    readonly hash?:        DigestAlgorithm;
    readonly curve?:       CoseCurve;
    readonly signing?:     boolean;
    readonly deprecated?:  boolean;
}

const algorithm = (id: number, name: string, description: string,
                   spec: AlgorithmSpec = {}): CoseAlgorithm => ({
    id,
    name,
    description,
    hash:        spec.hash       ?? null,
    curve:       spec.curve      ?? null,
    signing:     spec.signing    ?? false,
    deprecated:  spec.deprecated ?? false,
});


/** The algorithms this implementation knows by name. */
export const CoseAlgorithms = {

    // ECDSA, curve taken from the key [RFC 9053]. Deprecated by RFC 9864.
    ES256:   algorithm(  -7, 'ES256',   'ECDSA w/ SHA-256',
                       { hash: 'sha256', signing: true, deprecated: true }),
    ES384:   algorithm( -35, 'ES384',   'ECDSA w/ SHA-384',
                       { hash: 'sha384', signing: true, deprecated: true }),
    ES512:   algorithm( -36, 'ES512',   'ECDSA w/ SHA-512',
                       { hash: 'sha512', signing: true, deprecated: true }),

    ES256K:  algorithm( -47, 'ES256K',  'ECDSA using secp256k1 curve and SHA-256',
                       { hash: 'sha256', curve: CoseCurves.secp256k1, signing: true }),

    // Fully-specified ECDSA [RFC 9864].
    ESP256:  algorithm(  -9, 'ESP256',  'ECDSA using P-256 curve and SHA-256',
                       { hash: 'sha256', curve: CoseCurves.P256, signing: true }),
    ESP384:  algorithm( -51, 'ESP384',  'ECDSA using P-384 curve and SHA-384',
                       { hash: 'sha384', curve: CoseCurves.P384, signing: true }),
    ESP512:  algorithm( -52, 'ESP512',  'ECDSA using P-521 curve and SHA-512',
                       { hash: 'sha512', curve: CoseCurves.P521, signing: true }),

    ESB256:  algorithm(-265, 'ESB256',  'ECDSA using BrainpoolP256r1 curve and SHA-256',
                       { hash: 'sha256', curve: CoseCurves.brainpoolP256r1, signing: true }),
    ESB320:  algorithm(-266, 'ESB320',  'ECDSA using BrainpoolP320r1 curve and SHA-384',
                       { hash: 'sha384', curve: CoseCurves.brainpoolP320r1, signing: true }),
    ESB384:  algorithm(-267, 'ESB384',  'ECDSA using BrainpoolP384r1 curve and SHA-384',
                       { hash: 'sha384', curve: CoseCurves.brainpoolP384r1, signing: true }),
    ESB512:  algorithm(-268, 'ESB512',  'ECDSA using BrainpoolP512r1 curve and SHA-512',
                       { hash: 'sha512', curve: CoseCurves.brainpoolP512r1, signing: true }),

    // Recognized so that they are refused by name rather than as an unknown
    // number. EdDSA is not implemented here.
    EdDSA:   algorithm(  -8, 'EdDSA',   'EdDSA',
                       { deprecated: true }),
    Ed25519: algorithm( -19, 'Ed25519', 'EdDSA using the Ed25519 parameter set',
                       { curve: CoseCurves.Ed25519 }),
    Ed448:   algorithm( -53, 'Ed448',   'EdDSA using the Ed448 parameter set',
                       { curve: CoseCurves.Ed448 }),

    // Digests, which are algorithms in the same registry but never sign.
    SHA256:  algorithm( -16, 'SHA-256', 'SHA-2 256-bit Hash', { hash: 'sha256' }),
    SHA384:  algorithm( -43, 'SHA-384', 'SHA-2 384-bit Hash', { hash: 'sha384' }),
    SHA512:  algorithm( -44, 'SHA-512', 'SHA-2 512-bit Hash', { hash: 'sha512' }),
    SHA1:    algorithm( -14, 'SHA-1',   'SHA-1 Hash',         { deprecated: true }),

} as const;


/** Every registered algorithm, in registry order. */
export const ALL_ALGORITHMS: readonly CoseAlgorithm[] = Object.values(CoseAlgorithms);


/** The algorithm with the given identifier, or null when it is not registered. */
export function algorithmById(id: number): CoseAlgorithm | null {
    return ALL_ALGORITHMS.find(each => each.id === id) ?? null;
}


/** The algorithm with the given name, or null. Case sensitive. */
export function algorithmByName(name: string): CoseAlgorithm | null {
    return ALL_ALGORITHMS.find(each => each.name === name) ?? null;
}


/**
 * The algorithm a header parameter names.
 *
 * An unregistered identifier is not an error here. A message that names an
 * algorithm nobody knows is still worth reading — its headers, its key
 * identifier and its payload are all inspectable — and it fails at the point
 * where it would have to be verified, where the failure means something.
 */
export function algorithmFromCbor(value: CborValue): CoseAlgorithm {

    if (value.type !== 'int')
        throw new CoseError('The COSE algorithm identifier must be an integer!');

    const id = Number(value.value);

    return algorithmById(id)
        ?? algorithm(id, `unregistered(${String(id)})`, 'An algorithm this implementation does not know');

}


/** The header parameter value naming this algorithm. */
export const algorithmToCbor = (value: CoseAlgorithm): CborValue =>
    cbor.int(value.id);


/** Whether two algorithms are the same algorithm. */
export const sameAlgorithm = (left: CoseAlgorithm, right: CoseAlgorithm): boolean =>
    left.id === right.id;


/**
 * The curve a signature with this algorithm runs on.
 *
 * A fully-specified algorithm names it, and then the key has to agree; the
 * three older ones leave it to the key entirely. Checking the agreement is
 * what stops a `ESP256` message from being verified with a P-384 key, which no
 * amount of correct arithmetic further down would catch.
 */
export function resolveCurve(value: CoseAlgorithm, keyCurve: CoseCurve | null): CoseCurve {

    if (!value.signing)
        throw new CoseError(`The COSE algorithm '${value.name}' is not a signature algorithm this implementation supports!`);

    if (value.curve !== null) {

        if (keyCurve !== null && keyCurve.id !== value.curve.id)
            throw new CoseError(`The COSE algorithm '${value.name}' is defined on the curve '${value.curve.name}', but the key is on the curve '${keyCurve.name}'!`);

        return value.curve;

    }

    if (keyCurve === null)
        throw new CoseError(`The COSE algorithm '${value.name}' does not name a curve, therefore the key has to!`);

    return keyCurve;

}


function hashOf(value: CoseAlgorithm): DigestAlgorithm {

    if (value.hash === null)
        throw new CoseError(`The COSE algorithm '${value.name}' does not define a separate message digest!`);

    return value.hash;

}


/** Sign the Sig_structure of a message with the given algorithm. */
export function signWith(value:       CoseAlgorithm,
                         keyCurve:    CoseCurve | null,
                         toBeSigned:  Uint8Array,
                         privateKey:  Uint8Array): Uint8Array {

    const curve = resolveCurve(value, keyCurve);

    return sign(curve, digest(hashOf(value), toBeSigned), privateKey);

}


/** Verify a signature over the Sig_structure of a message. */
export function verifyWith(value:       CoseAlgorithm,
                           keyCurve:    CoseCurve | null,
                           toBeSigned:  Uint8Array,
                           signature:   Uint8Array,
                           publicKey:   Uint8Array): boolean {

    const curve = resolveCurve(value, keyCurve);

    return verify(curve, signature, digest(hashOf(value), toBeSigned), publicKey);

}
