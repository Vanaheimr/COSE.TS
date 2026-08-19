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
import { eddsaSign, eddsaVerify }        from './eddsa.ts';
import { mldsaSign, mldsaVerify }        from './mldsa.ts';
import { macTag, tagsEqual }             from './hmac.ts';


/**
 * Which machinery an algorithm needs.
 *
 * The distinction that earns its place here is `ecdsa` against the other two:
 * ECDSA signs a *digest* of the message, chosen by the algorithm, while EdDSA
 * and ML-DSA are pure and take the message itself. Handing a pure signer a
 * digest produces a signature that is valid for the digest and that nobody
 * else will ever accept — a failure with no symptom until the day two
 * implementations meet.
 */
export type AlgorithmFamily = 'ecdsa' | 'eddsa' | 'mldsa' | 'hmac'
                            | 'aesgcm' | 'keywrap' | 'direct' | 'none';


/** An algorithm in the COSE registry. */
export interface CoseAlgorithm {

    /** The IANA identifier, as it travels in the `alg` header parameter. */
    readonly id:           number;

    /** The registered name, e.g. `ES256`. Case sensitive. */
    readonly name:         string;

    /** The registered description. */
    readonly description:  string;

    /** Which signature machinery this needs. */
    readonly family:       AlgorithmFamily;

    /** The message digest, or null for a pure scheme that defines none. */
    readonly hash:         DigestAlgorithm | null;

    /** The curve this algorithm is defined on, or null when it leaves it to the key. */
    readonly curve:        CoseCurve | null;

    /** The ML-DSA parameter set, or null for everything else. */
    readonly parameterSet: string | null;

    /**
     * The width of the authentication tag in bytes, for a MAC algorithm.
     *
     * It is part of the identifier rather than a parameter: `HMAC 256/64` and
     * `HMAC 256/256` are two registered algorithms over the same hash, and a
     * verifier learns which width to expect from the message.
     */
    readonly tagSize:      number | null;

    /**
     * The width of the key in bytes, for an algorithm that fixes one.
     *
     * AES algorithms do: `A128GCM` and `A256GCM` are two registered identifiers
     * over one cipher, and the width is what tells them apart. The signature
     * algorithms leave it to the curve or to the parameter set.
     */
    readonly keySize:      number | null;

    /** Whether this implementation can sign and verify with it. */
    readonly signing:      boolean;

    /** Whether the registry marks it deprecated. */
    readonly deprecated:   boolean;

}


interface AlgorithmSpec {
    readonly family?:        AlgorithmFamily;
    readonly hash?:          DigestAlgorithm;
    readonly curve?:         CoseCurve;
    readonly parameterSet?:  string;
    readonly tagSize?:       number;
    readonly keySize?:       number;
    readonly signing?:       boolean;
    readonly deprecated?:    boolean;
}

const algorithm = (id: number, name: string, description: string,
                   spec: AlgorithmSpec = {}): CoseAlgorithm => ({
    id,
    name,
    description,
    family:        spec.family       ?? 'none',
    hash:          spec.hash         ?? null,
    curve:         spec.curve        ?? null,
    parameterSet:  spec.parameterSet ?? null,
    tagSize:       spec.tagSize      ?? null,
    keySize:       spec.keySize      ?? null,
    signing:       spec.signing      ?? false,
    deprecated:    spec.deprecated   ?? false,
});


/** The algorithms this implementation knows by name. */
export const CoseAlgorithms = {

    // ECDSA, curve taken from the key [RFC 9053]. Deprecated by RFC 9864.
    ES256:   algorithm(  -7, 'ES256',   'ECDSA w/ SHA-256',
                       { family: 'ecdsa', hash: 'sha256', signing: true, deprecated: true }),
    ES384:   algorithm( -35, 'ES384',   'ECDSA w/ SHA-384',
                       { family: 'ecdsa', hash: 'sha384', signing: true, deprecated: true }),
    ES512:   algorithm( -36, 'ES512',   'ECDSA w/ SHA-512',
                       { family: 'ecdsa', hash: 'sha512', signing: true, deprecated: true }),

    ES256K:  algorithm( -47, 'ES256K',  'ECDSA using secp256k1 curve and SHA-256',
                       { family: 'ecdsa', hash: 'sha256', curve: CoseCurves.secp256k1, signing: true }),

    // Fully-specified ECDSA [RFC 9864].
    ESP256:  algorithm(  -9, 'ESP256',  'ECDSA using P-256 curve and SHA-256',
                       { family: 'ecdsa', hash: 'sha256', curve: CoseCurves.P256, signing: true }),
    ESP384:  algorithm( -51, 'ESP384',  'ECDSA using P-384 curve and SHA-384',
                       { family: 'ecdsa', hash: 'sha384', curve: CoseCurves.P384, signing: true }),
    ESP512:  algorithm( -52, 'ESP512',  'ECDSA using P-521 curve and SHA-512',
                       { family: 'ecdsa', hash: 'sha512', curve: CoseCurves.P521, signing: true }),

    ESB256:  algorithm(-265, 'ESB256',  'ECDSA using BrainpoolP256r1 curve and SHA-256',
                       { family: 'ecdsa', hash: 'sha256', curve: CoseCurves.brainpoolP256r1, signing: true }),
    ESB320:  algorithm(-266, 'ESB320',  'ECDSA using BrainpoolP320r1 curve and SHA-384',
                       { family: 'ecdsa', hash: 'sha384', curve: CoseCurves.brainpoolP320r1, signing: true }),
    ESB384:  algorithm(-267, 'ESB384',  'ECDSA using BrainpoolP384r1 curve and SHA-384',
                       { family: 'ecdsa', hash: 'sha384', curve: CoseCurves.brainpoolP384r1, signing: true }),
    ESB512:  algorithm(-268, 'ESB512',  'ECDSA using BrainpoolP512r1 curve and SHA-512',
                       { family: 'ecdsa', hash: 'sha512', curve: CoseCurves.brainpoolP512r1, signing: true }),

    // EdDSA [RFC 8032]. No digest of its own: the message is signed whole.
    // The un-suffixed identifier leaves the curve to the key, which is what
    // RFC 9864 deprecates it for.
    EdDSA:   algorithm(  -8, 'EdDSA',   'EdDSA',
                       { family: 'eddsa', signing: true, deprecated: true }),
    Ed25519: algorithm( -19, 'Ed25519', 'EdDSA using the Ed25519 parameter set',
                       { family: 'eddsa', curve: CoseCurves.Ed25519, signing: true }),
    Ed448:   algorithm( -53, 'Ed448',   'EdDSA using the Ed448 parameter set',
                       { family: 'eddsa', curve: CoseCurves.Ed448, signing: true }),

    // ML-DSA [FIPS 204, RFC 9964]. Also pure, and also without a curve: an
    // ML-DSA key is a key pair of an algorithm rather than a point on
    // something, which is why RFC 9964 gives it a key type of its own.
    MLDSA44: algorithm( -48, 'ML-DSA-44', 'CBOR Object Signing Algorithm for ML-DSA-44',
                       { family: 'mldsa', parameterSet: 'ML-DSA-44', signing: true }),
    MLDSA65: algorithm( -49, 'ML-DSA-65', 'CBOR Object Signing Algorithm for ML-DSA-65',
                       { family: 'mldsa', parameterSet: 'ML-DSA-65', signing: true }),
    MLDSA87: algorithm( -50, 'ML-DSA-87', 'CBOR Object Signing Algorithm for ML-DSA-87',
                       { family: 'mldsa', parameterSet: 'ML-DSA-87', signing: true }),

    // HMAC [RFC 9053, Section 3.1]. A message authentication code rather than
    // a signature: symmetric, so whoever verifies one can produce one, and
    // `signing` is therefore false for all four. The name is "hash size /
    // tag size", and the tag is the leftmost bits of the full HMAC.
    HMAC256_64:  algorithm(   4, 'HMAC 256/64',  'HMAC w/ SHA-256 truncated to 64 bits',
                       { family: 'hmac', hash: 'sha256', tagSize:  8 }),
    HMAC256_256: algorithm(   5, 'HMAC 256/256', 'HMAC w/ SHA-256',
                       { family: 'hmac', hash: 'sha256', tagSize: 32 }),
    HMAC384_384: algorithm(   6, 'HMAC 384/384', 'HMAC w/ SHA-384',
                       { family: 'hmac', hash: 'sha384', tagSize: 48 }),
    HMAC512_512: algorithm(   7, 'HMAC 512/512', 'HMAC w/ SHA-512',
                       { family: 'hmac', hash: 'sha512', tagSize: 64 }),

    // AES-GCM [RFC 9053, Section 4.1], the content encryption algorithms.
    // COSE fixes the nonce at 96 bits and the authentication tag at 128, so the
    // key width is the only thing left for the identifier to name.
    A128GCM: algorithm(   1, 'A128GCM', 'AES-GCM mode w/ 128-bit key, 128-bit tag',
                       { family: 'aesgcm', keySize: 16, tagSize: 16 }),
    A192GCM: algorithm(   2, 'A192GCM', 'AES-GCM mode w/ 192-bit key, 128-bit tag',
                       { family: 'aesgcm', keySize: 24, tagSize: 16 }),
    A256GCM: algorithm(   3, 'A256GCM', 'AES-GCM mode w/ 256-bit key, 128-bit tag',
                       { family: 'aesgcm', keySize: 32, tagSize: 16 }),

    // AES key wrap [RFC 9053, Section 6.2.1, RFC 3394]. A recipient algorithm:
    // it carries a content key rather than content, and the width named here is
    // that of the KEY-ENCRYPTION key, not of the key being wrapped.
    A128KW:  algorithm(  -3, 'A128KW',  'AES Key Wrap w/ 128-bit key',
                       { family: 'keywrap', keySize: 16 }),
    A192KW:  algorithm(  -4, 'A192KW',  'AES Key Wrap w/ 192-bit key',
                       { family: 'keywrap', keySize: 24 }),
    A256KW:  algorithm(  -5, 'A256KW',  'AES Key Wrap w/ 256-bit key',
                       { family: 'keywrap', keySize: 32 }),

    // The recipient algorithm that transports nothing [RFC 9053, Section
    // 6.1.1]: the recipient's key IS the content key. Its protected bucket and
    // its ciphertext must both be empty, which is what makes a COSE_Mac with
    // one direct recipient a COSE_Mac0 with extra ceremony.
    direct:  algorithm(  -6, 'direct',  'Direct use of content encryption key (CEK)',
                       { family: 'direct' }),

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


function parameterSetOf(value: CoseAlgorithm): string {

    if (value.parameterSet === null)
        throw new CoseError(`The COSE algorithm '${value.name}' does not name an ML-DSA parameter set!`);

    return value.parameterSet;

}


/**
 * Sign the Sig_structure of a message with the given algorithm.
 *
 * Note which of the three branches hashes and which do not. ECDSA signs a
 * digest of the Sig_structure; EdDSA and ML-DSA sign the Sig_structure itself.
 * Getting that backwards yields a signature that verifies against nothing but
 * an implementation making the same mistake.
 */
export function signWith(value:       CoseAlgorithm,
                         keyCurve:    CoseCurve | null,
                         toBeSigned:  Uint8Array,
                         privateKey:  Uint8Array): Uint8Array {

    switch (value.family) {

        case 'ecdsa':
            return sign(resolveCurve(value, keyCurve),
                        digest(hashOf(value), toBeSigned),
                        privateKey);

        case 'eddsa':
            return eddsaSign(resolveCurve(value, keyCurve), toBeSigned, privateKey);

        case 'mldsa':
            return mldsaSign(parameterSetOf(value), toBeSigned, privateKey);

        default:
            throw new CoseError(`The COSE algorithm '${value.name}' is not a signature algorithm this implementation supports!`);

    }

}


/**
 * The authentication tag of a MAC_structure.
 *
 * Deliberately *not* reachable through {@link signWith}: a MAC is not a
 * signature with a shorter key, and an API that let one stand in for the other
 * would let a caller believe a message was signed when it was merely
 * authenticated between two parties who share a secret.
 */
export function macWith(value:      CoseAlgorithm,
                        toBeMaced:  Uint8Array,
                        key:        Uint8Array): Uint8Array {

    if (value.family !== 'hmac')
        throw new CoseError(`The COSE algorithm '${value.name}' is not a message authentication algorithm this implementation supports!`);

    return macTag(hashOf(value), tagSizeOf(value), key, toBeMaced);

}


/** Whether an authentication tag is the right one, compared in constant time. */
export function verifyMacWith(value:      CoseAlgorithm,
                              toBeMaced:  Uint8Array,
                              tag:        Uint8Array,
                              key:        Uint8Array): boolean {

    return tagsEqual(macWith(value, toBeMaced, key), tag);

}


function tagSizeOf(value: CoseAlgorithm): number {

    if (value.tagSize === null)
        throw new CoseError(`The COSE algorithm '${value.name}' does not define an authentication tag width!`);

    return value.tagSize;

}


/** Verify a signature over the Sig_structure of a message. */
export function verifyWith(value:       CoseAlgorithm,
                           keyCurve:    CoseCurve | null,
                           toBeSigned:  Uint8Array,
                           signature:   Uint8Array,
                           publicKey:   Uint8Array): boolean {

    switch (value.family) {

        case 'ecdsa':
            return verify(resolveCurve(value, keyCurve),
                          signature,
                          digest(hashOf(value), toBeSigned),
                          publicKey);

        case 'eddsa':
            return eddsaVerify(resolveCurve(value, keyCurve), signature, toBeSigned, publicKey);

        case 'mldsa':
            return mldsaVerify(parameterSetOf(value), signature, toBeSigned, publicKey);

        default:
            throw new CoseError(`The COSE algorithm '${value.name}' is not a signature algorithm this implementation supports!`);

    }

}
