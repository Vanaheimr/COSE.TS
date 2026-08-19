/*
 * Copyright (c) 2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr COSE <https://github.com/Vanaheimr/COSE.TS>
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * The COSE elliptic curve registry [IANA, "COSE Elliptic Curves"].
 *
 * Two widths are recorded per curve and they are kept apart on purpose: the
 * *field* size is the width of a coordinate, the *order* size is the width of
 * a private key and of each half of an ECDSA signature. They coincide for
 * every curve in this registry, and they are still two different quantities —
 * a curve where they differ would silently produce keys other implementations
 * reject.
 *
 * P-521 is 66 bytes, not 64 and not 65. Its field is 521 bits wide, which is
 * 65 bytes and one bit.
 */


/** A curve in the COSE registry. */
export interface CoseCurve {

    /** The IANA identifier, as it travels in a COSE key. */
    readonly id:          number;

    /** The registered name, e.g. `P-256`. Case sensitive. */
    readonly name:        string;

    /** The key type this curve belongs to: 2 = EC2, 1 = OKP. */
    readonly keyType:     number;

    /** The width of one coordinate, in bytes, or null when not an EC2 curve. */
    readonly fieldSize:   number | null;

    /** The width of a private key and of each signature half, in bytes. */
    readonly orderSize:   number | null;

}


const curve = (id: number, name: string, keyType: number,
               fieldSize: number | null, orderSize: number | null): CoseCurve =>
    ({ id, name, keyType, fieldSize, orderSize });


/** Key type 2, elliptic curve keys with x and y coordinates [RFC 9052, Section 7]. */
export const KEY_TYPE_EC2 = 2;

/** Key type 1, octet key pairs [RFC 9052, Section 7]. */
export const KEY_TYPE_OKP = 1;


/** The curves this implementation knows by name. */
export const CoseCurves = {

    P256:             curve(  1, 'P-256',           KEY_TYPE_EC2, 32,   32),
    P384:             curve(  2, 'P-384',           KEY_TYPE_EC2, 48,   48),
    P521:             curve(  3, 'P-521',           KEY_TYPE_EC2, 66,   66),
    X25519:           curve(  4, 'X25519',          KEY_TYPE_OKP, null, null),
    X448:             curve(  5, 'X448',            KEY_TYPE_OKP, null, null),
    Ed25519:          curve(  6, 'Ed25519',         KEY_TYPE_OKP, null, null),
    Ed448:            curve(  7, 'Ed448',           KEY_TYPE_OKP, null, null),
    secp256k1:        curve(  8, 'secp256k1',       KEY_TYPE_EC2, 32,   32),

    // Registered by ISO/IEC 18013-5 for the mobile driving licence.
    brainpoolP256r1:  curve(256, 'brainpoolP256r1', KEY_TYPE_EC2, 32,   32),
    brainpoolP320r1:  curve(257, 'brainpoolP320r1', KEY_TYPE_EC2, 40,   40),
    brainpoolP384r1:  curve(258, 'brainpoolP384r1', KEY_TYPE_EC2, 48,   48),
    brainpoolP512r1:  curve(259, 'brainpoolP512r1', KEY_TYPE_EC2, 64,   64),

} as const;


/** Every registered curve, in registry order. */
export const ALL_CURVES: readonly CoseCurve[] = Object.values(CoseCurves);


/** The curve with the given identifier, or null when it is not registered. */
export function curveById(id: number): CoseCurve | null {
    return ALL_CURVES.find(each => each.id === id) ?? null;
}


/**
 * The curve with the given name, or null.
 *
 * Case sensitive, like the registry: `p-256` is not `P-256`.
 */
export function curveByName(name: string): CoseCurve | null {
    return ALL_CURVES.find(each => each.name === name) ?? null;
}
