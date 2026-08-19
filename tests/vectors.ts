/*
 * Copyright (c) 2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr COSE <https://github.com/Vanaheimr/COSE.TS>
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * The published vectors, and the keys they were made with.
 *
 * These are byte for byte the constants the C# reference implementation tests
 * against — same RFCs, same appendices, same transcription. Two independent
 * implementations agreeing with a published example is a much stronger claim
 * than either of them agreeing with itself, and it is what makes the
 * cross-signing suite mean something.
 *
 * The keys are the RFCs' own example keys. They secure nothing.
 *
 * Each key is built from its private scalar alone and its public point is
 * recomputed, so that comparing the result with the published coordinates
 * tests the point arithmetic and the fixed-width padding rather than assuming
 * them.
 */

import { CoseAlgorithms, CoseCurves, CoseKey }  from '../src/index.ts';


/** The JOSE-flavoured base64url the RFC 9052 examples print their keys in. */
export function base64url(value: string): Uint8Array {
    return new Uint8Array(Buffer.from(value.replace(/-/gu, '+').replace(/_/gu, '/'), 'base64'));
}

/** Uppercase hexadecimal, the notation both specifications use. */
export function hex(value: Uint8Array): string {
    return Buffer.from(value).toString('hex').toUpperCase();
}

/** Bytes from hexadecimal. */
export function unhex(value: string): Uint8Array {
    return new Uint8Array(Buffer.from(value, 'hex'));
}

/** The payload of nearly every example in RFC 9052. */
export const CONTENT = new TextEncoder().encode('This is the content.');


// --- The P-256 key of RFC 9052, key identifier "11" -------------------------

export const KEY_11_X = 'usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8';
export const KEY_11_Y = 'IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4';
export const KEY_11_D = 'V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM';

/** Used by Appendix C.2.1, by C.1.1 and by the body signature of RFC 9338 A.2.1. */
export const KEY_11 = CoseKey.fromPrivateScalar(
    CoseCurves.P256,
    base64url(KEY_11_D),
    {
        algorithm:     CoseAlgorithms.ES256,
        keyIdentifier: new TextEncoder().encode('11'),
    },
);


// --- The P-521 key of RFC 9052, "bilbo.baggins@hobbiton.example" ------------

export const KEY_BILBO_X = 'AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt';
export const KEY_BILBO_Y = 'AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1';
export const KEY_BILBO_D = 'AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zbKipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt';

/**
 * Both its private scalar and its x coordinate begin with a zero byte, which
 * is exactly what a naive big-integer serialization drops.
 */
export const KEY_BILBO = CoseKey.fromPrivateScalar(
    CoseCurves.P521,
    base64url(KEY_BILBO_D),
    {
        algorithm:     CoseAlgorithms.ES512,
        keyIdentifier: new TextEncoder().encode('bilbo.baggins@hobbiton.example'),
    },
);
