/*
 * Copyright (c) 2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr COSE <https://github.com/Vanaheimr/COSE.TS>
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * The two questions every verification has to answer before it can do any
 * arithmetic: *which algorithm*, and *over which payload*.
 *
 * Both are shared by COSE_Sign1, COSE_Sign and countersignatures, and both are
 * places where a permissive answer quietly destroys the guarantee. They live
 * here so that the three cannot drift apart.
 */

import { sameAlgorithm }        from './algorithm.ts';
import type { CoseAlgorithm }   from './algorithm.ts';
import type { CoseHeaders }     from './headers.ts';


/** Either an answer, or the reason there is none. */
export type Resolved<T> =
    | { readonly ok: true;  readonly value: T }
    | { readonly ok: false; readonly reason: string };


/**
 * Which algorithm to verify with.
 *
 * An algorithm stated in the *unprotected* bucket is not covered by the
 * signature and can therefore be changed by anyone on the path. It is not
 * silently trusted: the caller has to name the expected algorithm to accept
 * it, deliberately, which is the difference between a verifier that resists an
 * algorithm-substitution attack and one that documents that it does.
 */
export function resolveAlgorithm(protectedHeader:   CoseHeaders,
                                 unprotectedHeader: CoseHeaders,
                                 expected:          CoseAlgorithm | null,
                                 what:              string): Resolved<CoseAlgorithm> {

    const algorithm = expected ?? protectedHeader.algorithm;

    if (algorithm === null) {

        const stated = unprotectedHeader.algorithm;

        return {
            ok:     false,
            reason: stated !== null
                        ? `${what} states its algorithm '${stated.name}' within the unprotected header bucket only, where it is not covered by the signature: pass the expected algorithm explicitly in order to accept it!`
                        : `${what} does not state its signature algorithm: pass the expected algorithm explicitly!`,
        };

    }

    const stated = protectedHeader.algorithm ?? unprotectedHeader.algorithm;

    if (stated !== null && !sameAlgorithm(stated, algorithm))
        return {
            ok:     false,
            reason: `${what} was signed with the algorithm '${stated.name}', but the algorithm '${algorithm.name}' was expected!`,
        };

    return { ok: true, value: algorithm };

}


/**
 * Which payload the signature is computed over: the one carried within the
 * message, or the detached one supplied by the caller.
 *
 * Supplying both is rejected, because there would be no way to tell which of
 * the two a verification result refers to.
 */
export function resolvePayload(carried:  Uint8Array | null,
                               detached: Uint8Array | null,
                               what:     string): Resolved<Uint8Array> {

    if (carried !== null) {

        if (detached !== null)
            return { ok: false, reason: `${what} carries its payload, therefore no detached payload must be supplied!` };

        return { ok: true, value: carried };

    }

    if (detached === null)
        return { ok: false, reason: `The payload of ${what} is detached, therefore it must be supplied for the signature to be computed!` };

    return { ok: true, value: detached };

}
