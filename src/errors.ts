/*
 * Copyright (c) 2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr COSE <https://github.com/Vanaheimr/COSE.TS>
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * What goes wrong, and the difference between the two kinds of wrong.
 *
 * A malformed message is a programming or transport error and throws. A
 * signature that does not verify is neither: it is the expected outcome of
 * checking untrusted data, and a library that throws for it invites the
 * `catch {}` that swallows the distinction. Verification therefore returns a
 * result that has to be looked at, and says why when the answer is no.
 */


/** A COSE message, key or header bucket that is not well formed. */
export class CoseError extends Error {

    public override readonly name = 'CoseError';

    public constructor(message: string, options?: ErrorOptions) {
        super(message, options);
    }

}


/**
 * The outcome of a verification.
 *
 * `verified: false` carries a reason, because "it did not verify" is rarely
 * the useful half of the answer — whether the algorithm was refused, the
 * payload was missing or the signature itself was wrong are three very
 * different situations.
 */
export type Verification =
    | { readonly verified: true }
    | { readonly verified: false; readonly reason: string };


/** A successful verification. */
export const VERIFIED: Verification = { verified: true };


/**
 * A verification that failed.
 *
 * Named because it is the half of {@link Verification} that carries a reason,
 * and a function returning only this half lets a caller pass it straight on as
 * its own failure without the type widening back to "or it succeeded".
 */
export type NotVerified = Extract<Verification, { verified: false }>;


/** A failed verification, with the reason it failed. */
export const notVerified = (reason: string): NotVerified =>
    ({ verified: false, reason });
