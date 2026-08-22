/*
 * Copyright (c) 2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr COSE <https://github.com/Vanaheimr/COSE.TS>
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * The parsers against input that is trying to break them.
 *
 * Everything this library reads arrives from somewhere else: a COSE message
 * from a wire, a certificate from a party that may be hostile, a key from a
 * file someone else wrote. The requirement is not that it parse everything —
 * it is that every possible input have exactly one of two outcomes, a value
 * or a typed refusal, and that neither take unbounded time. A third outcome
 * is a defect, and `outcome` re-throws it as itself.
 *
 * Two properties ride on top of that. Whatever a parser accepts it must
 * re-encode, stably: one round trip in, the bytes are a fixed point, because
 * a message that re-encodes differently each time cannot carry a signature.
 * And a damaged signature must never verify, whichever of its bytes the
 * damage lands on — checked exhaustively rather than by property, since the
 * signature is only sixty-four bytes wide.
 */

import fc                        from 'fast-check';
import { describe, expect, it }  from 'vitest';

import { CoseSign1,
         X509Certificate }       from '../../src/index.ts';
import { hex }                   from '../vectors.ts';
import { acceptanceRate, arbitraryBytes, FUZZ_RUNS,
         mutatedCertificate, mutatedFrom, outcome,
         SIGN1_SEED, SIGN1_VERIFIER, STRUCTURES } from './corpus.ts';


describe('the fuzzer itself', () => {

    // Every property below is of the form "if it was accepted, then …",
    // which holds vacuously over a corpus that has stopped reaching the
    // parser — a fuzzer that reports green while covering nothing is worse
    // than none. These floors are far below what is measured (29 to 33
    // percent for the messages, 22 for the certificates), so that ordinary
    // variation does not trip them and a corpus gone wrong still does.

    for (const structure of STRUCTURES)
        it(`gets past ${structure.name} often enough to be testing it`, () => {
            expect(acceptanceRate(mutatedFrom(structure.seed), structure.parse)).toBeGreaterThan(0.15);
        });

    it('gets past the DER reader often enough to be testing it', () => {
        expect(acceptanceRate(mutatedCertificate(), bytes => X509Certificate.parse(bytes))).toBeGreaterThan(0.10);
    });

});


for (const structure of STRUCTURES)
    describe(`${structure.name}, against damaged messages`, () => {

        it('either parses or refuses, and never a third thing', () => {

            fc.assert(
                fc.property(mutatedFrom(structure.seed), bytes => {
                    outcome(() => structure.parse(bytes));
                }),
                { numRuns: FUZZ_RUNS });

        });

        it('re-encodes whatever it accepts, and stably', () => {

            fc.assert(
                fc.property(mutatedFrom(structure.seed), bytes => {

                    let message;

                    try {
                        message = structure.parse(bytes);
                    }
                    catch {
                        return;
                    }

                    // Accepted once, the message must survive its own round
                    // trip: what toBytes writes, parse accepts, and writes
                    // again identically.
                    const first  = message.toBytes();
                    const second = structure.parse(first).toBytes();

                    expect(hex(second)).toBe(hex(first));

                }),
                { numRuns: FUZZ_RUNS });

        });

        it('survives bytes with no relation to any seed', () => {

            fc.assert(
                fc.property(arbitraryBytes, bytes => {
                    outcome(() => structure.parse(bytes));
                }),
                { numRuns: FUZZ_RUNS });

        });

    });


describe('a damaged signature', () => {

    it('never verifies, whichever of its bytes the damage lands on', () => {

        // The signature is the last element of the COSE_Sign1 array, so its
        // bytes are the last bytes of the message: the flip lands inside the
        // byte string, the message still parses, and verification is the
        // layer that has to refuse it.
        const width = CoseSign1.parse(SIGN1_SEED).signature.length;

        for (let index = 0; index < width; index++) {

            const damaged   = Uint8Array.from(SIGN1_SEED);
            const position  = damaged.length - 1 - index;

            damaged[position] = (damaged[position] ?? 0) ^ 0x01;

            expect(CoseSign1.parse(damaged).verify(SIGN1_VERIFIER).verified,
                   `signature byte ${String(width - 1 - index)}`).toBe(false);

        }

    });

});


describe('the DER reader, against damaged certificates', () => {

    it('either parses or refuses, and never a third thing', () => {

        fc.assert(
            fc.property(mutatedCertificate(), bytes => {
                outcome(() => X509Certificate.parse(bytes));
            }),
            { numRuns: FUZZ_RUNS });

    });

    it('survives bytes with no relation to any seed', () => {

        fc.assert(
            fc.property(arbitraryBytes, bytes => {
                outcome(() => X509Certificate.parse(bytes));
            }),
            { numRuns: FUZZ_RUNS });

    });

});
