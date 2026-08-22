/*
 * Copyright (c) 2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr COSE <https://github.com/Vanaheimr/COSE.TS>
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * The seeds the fuzz suite starts from, and the ways they are damaged.
 *
 * Random bytes are a weak fuzzer for a self-describing format: almost every
 * draw dies at the first byte, and the code that has already decided it is
 * looking at a protected bucket or a recipient array is never reached.
 * Starting from messages that *are* valid and damaging them one edit at a
 * time puts the input a single bit away from correct, which is where a
 * parser's mistakes live. Both are run: mutation reaches the deep paths,
 * random bytes cover the shallow ones the seeds never spell.
 *
 * Every message seed is built by this library at load time, and
 * deterministically — RFC 6979 signing, fixed keys, fixed nonces — so a
 * failing case reproduces from its fast-check counterexample alone. The
 * certificate seeds are the Bouncy Castle corpus, damaged the same way.
 */

import fc                        from 'fast-check';

import { CborError }             from '@vanaheimr/metrological-cbor';

import { CoseAlgorithms, CoseEncrypt, CoseEncrypt0, CoseError,
         CoseKey, CoseMac, CoseMac0, CoseRecipient,
         CoseSign, CoseSign1 }   from '../../src/index.ts';
import corpus                    from '../certificate-corpus.json' with { type: 'json' };
import { KEY_11, unhex }         from '../vectors.ts';


/**
 * How many cases each property runs.
 *
 * The default is what a pull request can afford; the nightly job raises it,
 * so the corpus that runs while nobody is waiting is a much larger one. Set
 * `COSE_FUZZ_RUNS` to any positive integer.
 */
export const FUZZ_RUNS: number = (() => {
    const stated = Number.parseInt(process.env.COSE_FUZZ_RUNS ?? '', 10);
    return Number.isSafeInteger(stated) && stated > 0 ? stated : 2_000;
})();


const PAYLOAD  = new TextEncoder().encode('This is the content.');
const NAMED    = { keyIdentifier: new TextEncoder().encode('our-secret') };

/** The shared secret RFC 9052's MAC examples use; it secures nothing. */
const HMAC_KEY = CoseKey.fromSymmetricKey(
    unhex('849B57219DAE48DE646D07DBB533566E976686457C1491BE3A76DCEA6C427188'),
    { algorithm: CoseAlgorithms.HMAC256_256, ...NAMED });

/** The 128-bit key and nonce of the COSE working group's A128GCM examples. */
const GCM_KEY  = CoseKey.fromSymmetricKey(
    unhex('849B5786457C1491BE3A76DCEA6C4271'),
    { algorithm: CoseAlgorithms.A128GCM, ...NAMED });

const IV       = unhex('C9CF4DF2FE6C632BF7886413');

const KEK      = CoseKey.fromSymmetricKey(
    unhex('000102030405060708090A0B0C0D0E0F'),
    { algorithm: CoseAlgorithms.A128KW, keyIdentifier: new TextEncoder().encode('kek') });


/** The message a valid `COSE_Sign1` seed carries, for the signature-damage test. */
export const SIGN1_SEED: Uint8Array = CoseSign1.sign(PAYLOAD, KEY_11).toBytes();

/** The key that verifies {@link SIGN1_SEED}. */
export const SIGN1_VERIFIER: CoseKey = KEY_11.publicKey();


/** One COSE structure under fuzz: its name, one valid seed, and its parser. */
export interface FuzzedStructure {
    readonly name:  string;
    readonly seed:  Uint8Array;
    readonly parse: (bytes: Uint8Array) => { toBytes(): Uint8Array };
}

/**
 * Every structure this library parses, one authentic seed each — signed,
 * MACed and encrypted for real, recipients included, plus a COSE key.
 */
export const STRUCTURES: readonly FuzzedStructure[] = [
    { name: 'COSE_Sign1',    seed: SIGN1_SEED,
      parse: bytes => CoseSign1.parse(bytes) },
    { name: 'COSE_Sign',     seed: CoseSign.sign(PAYLOAD, KEY_11).toBytes(),
      parse: bytes => CoseSign.parse(bytes) },
    { name: 'COSE_Mac0',     seed: CoseMac0.create(PAYLOAD, HMAC_KEY).toBytes(),
      parse: bytes => CoseMac0.parse(bytes) },
    { name: 'COSE_Mac',      seed: CoseMac.create(PAYLOAD, HMAC_KEY, [CoseRecipient.direct(HMAC_KEY)]).toBytes(),
      parse: bytes => CoseMac.parse(bytes) },
    { name: 'COSE_Encrypt0', seed: CoseEncrypt0.encrypt(PAYLOAD, GCM_KEY, { iv: IV }).toBytes(),
      parse: bytes => CoseEncrypt0.parse(bytes) },
    { name: 'COSE_Encrypt',  seed: CoseEncrypt.encrypt(PAYLOAD, GCM_KEY,
                                                       [CoseRecipient.keyWrap(GCM_KEY.privateKeyBytes(), KEK)],
                                                       { iv: IV }).toBytes(),
      parse: bytes => CoseEncrypt.parse(bytes) },
    { name: 'COSE_Key',      seed: KEY_11.toBytes(),
      parse: bytes => CoseKey.parse(bytes) },
];


/** The Bouncy-Castle-minted certificates of the corpus, as DER. */
export const CERTIFICATE_SEEDS: readonly Uint8Array[] =
    Object.values(corpus.certificates as Record<string, string>).map(unhex);


/**
 * The seed, damaged by one edit: a flipped bit, a rewritten byte, a byte
 * inserted or removed, or a truncation. One edit, deliberately — an input a
 * single step away from correct is the one a parser's mistakes accept.
 */
export function mutatedFrom(seed: Uint8Array): fc.Arbitrary<Uint8Array> {

    return fc.oneof(

        fc.record({ index: fc.nat(seed.length - 1), bit: fc.nat(7) }).map(({ index, bit }) => {
            const copy = Uint8Array.from(seed);
            copy[index] = (copy[index] ?? 0) ^ (1 << bit);
            return copy;
        }),

        fc.record({ index: fc.nat(seed.length - 1), value: fc.nat(255) }).map(({ index, value }) => {
            const copy = Uint8Array.from(seed);
            copy[index] = value;
            return copy;
        }),

        fc.record({ index: fc.nat(seed.length), value: fc.nat(255) }).map(({ index, value }) => {
            const copy = new Uint8Array(seed.length + 1);
            copy.set(seed.subarray(0, index), 0);
            copy[index] = value;
            copy.set(seed.subarray(index), index + 1);
            return copy;
        }),

        fc.nat(seed.length - 1).map(index => {
            const copy = new Uint8Array(seed.length - 1);
            copy.set(seed.subarray(0, index), 0);
            copy.set(seed.subarray(index + 1), index);
            return copy;
        }),

        fc.nat(seed.length).map(length => seed.subarray(0, length)),

    );

}


/** A damaged certificate, from any seed of the corpus. */
export const mutatedCertificate = (): fc.Arbitrary<Uint8Array> =>
    fc.constantFrom(...CERTIFICATE_SEEDS).chain(mutatedFrom);


/** Bytes with no relation to any seed: the shallow paths the seeds never spell. */
export const arbitraryBytes: fc.Arbitrary<Uint8Array> = fc.uint8Array({ maxLength: 512 });


/**
 * Of `count` samples, the share the given reader accepts.
 *
 * The floors asserted over this are what make the rest mean something: every
 * other property is of the form "if it was accepted, then …", which holds
 * vacuously over a corpus that has stopped reaching the parser.
 */
export function acceptanceRate(cases:  fc.Arbitrary<Uint8Array>,
                               read:   (bytes: Uint8Array) => unknown,
                               count = 1_000): number {

    let accepted = 0;

    for (const bytes of fc.sample(cases, count)) {
        try { read(bytes); accepted++; }
        catch { /* a refusal is the other expected outcome */ }
    }

    return accepted / count;

}


/**
 * Every input has exactly one of two outcomes: a value, or a typed refusal —
 * `CoseError` from this library, `CborError` from the codec beneath it. A
 * third outcome is a defect, and this re-throws it as itself.
 */
export function outcome(run: () => unknown): void {

    try {
        run();
    }
    catch (error) {

        if (error instanceof CoseError || error instanceof CborError)
            return;

        throw error;

    }

}
