/*
 * Copyright (c) 2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr COSE <https://github.com/Vanaheimr/COSE.TS>
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * What signing does to a payload before it signs it.
 *
 * A COSE payload is an opaque byte string, so a signature covers one
 * *spelling* of a record rather than the record. That costs nothing until
 * somebody receives a message, decodes it and encodes it again — which in
 * e-mobility is the normal case rather than the exception: a meter reading
 * passes a charging station, a backend and a roaming hub on its way to the
 * customer, and every one of them parses and re-serializes it. Their encoders
 * write the deterministic encoding of RFC 8949 §4.2.1. Where the signer wrote
 * something else, the record arrives unaltered in meaning and broken in fact,
 * and the failure looks exactly like tampering.
 *
 * `CoseSign1.sign` therefore rewrites a CBOR payload in that encoding before
 * signing it, unless told not to. The pair in the middle of this file is what
 * shows the default is doing the work: the same record, forwarded the same
 * way, survives with it and breaks without it.
 *
 * The record below is the `sign1-non-canonical-payload` vector of the
 * conformance suite, where Styx signs the very same bytes and has to arrive
 * at the very same message.
 */

import { describe, expect, it }              from 'vitest';

import { canonicalizePayload, cbor,
         CoseAlgorithms, CoseCurves, CoseKey,
         CoseSign1, isCanonicalPayload,
         PRESERVE }                          from '../src/index.ts';


const key = CoseKey.fromPrivateScalar(
    CoseCurves.P256,
    cbor.hexToBytes('57C92077664146E876760C9520D054AA93C3AFB04E306705DB6090308507B4D3'),
    { algorithm: CoseAlgorithms.ES256 },
);


/**
 * One meter reading, written the way a person reads it: meter, then time.
 * Deterministic encoding sorts map keys by their encoded bytes, which puts the
 * shorter name first — so these bytes are well-formed CBOR and not the
 * deterministic encoding of themselves.
 */
const readingInReadingOrder = (): Uint8Array =>
    cbor.encode(
        cbor.map([
            [cbor.text('meter'), cbor.text('1ISA0000000042')],
            [cbor.text('time'),  cbor.tag(0, cbor.text('2026-08-15T08:14:00Z'))],
        ]),
        PRESERVE,
    );


/**
 * What a backend or a roaming hub does to a record it passes on: take the
 * message apart, decode the payload, encode it again with its own encoder —
 * which writes the deterministic encoding — and put the message back together.
 * Not one value is touched.
 */
const forward = (message: CoseSign1): CoseSign1 =>
    new CoseSign1(message.protectedHeaderBytes,
                  message.unprotectedHeader,
                  canonicalizePayload(message.payload!),
                  message.signature,
                  message.isTagged);


describe('a record in reading order', () => {

    it('is not canonical, and canonicalizing it changes nothing but the order', () => {

        const reading   = readingInReadingOrder();

        expect(isCanonicalPayload(reading)).toBe(false);

        const canonical = canonicalizePayload(reading);

        // Sorting a map moves bytes around without adding or removing any:
        // same length, same entries, same values. Which is precisely what
        // makes the breakage below impossible to see by eye.
        expect(canonical.length).toBe(reading.length);
        expect(isCanonicalPayload(canonical)).toBe(true);
        // Decoded leniently, because a strict decoder is exactly what
        // refuses the left-hand side of the comparison.
        expect(cbor.encodeToHex(cbor.decode(canonical, { strict: false })))
            .toBe(cbor.encodeToHex(cbor.decode(reading,   { strict: false })));

    });

});


describe('a payload that is not CBOR', () => {

    it('is signed as it is', () => {

        // The payload of every published COSE example there is — and not CBOR
        // at all. There is nothing here to canonicalize, and refusing to sign
        // it would make the default useless for the format's own examples.
        const text = new TextEncoder().encode('This is the content.');

        expect(canonicalizePayload(text)).toEqual(text);
        expect(isCanonicalPayload(text)).toBe(false);

        const signed = CoseSign1.sign(text, key);

        expect(signed.payload).toEqual(text);
        expect(signed.verify(key.publicKey()).verified).toBe(true);

    });

});


describe('signing', () => {

    it('canonicalizes by default, so forwarding survives', () => {

        const reading = readingInReadingOrder();
        const signed  = CoseSign1.sign(reading, key);

        // What was signed is not what was handed in ...
        expect(signed.payload).not.toEqual(reading);
        expect(isCanonicalPayload(signed.payload!)).toBe(true);

        // ... and that is what lets everybody who forwards the record decode
        // and encode it again without destroying it.
        expect(forward(signed).verify(key.publicKey()).verified).toBe(true);

    });

    it('signs the bytes as they are where told to, and forwarding breaks them', () => {

        const reading = readingInReadingOrder();
        const signed  = CoseSign1.sign(reading, key, { canonicalizePayload: false });

        expect(signed.payload).toEqual(reading);
        expect(signed.verify(key.publicKey()).verified).toBe(true);

        // Nobody tampered with anything: the forwarder re-encoded the very
        // same two entries, and the signature is gone. This is the failure the
        // default exists to prevent, and the reason it is a default rather
        // than an option: the party who loses is never the party who chose.
        expect(forward(signed).verify(key.publicKey()).verified).toBe(false);

    });

    it('refuses a detached payload that canonicalizing would change', () => {

        const reading = readingInReadingOrder();

        // A detached payload does not travel within the message, so the
        // verifier is handed the caller's own bytes. Quietly signing a
        // different spelling of them would produce a message that can never
        // verify, whoever holds it — so this is the one place where
        // canonicalizing is refused rather than performed.
        expect(() => CoseSign1.sign(reading, key, { detachPayload: true })).toThrow();

        // Doing what the error asks for leaves nothing to change.
        const canonical = canonicalizePayload(reading);
        const detached  = CoseSign1.sign(canonical, key, { detachPayload: true });

        expect(detached.payload).toBeNull();
        expect(detached.verify(key.publicKey(), { detachedPayload: canonical }).verified).toBe(true);

    });

});
