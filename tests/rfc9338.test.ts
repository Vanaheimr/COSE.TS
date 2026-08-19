/*
 * Copyright (c) 2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr COSE <https://github.com/Vanaheimr/COSE.TS>
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Countersignatures [RFC 9338], against the worked example of Appendix A.2.1.
 *
 * The RFC prints that example in diagnostic notation only, so the message is
 * assembled here from its documented parts. That both its body signature and
 * its countersignature then verify against the published keys is what proves
 * the assembly and the transcription — a single wrong byte in either
 * structure, and neither would.
 *
 * The version 2 structure is the one implemented, and the difference from
 * RFC 8152 is not cosmetic: the older countersignature covered the payload but
 * *not* the signature it was countersigning, so it never actually attested to
 * having seen it. Version 2 appends that signature as `other_fields`, which is
 * why replacing the body signature — even with another valid one over the same
 * payload — invalidates the countersignature. There is a test for exactly that
 * below.
 */

import { describe, expect, it }              from 'vitest';

import { cbor, CoseAlgorithms, CoseHeaders,
         CoseSign1, CoseSignature,
         signWith }                          from '../src/index.ts';
import { CONTENT, hex, KEY_11,
         KEY_BILBO, unhex }                  from './vectors.ts';


/** `{1: -7, 3: 0}` — ES256 and a content type. */
const BODY_PROTECTED             = unhex('A201260300');

/** `{1: -36}` — ES512, the countersigner's algorithm. */
const COUNTERSIGNATURE_PROTECTED = unhex('A1013823');

const BODY_SIGNATURE = unhex(
    'BB587D6B15F47BFD54D2CBFCECEF75451E92B08A514BD439FA3AA65C6AC92DF0' +
    'D7328C4A47529B32ADD3DD1B4E940071C021E9A8F2641F1D8E3B053DDD65AE52');

const COUNTERSIGNATURE = unhex(
    '01B1291B0E60A79C459A4A9184A0D393E034B34AF069A1CCA34F5A913AFFFF69' +
    '8002295FA9F8FCBFB6FDFF59132FC0C406E98754A98F1FBFE81C03095F481856' +
    'BC470170227206FA5BEE3C0431C56A66824E7AAF692985952E31271434B2BA2E' +
    '47A335C658B5E995AEB5D63CF2D0CED367D3E4CC8FFFD53B70D115BAA9E86961' +
    'FBD1A5CF');


/** The message of Appendix A.2.1, assembled from the parts the RFC prints. */
function appendixA21(): CoseSign1 {

    const countersignature = new CoseSignature(COUNTERSIGNATURE_PROTECTED,
                                               CoseHeaders.empty,
                                               COUNTERSIGNATURE);

    return new CoseSign1(BODY_PROTECTED,
                         CoseHeaders.empty.set(cbor.int(11), countersignature.toCbor()),
                         CONTENT,
                         BODY_SIGNATURE);

}


describe('RFC 9338 Appendix A.2.1', () => {

    const message = appendixA21();

    it('carries exactly one countersignature, held bare rather than wrapped', () => {

        expect(message.countersignatures).toHaveLength(1);
        expect(message.countersignatures[0]!.algorithm?.name).toBe('ES512');

        // A single countersignature is the three-element structure itself, so
        // its first element is the protected bucket: a byte string.
        const value = message.unprotectedHeader.get(cbor.int(11));

        expect(value?.type).toBe('array');
        expect(value?.type === 'array' && value.items[0]?.type).toBe('bytes');

    });

    it('signs a six-element structure whose last element holds the body signature', () => {

        const structure = cbor.decode(message.toBeCountersigned(message.countersignatures[0]!),
                                      { strict: false });

        expect(structure.type).toBe('array');

        if (structure.type !== 'array')
            throw new Error('unreachable');

        expect(structure.items).toHaveLength(6);
        expect(structure.items[0]).toStrictEqual(cbor.text('CounterSignatureV2'));

        // other_fields is an array holding the one signature — not a bare
        // byte string, which is the detail that decides interoperability.
        const otherFields = structure.items[5]!;

        expect(otherFields.type).toBe('array');
        expect(otherFields.type === 'array' && otherFields.items).toHaveLength(1);
        expect(otherFields.type === 'array' && otherFields.items[0]).toStrictEqual(cbor.bytes(BODY_SIGNATURE));

    });

    it('verifies both the body signature and the countersignature', () => {

        expect(message.verify(KEY_11.publicKey())).toStrictEqual({ verified: true });

        expect(message.verifyCountersignature(message.countersignatures[0]!,
                                              KEY_BILBO.publicKey())).toStrictEqual({ verified: true });

    });

    it('does not accept the countersignature as a body signature, or the reverse', () => {

        expect(message.verify(KEY_BILBO.publicKey()).verified).toBe(false);

        expect(message.verifyCountersignature(message.countersignatures[0]!,
                                              KEY_11.publicKey()).verified).toBe(false);

    });

});


describe('a countersignature', () => {

    it('breaks when the signature it covers changes, even for a valid one', () => {

        const message   = appendixA21();

        // Another perfectly good signature by the same key over the same
        // payload. The body still verifies...
        const resigned  = new CoseSign1(
            BODY_PROTECTED,
            message.unprotectedHeader,
            CONTENT,
            signWith(CoseAlgorithms.ES256, KEY_11.curve,
                     CoseSign1.toBeSigned(BODY_PROTECTED, CONTENT),
                     KEY_11.privateKeyBytes()),
        );

        expect(hex(resigned.signature)).not.toBe(hex(BODY_SIGNATURE));
        expect(resigned.verify(KEY_11.publicKey()).verified).toBe(true);

        // ...and the countersignature does not, because it attested to the
        // signature that is no longer there.
        expect(resigned.verifyCountersignature(resigned.countersignatures[0]!,
                                               KEY_BILBO.publicKey()).verified).toBe(false);

    });

    it('leaves the message it is added to byte-identical where it matters', () => {

        const signed  = CoseSign1.sign(CONTENT, KEY_11);
        const vouched = signed.addCountersignature(KEY_BILBO);

        expect(hex(vouched.signature)).toBe(hex(signed.signature));
        expect(hex(vouched.protectedHeaderBytes)).toBe(hex(signed.protectedHeaderBytes));
        expect(hex(vouched.payload!)).toBe(hex(signed.payload!));

        // The body signature keeps verifying, and so does the new vouching.
        expect(vouched.verify(KEY_11.publicKey()).verified).toBe(true);
        expect(vouched.verifyCountersignature(vouched.countersignatures[0]!,
                                              KEY_BILBO.publicKey()).verified).toBe(true);

    });

    it('is wrapped in an array once there is more than one', () => {

        const two = CoseSign1.sign(CONTENT, KEY_11)
                             .addCountersignature(KEY_BILBO)
                             .addCountersignature(KEY_11);

        expect(two.countersignatures).toHaveLength(2);

        // Several countersignatures are an array of them, so the first element
        // is now an array rather than a byte string.
        const value = two.unprotectedHeader.get(cbor.int(11));

        expect(value?.type === 'array' && value.items[0]?.type).toBe('array');

        expect(two.verifyCountersignature(two.countersignatures[0]!, KEY_BILBO.publicKey()).verified).toBe(true);
        expect(two.verifyCountersignature(two.countersignatures[1]!, KEY_11.publicKey()).verified).toBe(true);

        // ...and they survive a round trip through the wire in that shape.
        const parsed = CoseSign1.parse(two.toBytes());

        expect(parsed.countersignatures).toHaveLength(2);
        expect(parsed.verifyCountersignature(parsed.countersignatures[1]!, KEY_11.publicKey()).verified).toBe(true);

    });

});
