/*
 * Copyright (c) 2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr COSE <https://github.com/Vanaheimr/COSE.TS>
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * The countersignature of RFC 8152, header parameter 7, which RFC 9338
 * deprecated and RFC 9052, Section 3.1 still says "must be understood by new
 * implementations, to remain compatible with senders that adhere to" RFC 8152.
 *
 * The golden vectors are the COSE working group's own,
 * countersign/signed1-01.json and signed1-02.json of
 * https://github.com/cose-wg/Examples: a COSE_Sign1 signed with EdDSA on
 * Ed25519, countersigned once with EdDSA and then also with ES256 on P-256.
 * The working group publishes the structure each countersigner signed as
 * well, so the Sig_structure is checked byte for byte, and the EdDSA
 * countersignature, being deterministic, verifies only if it was computed over
 * exactly those bytes. Styx is held to the same two examples.
 */

import { describe, expect, it }              from 'vitest';

import { cbor, CoseAlgorithms, CoseCurves,
         CoseHeaders, CoseKey, CoseSign1 }   from '../src/index.ts';
import { CONTENT, hex, KEY_11, unhex }       from './vectors.ts';


/** The Ed25519 key of both examples, with the key identifier "11". */
const ED25519 = CoseKey.fromOkpPublicKey(
    CoseCurves.Ed25519,
    unhex('D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F707511A'));

/** The P-256 key of both examples: RFC 9052, Appendix C.7, "11". */
const P256 = KEY_11.publicKey();

const KEY_IDENTIFIER = new TextEncoder().encode('11');

/** countersign/signed1-01.json: one countersignature, EdDSA. */
const SIGNED1_01 = unhex(
    'D28445A201270300A2078343A10127A10442313158406DAED158AFE4032E8DD477D3D2B7F667E7957AA8302BB5E568B4DCBCCE3CF0ED5A90F831351C85D6155A42A17CA1F25F501CC13F67108AE53BDA92DB88272E000442313154546869732069732074686520636F6E74656E742E58407142FD2FF96D56DB85BEE905A76BA1D0B7321A95C8C4D3607C5781932B7AFB8711497DFA751BF40B58B3BCC32300B1487F3DB34085EEF013BF08F4A44D6FEF0D');

/** countersign/signed1-02.json: two of them, EdDSA and ES256. */
const SIGNED1_02 = unhex(
    'D28445A201270300A207828343A10127A10442313158406DAED158AFE4032E8DD477D3D2B7F667E7957AA8302BB5E568B4DCBCCE3CF0ED5A90F831351C85D6155A42A17CA1F25F501CC13F67108AE53BDA92DB88272E008343A10126A104423131584093487D09256A3EF4963719BA5CF101ACE2FC13D6314B49582171FFA4A1314DC93E4A4ADFA42A79E31B35D7304358585B41799678CE00CA47C3E023863923F8C80442313154546869732069732074686520636F6E74656E742E58407142FD2FF96D56DB85BEE905A76BA1D0B7321A95C8C4D3607C5781932B7AFB8711497DFA751BF40B58B3BCC32300B1487F3DB34085EEF013BF08F4A44D6FEF0D');

/** The "intermediates" of both examples: what each countersigner signed. */
const TO_BE_SIGNED_EDDSA = '8570436F756E7465725369676E617475726545A20127030043A101274054546869732069732074686520636F6E74656E742E';
const TO_BE_SIGNED_ES256 = '8570436F756E7465725369676E617475726545A20127030043A101264054546869732069732074686520636F6E74656E742E';


describe('the countersignature of RFC 8152', () => {

    it('verifies as the working group published it', () => {

        const message = CoseSign1.parse(SIGNED1_01);

        // A single countersignature is written bare.
        expect(message.rfc8152Countersignatures).toHaveLength(1);

        const countersignature = message.rfc8152Countersignatures[0]!;

        expect(countersignature.algorithm).toBe(CoseAlgorithms.EdDSA);
        expect(hex(countersignature.keyIdentifier!)).toBe(hex(KEY_IDENTIFIER));

        // What the working group says the countersigner signed.
        expect(hex(CoseSign1.toBeRfc8152Countersigned(message.protectedHeaderBytes,
                                                      countersignature.protectedHeaderBytes,
                                                      CONTENT))).toBe(TO_BE_SIGNED_EDDSA);

        expect(message.verifyRfc8152Countersignature(countersignature, ED25519)).toStrictEqual({ verified: true });

        // And the body signature, which is a separate question.
        expect(message.verify(ED25519)).toStrictEqual({ verified: true });

    });

    it('verifies both of them, each with its own key only', () => {

        const message = CoseSign1.parse(SIGNED1_02);

        // Several are written as an array of them.
        expect(message.rfc8152Countersignatures).toHaveLength(2);

        const [eddsa, es256] = message.rfc8152Countersignatures;

        expect(eddsa!.algorithm).toBe(CoseAlgorithms.EdDSA);
        expect(es256!.algorithm).toBe(CoseAlgorithms.ES256);

        expect(hex(CoseSign1.toBeRfc8152Countersigned(message.protectedHeaderBytes,
                                                      es256!.protectedHeaderBytes,
                                                      CONTENT))).toBe(TO_BE_SIGNED_ES256);

        expect(message.verifyRfc8152Countersignature(eddsa!, ED25519)).toStrictEqual({ verified: true });
        expect(message.verifyRfc8152Countersignature(es256!, P256)).toStrictEqual({ verified: true });

        expect(message.verifyRfc8152Countersignature(es256!, ED25519).verified).toBe(false);

    });

    it('is not a countersignature of version 2', () => {

        const message = CoseSign1.parse(SIGNED1_01);

        // Label 7 is not label 11...
        expect(message.countersignatures).toHaveLength(0);

        // ...and the structure of version 2 is not the one that was signed.
        expect(message.verifyCountersignature(message.rfc8152Countersignatures[0]!, ED25519).verified).toBe(false);

    });

    it('does not cover the body signature', () => {

        const published = CoseSign1.parse(SIGNED1_01);

        // The body signature replaced by 64 zero bytes: the message no longer
        // verifies, and its RFC 8152 countersignature still does. That is the
        // flaw RFC 9338 replaced it for, and why a valid one does not say
        // that its signer saw the signature.
        const replaced = new CoseSign1(published.protectedHeaderBytes,
                                       published.unprotectedHeader,
                                       published.payload,
                                       new Uint8Array(64));

        expect(replaced.verify(ED25519).verified).toBe(false);

        expect(replaced.verifyRfc8152Countersignature(replaced.rfc8152Countersignatures[0]!,
                                                      ED25519)).toStrictEqual({ verified: true });

    });

    it('does cover the payload and the protected bucket', () => {

        const published = CoseSign1.parse(SIGNED1_01);

        const otherPayload = new CoseSign1(published.protectedHeaderBytes,
                                           published.unprotectedHeader,
                                           new TextEncoder().encode('This is other content.'),
                                           published.signature);

        expect(otherPayload.verifyRfc8152Countersignature(otherPayload.rfc8152Countersignatures[0]!,
                                                          ED25519).verified).toBe(false);

        // The same algorithm, without the content type the published
        // protected bucket carries.
        const otherBucket = new CoseSign1(unhex('A10127'),
                                          published.unprotectedHeader,
                                          published.payload,
                                          published.signature);

        expect(otherBucket.verifyRfc8152Countersignature(otherBucket.rfc8152Countersignatures[0]!,
                                                         ED25519).verified).toBe(false);

    });

    it('is refused where label 7 holds no countersignature', () => {

        const published = CoseSign1.parse(SIGNED1_01);

        const notAnArray = new CoseSign1(published.protectedHeaderBytes,
                                         CoseHeaders.empty.set(cbor.int(7), cbor.text('countersigned')),
                                         published.payload,
                                         published.signature);

        expect(() => notAnArray.rfc8152Countersignatures).toThrow('must be a COSE_Signature or an array of them');

        const notASignature = new CoseSign1(published.protectedHeaderBytes,
                                            CoseHeaders.empty.set(cbor.int(7), cbor.array([cbor.int(1)])),
                                            published.payload,
                                            published.signature);

        expect(() => notASignature.rfc8152Countersignatures).toThrow();

    });

});
