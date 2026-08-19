/*
 * Copyright (c) 2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr COSE <https://github.com/Vanaheimr/COSE.TS>
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * The worked examples of RFC 9052.
 *
 * ECDSA is randomized, so published signature bytes cannot be reproduced by
 * signing them again — but they can be *verified*, which is the stronger
 * statement: a single wrong byte anywhere in the Sig_structure, in either
 * header bucket or in the key would make the verification fail. What is
 * checked here is therefore mostly that this implementation agrees with the
 * RFC about what a signature is over, and that its own re-encoding of the
 * published message is the published message.
 */

import { describe, expect, it }              from 'vitest';

import { CoseAlgorithms, CoseCurves, CoseHeaders,
         CoseKey, CoseSign, CoseSign1 }      from '../src/index.ts';
import { base64url, CONTENT, hex,
         KEY_11, KEY_11_X, KEY_11_Y,
         KEY_BILBO, KEY_BILBO_X,
         KEY_BILBO_Y, unhex }                from './vectors.ts';


// --- Appendix C.2.1, a COSE_Sign1 -------------------------------------------

const C21_MESSAGE      = 'D28443A10126A10442313154546869732069732074686520636F6E74656E742E' +
                         '58408EB33E4CA31D1C465AB05AAC34CC6B23D58FEF5C083106C4D25A91AEF0B0117E' +
                         '2AF9A291AA32E14AB834DC56ED2A223444547E01F11D3B0916E5A4C345CACB36';

const C21_TO_BE_SIGNED = '846A5369676E61747572653143A101264054546869732069732074686520636F6E74656E742E';

/** The same message untagged, which carries the very same signature bytes. */
const C21_UNTAGGED     = '8443A10126A10442313154546869732069732074686520636F6E74656E742E' +
                         '58408EB33E4CA31D1C465AB05AAC34CC6B23D58FEF5C083106C4D25A91AEF0B0117E' +
                         '2AF9A291AA32E14AB834DC56ED2A223444547E01F11D3B0916E5A4C345CACB36';

/** The same content signed with externally supplied additional data. */
const AAD_MESSAGE      = 'D28443A10126A10442313154546869732069732074686520636F6E74656E742E' +
                         '584010729CD711CB3813D8D8E944A8DA7111E7B258C9BDCA6135F7AE1ADBEE950989' +
                         '1267837E1E33BD36C150326AE62755C6BD8E540C3E8F92D7D225E8DB72B8820B';

const AAD_TO_BE_SIGNED = '846A5369676E61747572653143A101264C11AA22BB33CC44DD5500669954546869732069732074686520636F6E74656E742E';

const EXTERNAL_AAD     = unhex('11AA22BB33CC44DD55006699');


describe('the example keys', () => {

    it('produce the published coordinates from their private scalars alone', () => {

        expect(hex(KEY_11.x!)).toBe(hex(base64url(KEY_11_X)));
        expect(hex(KEY_11.y!)).toBe(hex(base64url(KEY_11_Y)));

        expect(hex(KEY_BILBO.x!)).toBe(hex(base64url(KEY_BILBO_X)));
        expect(hex(KEY_BILBO.y!)).toBe(hex(base64url(KEY_BILBO_Y)));

    });

    it('keep the leading zero octets that a big-integer serialization drops', () => {

        // P-521 is 66 bytes wide, and this key needs every one of them.
        expect(KEY_BILBO.d).toHaveLength(66);
        expect(KEY_BILBO.x).toHaveLength(66);
        expect(KEY_BILBO.d![0]).toBe(0x00);
        expect(KEY_BILBO.x![0]).toBe(0x00);

    });

});


describe('RFC 9052 Appendix C.2.1', () => {

    const message = CoseSign1.parse(unhex(C21_MESSAGE));

    it('is read as a tagged COSE_Sign1 with the headers the RFC prints', () => {

        expect(message.isTagged).toBe(true);
        expect(message.algorithm?.name).toBe('ES256');
        expect(hex(message.keyIdentifier!)).toBe('3131');
        expect(hex(message.payload!)).toBe(hex(CONTENT));

    });

    it('agrees with the RFC about what the signature is over', () => {
        expect(hex(message.toBeSigned())).toBe(C21_TO_BE_SIGNED);
    });

    it('verifies against the published key', () => {
        expect(message.verify(KEY_11.publicKey())).toStrictEqual({ verified: true });
    });

    it('re-encodes to the very bytes it was read from', () => {
        expect(hex(message.toBytes())).toBe(C21_MESSAGE);
    });

    it('carries the same signature with and without its tag', () => {

        const untagged = CoseSign1.parse(unhex(C21_UNTAGGED));

        expect(untagged.isTagged).toBe(false);
        expect(hex(untagged.signature)).toBe(hex(message.signature));
        expect(untagged.verify(KEY_11.publicKey()).verified).toBe(true);
        expect(hex(untagged.toBytes())).toBe(C21_UNTAGGED);

    });

    it('still verifies when its payload travels detached', () => {

        const detached = message.detach();

        expect(detached.isDetached).toBe(true);
        expect(detached.verify(KEY_11.publicKey(), { detachedPayload: CONTENT }).verified).toBe(true);

        // ...and refuses to guess when nobody supplies it.
        expect(detached.verify(KEY_11.publicKey()).verified).toBe(false);

    });

});


describe('external additional authenticated data', () => {

    const message = CoseSign1.parse(unhex(AAD_MESSAGE));

    it('is part of the Sig_structure without travelling in the message', () => {
        expect(hex(message.toBeSigned({ externalAad: EXTERNAL_AAD }))).toBe(AAD_TO_BE_SIGNED);
    });

    it('verifies only when the verifier supplies the same data', () => {

        expect(message.verify(KEY_11.publicKey(), { externalAad: EXTERNAL_AAD }).verified).toBe(true);
        expect(message.verify(KEY_11.publicKey()).verified).toBe(false);

    });

});


// --- Appendix C.1.1 and C.1.2, a COSE_Sign ----------------------------------

const ONE_SIGNER  = 'D8628440A054546869732069732074686520636F6E74656E742E818343A10126A104423131' +
                    '5840E2AEAFD40D69D19DFE6E52077C5D7FF4E408282CBEFB5D06CBF414AF2E19D982' +
                    'AC45AC98B8544C908B4507DE1E90B717C3D34816FE926A2B98F53AFD2FA0F30A';

const TWO_SIGNERS = 'D8628440A054546869732069732074686520636F6E74656E742E828343A10126A104423131' +
                    '5840E2AEAFD40D69D19DFE6E52077C5D7FF4E408282CBEFB5D06CBF414AF2E19D982' +
                    'AC45AC98B8544C908B4507DE1E90B717C3D34816FE926A2B98F53AFD2FA0F30A' +
                    '8344A1013823A104581E62696C626F2E62616767696E7340686F626269746F6E2E6578616D706C65' +
                    '588400A2D28A7C2BDB1587877420F65ADF7D0B9A06635DD1DE64BB62974C863F0B160' +
                    'DD2163734034E6AC003B01E8705524C5C4CA479A952F0247EE8CB0B4FB7397BA08D00' +
                    '9E0C8BF482270CC5771AA143966E5A469A09F613488030C5B07EC6D722E3835ADB5B2' +
                    'D8C44E95FFB13877DD2582866883535DE3BB03D01753F83AB87BB4F7A0297';

const SIGNATURE_0_TO_BE_SIGNED = '85695369676E61747572654043A101264054546869732069732074686520636F6E74656E742E';
const SIGNATURE_1_TO_BE_SIGNED = '85695369676E61747572654044A10138234054546869732069732074686520636F6E74656E742E';


describe('RFC 9052 Appendix C.1.1', () => {

    const message = CoseSign.parse(unhex(ONE_SIGNER));

    it('is read as a tagged COSE_Sign with one signature', () => {

        expect(message.isTagged).toBe(true);
        expect(message.signatures).toHaveLength(1);
        expect(message.protectedHeaderBytes).toHaveLength(0);
        expect(hex(message.payload!)).toBe(hex(CONTENT));

    });

    it('signs a five-element Sig_structure, not the four of a COSE_Sign1', () => {
        expect(hex(message.toBeSigned(message.signatures[0]!))).toBe(SIGNATURE_0_TO_BE_SIGNED);
    });

    it('verifies against the published key', () => {
        expect(message.verify(message.signatures[0]!, KEY_11.publicKey())).toStrictEqual({ verified: true });
    });

    it('re-encodes to the very bytes it was read from', () => {
        expect(hex(message.toBytes())).toBe(ONE_SIGNER);
    });

});


describe('RFC 9052 Appendix C.1.2', () => {

    const message = CoseSign.parse(unhex(TWO_SIGNERS));

    it('carries two signatures on two different curves', () => {

        expect(message.signatures).toHaveLength(2);
        expect(message.signatures[0]!.algorithm?.name).toBe('ES256');
        expect(message.signatures[1]!.algorithm?.name).toBe('ES512');
        expect(message.signatures[0]!.signature).toHaveLength(64);
        expect(message.signatures[1]!.signature).toHaveLength(132);

    });

    it('gives every signature its own protected bucket in the Sig_structure', () => {

        expect(hex(message.toBeSigned(message.signatures[0]!))).toBe(SIGNATURE_0_TO_BE_SIGNED);
        expect(hex(message.toBeSigned(message.signatures[1]!))).toBe(SIGNATURE_1_TO_BE_SIGNED);

    });

    it('verifies each signature with its own key', () => {

        expect(message.verify(message.signatures[0]!, KEY_11.publicKey())).toStrictEqual({ verified: true });
        expect(message.verify(message.signatures[1]!, KEY_BILBO.publicKey())).toStrictEqual({ verified: true });

    });

    it('never verifies one party\'s signature with the other party\'s key', () => {

        expect(message.verify(message.signatures[0]!, KEY_BILBO.publicKey()).verified).toBe(false);
        expect(message.verify(message.signatures[1]!, KEY_11.publicKey()).verified).toBe(false);

    });

    it('finds the signature a key belongs to', () => {

        expect(message.verifyAny(KEY_BILBO.publicKey())).toBe(message.signatures[1]);
        expect(message.verifyAny(KEY_11.publicKey())).toBe(message.signatures[0]);

    });

    it('re-encodes to the very bytes it was read from', () => {
        expect(hex(message.toBytes())).toBe(TWO_SIGNERS);
    });

    it('leaves the first signature untouched when a second is added', () => {

        const one   = CoseSign.parse(unhex(ONE_SIGNER));
        const two   = one.addSignature(KEY_BILBO);

        expect(hex(two.signatures[0]!.signature)).toBe(hex(one.signatures[0]!.signature));
        expect(two.verify(two.signatures[0]!, KEY_11.publicKey()).verified).toBe(true);
        expect(two.verify(two.signatures[1]!, KEY_BILBO.publicKey()).verified).toBe(true);

    });

});


describe('an empty protected bucket', () => {

    it('is a zero-length byte string and never an encoded empty map', () => {

        expect(CoseHeaders.empty.toProtectedBytes()).toHaveLength(0);

        // h'A0' would be the encoding of {}, and it is a different signature
        // input — which is why the parser must not "repair" one into the other.
        expect(CoseHeaders.parseProtected(new Uint8Array()).isEmpty).toBe(true);
        expect(CoseHeaders.parseProtected(unhex('A0')).isEmpty).toBe(true);

    });

    it('is what the application-algorithm form leaves behind', () => {

        const message  = CoseSign1.signWithApplicationAlgorithm(CONTENT, KEY_11);
        const bareKey  = CoseKey.fromCoordinates(CoseCurves.P256, KEY_11.x!, KEY_11.y!);

        expect(message.protectedHeaderBytes).toHaveLength(0);
        expect(message.protectedHeader.algorithm).toBeNull();

        // The verifier has to name the algorithm, because the message does not
        // — either explicitly or by verifying with a key that carries one.
        expect(message.verify(bareKey, { expectedAlgorithm: CoseAlgorithms.ES256 }).verified).toBe(true);
        expect(message.verify(bareKey.withAlgorithm(CoseAlgorithms.ES256)).verified).toBe(true);
        expect(message.verify(bareKey).verified).toBe(false);

    });

});
