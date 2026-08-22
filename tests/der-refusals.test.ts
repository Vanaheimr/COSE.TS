/*
 * Copyright (c) 2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr COSE <https://github.com/Vanaheimr/COSE.TS>
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * The DER readers against what DER forbids, and the certificate structures
 * against what RFC 9360 does.
 *
 * DER exists so that one value has one encoding, and the reader here holds
 * that line deliberately: a non-minimal integer, an overlong OID arc, a BIT
 * STRING with impossible unused bits are all refusals, because two readers
 * that disagree about where a value ends can be made to disagree about what
 * a certificate says. Each test provokes one such refusal with the smallest
 * DER that reaches it.
 */

import { describe, expect, it }  from 'vitest';

import { cbor, CoseAlgorithms, CoseCertificateChain, CoseCertificateHash,
         CoseError, curveByOid, CoseCurves, derBitString, derBoolean,
         derInteger, derObjectIdentifier, DerReader, derString, derTime,
         oidOfCurve, signatureAlgorithmByOid,
         X509Certificate }       from '../src/index.ts';
import corpus                    from './certificate-corpus.json' with { type: 'json' };
import { unhex }                 from './vectors.ts';


const certificates = corpus.certificates as Record<string, string>;

const certificate = (name: string): X509Certificate => {

    const encoded = certificates[name];

    if (encoded === undefined)
        throw new Error(`The certificate corpus holds no '${name}'!`);

    return X509Certificate.parse(unhex(encoded));

};

/** The first DER node of the given hex. */
const node = (hexBytes: string) => new DerReader(unhex(hexBytes), 'test').read();


// -------------------------------------------------------------------- der ---

describe('the DER integer reader', () => {

    it('refuses an empty INTEGER', () => {
        expect(() => derInteger(node('0200'), 'test')).toThrow(CoseError);
    });

    it('refuses a non-minimal INTEGER, which BER allows and DER does not', () => {
        expect(() => derInteger(node('02020001'), 'test')).toThrow(CoseError);
    });

});


describe('the DER bit string reader', () => {

    it('needs at least the unused-bit count', () => {
        expect(() => derBitString(node('0300'), 'test')).toThrow(CoseError);
    });

    it('refuses an empty BIT STRING declaring unused bits it does not have', () => {
        expect(() => derBitString(node('030101'), 'test')).toThrow(CoseError);
    });

});


describe('the DER boolean reader', () => {

    it('reads false as false', () => {
        expect(derBoolean(node('010100'), 'test')).toBe(false);
    });

});


describe('the DER object identifier reader', () => {

    it('refuses an empty OBJECT IDENTIFIER', () => {
        expect(() => derObjectIdentifier(node('0600'), 'test')).toThrow(CoseError);
    });

    it('refuses a non-minimal arc', () => {
        expect(() => derObjectIdentifier(node('06022A80'), 'test')).toThrow(CoseError);
    });

});


describe('the DER string reader', () => {

    it('reads a BMPString as UTF-16BE', () => {
        expect(derString(node('1E0400410042'), 'test')).toBe('AB');
    });

    it('reads a UniversalString as UTF-32BE', () => {
        expect(derString(node('1C0400000041'), 'test')).toBe('A');
    });

    it('reads a TeletexString as the Latin-1 it is in practice', () => {
        expect(derString(node('1403414243'), 'test')).toBe('ABC');
    });

    it('refuses a wide string that is not a whole number of characters', () => {
        expect(() => derString(node('1E03414141'), 'test')).toThrow(CoseError);
    });

    it('refuses a character beyond Unicode', () => {
        expect(() => derString(node('1C0400110000'), 'test')).toThrow(CoseError);
    });

});


describe('the DER time reader', () => {

    it('reads the one GeneralizedTime form DER admits', () => {
        expect(derTime(node('180F' + '32303236303832323030303030305A'), 'test').getTime())
            .toBe(Date.UTC(2026, 7, 22));
    });

    it('refuses anything else', () => {
        expect(() => derTime(node('1806' + '323032365858'), 'test')).toThrow(CoseError);
    });

});


// ------------------------------------------------------------ registries ---

describe('the OID registries', () => {

    it('answer an unknown OID with null rather than a guess', () => {
        expect(signatureAlgorithmByOid('1.2.3.4')).toBeNull();
        expect(curveByOid('1.2.3.4')).toBeNull();
    });

    it('know the OID of a certificate curve, and none for a key-agreement one', () => {
        expect(oidOfCurve(CoseCurves.P256)).toBe('1.2.840.10045.3.1.7');
        expect(oidOfCurve(CoseCurves.X25519)).toBeNull();
    });

});


// ------------------------------------------------------------------ chain ---

describe('a COSE_X509 chain', () => {

    it('must hold at least one certificate', () => {
        expect(() => CoseCertificateChain.fromCbor(cbor.array([]))).toThrow(CoseError);
        expect(() => new CoseCertificateChain([])).toThrow(CoseError);
    });

    it('checks the anchor that issued the last certificate, validity included', () => {

        // The chain is just the meter: not an anchor itself, but issued by
        // one — and at a date where that anchor was not yet valid, the check
        // of the anchor is the one that fails.
        const chain = CoseCertificateChain.fromCbor(cbor.bytes(unhex(certificates.meter!)));

        expect(chain.validate([certificate('metrologyRoot')],
                              { at: new Date('1970-01-01T00:00:00Z') }).verified)
            .toBe(false);

    });

    it('is a bare byte string below two certificates, as the CDDL says', () => {
        expect(() => CoseCertificateChain.fromCbor(cbor.array([cbor.bytes(unhex(certificates.meter!))])))
            .toThrow(CoseError);
    });

    it('says which certificate could not be read', () => {
        expect(() => CoseCertificateChain.fromCbor(cbor.array([cbor.bytes(unhex('DEADBEEF')),
                                                               cbor.bytes(unhex(certificates.meter!))])))
            .toThrow(/position 0/);
    });

    it('spells itself end-entity first', () => {

        const chain = CoseCertificateChain.fromCbor(cbor.array([
            cbor.bytes(unhex(certificates.meter!)),
            cbor.bytes(unhex(certificates.metrologyRoot!)),
        ]));

        expect(String(chain)).toContain(' <- ');
        expect(chain.publicKey()).toBeDefined();

    });

    it('refuses an issuer that may not sign certificates', () => {

        // Two end-entity certificates, neither of which is a CA: whatever
        // else may be wrong with this chain, the CA flag alone forbids it.
        const leaves = Object.values(certificates)
            .filter(each => !X509Certificate.parse(unhex(each)).isCertificateAuthority);

        expect(leaves.length).toBeGreaterThan(1);

        const chain  = CoseCertificateChain.fromCbor(cbor.array([
            cbor.bytes(unhex(leaves[0]!)),
            cbor.bytes(unhex(leaves[1]!)),
        ]));

        const result = chain.validate([certificate('metrologyRoot')],
                                      { at: new Date(corpus.validateAt) });

        expect(result.verified).toBe(false);

    });

});


// ------------------------------------------------------------- thumbprint ---

describe('a COSE_CertHash', () => {

    it('must be a two-element array', () => {
        expect(() => CoseCertificateHash.fromCbor(cbor.int(1))).toThrow(CoseError);
        expect(() => CoseCertificateHash.fromCbor(cbor.array([cbor.int(-16), cbor.bytes(new Uint8Array(32)),
                                                              cbor.int(1)])))
            .toThrow(CoseError);
    });

    it('carries its hash as bytes and its algorithm as a registered hash', () => {
        expect(() => CoseCertificateHash.fromCbor(cbor.array([cbor.int(-16), cbor.int(1)])))
            .toThrow(CoseError);
        expect(() => CoseCertificateHash.fromCbor(cbor.array([cbor.text('SHA-256'),
                                                              cbor.bytes(new Uint8Array(32))])))
            .toThrow(CoseError);
        expect(() => CoseCertificateHash.fromCbor(cbor.array([cbor.int(999999),
                                                              cbor.bytes(new Uint8Array(32))])))
            .toThrow(CoseError);
        expect(() => CoseCertificateHash.fromCbor(cbor.array([cbor.int(1),
                                                              cbor.bytes(new Uint8Array(32))])))
            .toThrow(/not a hash algorithm/);
    });

    it('refuses to be built with a non-hash algorithm', () => {
        expect(() => CoseCertificateHash.from(certificate('meter'), CoseAlgorithms.A128GCM))
            .toThrow(CoseError);
    });

    it('matches nothing when its algorithm is no hash algorithm', () => {

        // The one way such a thumbprint can exist is being constructed
        // directly — fromCbor refuses it — and matches() refuses it again.
        const stated = new CoseCertificateHash(CoseAlgorithms.A128GCM, new Uint8Array(32));

        expect(stated.matches(certificate('meter')).verified).toBe(false);

    });

});
