/*
 * Copyright (c) 2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr COSE <https://github.com/Vanaheimr/COSE.TS>
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * ECDH-ES against the examples of the COSE working group.
 *
 * Every published example is checked at every step it publishes, because a
 * final message that comes out right by way of a wrong intermediate is a
 * coincidence that the next example would not repeat: the agreed secret, the
 * encoded COSE_KDF_Context, the derived key, and then the message itself,
 * byte for byte. Each message is also read back — the examples' own bytes,
 * not this implementation's — and opened with the recipient's private key.
 *
 * The examples cover P-256, P-521 and X25519; direct agreement with HKDF-256
 * and HKDF-512; key wrap with A128KW, A192KW and A256KW; and each of them
 * under AES-GCM and HMAC, since a recipient structure delivers a MAC key the
 * same way it delivers an encryption key.
 */

import { describe, expect, it }  from 'vitest';

import { cbor, CoseAlgorithms, CoseCertificateHash, CoseCurves, CoseEncrypt,
         CoseError, CoseHeaders, CoseKey, CoseMac, CoseRecipient, curveByName,
         ecdhSharedSecret, HeaderLabel, isEcdhCurve, kdfContext, label,
         NO_BYTES, X509Certificate }
                                 from '../src/index.ts';
import type { CoseAlgorithm, CoseCurve } from '../src/index.ts';
import certificates              from './certificate-corpus.json' with { type: 'json' };
import corpus                    from './ecdh-vectors.json' with { type: 'json' };
import { hex, unhex }            from './vectors.ts';


interface Vector {
    readonly name:       string;
    readonly message:    'COSE_Encrypt' | 'COSE_Mac';
    readonly content:    string;
    readonly recipient:  string;
    readonly curve:      string;
    readonly kid:        string;
    readonly x:          string;
    readonly y:          string | null;
    readonly d:          string;
    readonly ephemeral:  string;
    readonly iv:         string | null;
    readonly cek:        string;
    readonly context:    string;
    readonly secret:     string;
    readonly kek:        string | null;
    readonly plaintext:  string;
    readonly cbor:       string;
}

const VECTORS = corpus.vectors as readonly Vector[];


/** The examples' algorithm names, which are the JOSE-style ones of their generator. */
const CONTENT: Readonly<Record<string, CoseAlgorithm>> = {
    'A128GCM': CoseAlgorithms.A128GCM,
    'A256GCM': CoseAlgorithms.A256GCM,
    'HS512':   CoseAlgorithms.HMAC512_512,
};

const RECIPIENT: Readonly<Record<string, CoseAlgorithm>> = {
    'ECDH-ES':        CoseAlgorithms.ECDH_ES_HKDF_256,
    'ECDH-ES-512':    CoseAlgorithms.ECDH_ES_HKDF_512,
    'ECDH-ES-A128KW': CoseAlgorithms.ECDH_ES_A128KW,
    'ECDH-ES-A192KW': CoseAlgorithms.ECDH_ES_A192KW,
    'ECDH-ES-A256KW': CoseAlgorithms.ECDH_ES_A256KW,
};


const lookup = <T>(table: Readonly<Record<string, T>>, name: string): T => {
    const value = table[name];
    if (value === undefined)
        throw new Error(`Unknown name '${name}' in the ECDH corpus!`);
    return value;
};

const curveOf = (name: string): CoseCurve => {
    const curve = curveByName(name);
    if (curve === null)
        throw new Error(`Unknown curve '${name}' in the ECDH corpus!`);
    return curve;
};

/** A private key on the vector's curve, EC2 or OKP as the curve decides. */
const privateKey = (curve: CoseCurve, d: string, keyIdentifier?: string): CoseKey =>
    CoseKey.fromPrivateScalar(curve, unhex(d),
                              keyIdentifier === undefined ? {} : { keyIdentifier: unhex(keyIdentifier) });


describe('the ECDH-ES examples of the COSE working group', () => {

    it('cover what they are meant to cover', () => {

        expect(VECTORS).toHaveLength(31);
        expect(new Set(VECTORS.map(each => each.curve))).toStrictEqual(new Set(['P-256', 'P-521', 'X25519']));
        expect(new Set(VECTORS.map(each => each.recipient)).size).toBe(5);
        expect(VECTORS.filter(each => each.message === 'COSE_Mac').length).toBeGreaterThan(0);

    });

    for (const vector of VECTORS) {

        describe(vector.name, () => {

            const curve      = curveOf(vector.curve);
            const content    = lookup(CONTENT, vector.content);
            const algorithm  = lookup(RECIPIENT, vector.recipient);
            const recipient  = privateKey(curve, vector.d, vector.kid);
            const ephemeral  = privateKey(curve, vector.ephemeral);
            const plaintext  = unhex(vector.plaintext);

            it('has the recipient key it says it has', () => {

                expect(hex(recipient.x!)).toBe(vector.x);

                if (vector.y !== null)
                    expect(hex(recipient.y!)).toBe(vector.y);

            });

            it('agrees the published secret, from either side', () => {

                expect(hex(ecdhSharedSecret(curve, ephemeral.privateKeyBytes(), recipient.publicKeyBytes())))
                    .toBe(vector.secret);

                expect(hex(ecdhSharedSecret(curve, recipient.privateKeyBytes(), ephemeral.publicKeyBytes())))
                    .toBe(vector.secret);

            });

            it('encodes the published COSE_KDF_Context', () => {

                // The two fields people get wrong, both pinned here by the
                // examples: what the key is FOR, and its length in bits.
                const forWhat = algorithm.family === 'ecdh-direct'
                                    ? content.id
                                    : lookup(RECIPIENT, vector.recipient).keySize === 16 ? CoseAlgorithms.A128KW.id
                                    : lookup(RECIPIENT, vector.recipient).keySize === 24 ? CoseAlgorithms.A192KW.id
                                    :                                                    CoseAlgorithms.A256KW.id;

                const keyLength = algorithm.family === 'ecdh-direct'
                                      ? unhex(vector.cek).length
                                      : algorithm.keySize!;

                expect(hex(kdfContext({
                    algorithmId:     forWhat,
                    keyLength,
                    protectedBytes:  cbor.encode(cbor.map([[label(HeaderLabel.algorithm), cbor.int(algorithm.id)]])),
                }))).toBe(vector.context);

            });

            it('writes the published message, byte for byte', () => {

                const publicKey = recipient.publicKey();
                let   contentKey: CoseKey;
                let   recipientStructure: CoseRecipient;

                if (algorithm.family === 'ecdh-direct') {

                    const agreed = CoseRecipient.ecdhDirect(publicKey, ephemeral, content, { algorithm });

                    expect(hex(agreed.contentKey.privateKeyBytes())).toBe(vector.cek);

                    contentKey         = agreed.contentKey;
                    recipientStructure = agreed.recipient;

                }
                else {

                    contentKey         = CoseKey.fromSymmetricKey(unhex(vector.cek), { algorithm: content });
                    recipientStructure = CoseRecipient.ecdhKeyWrap(unhex(vector.cek), publicKey, ephemeral, algorithm);

                }

                const bytes = vector.message === 'COSE_Encrypt'
                                  ? CoseEncrypt.encrypt(plaintext, contentKey, [recipientStructure],
                                                        { iv: unhex(vector.iv!) }).toBytes()
                                  : CoseMac.create(plaintext, contentKey, [recipientStructure]).toBytes();

                expect(hex(bytes)).toBe(vector.cbor);

            });

            it('opens the published message with the recipient\'s private key', () => {

                if (vector.message === 'COSE_Encrypt') {

                    const result = CoseEncrypt.parse(unhex(vector.cbor)).decrypt(recipient);

                    expect(result.decrypted).toBe(true);
                    expect(result.decrypted && hex(result.plaintext)).toBe(vector.plaintext);

                }
                else
                    expect(CoseMac.parse(unhex(vector.cbor)).verify(recipient).verified).toBe(true);

            });

            it('opens nothing with the public key alone, or with somebody else\'s', () => {

                const stranger = privateKey(curve, vector.ephemeral);

                if (vector.message === 'COSE_Encrypt') {
                    const message = CoseEncrypt.parse(unhex(vector.cbor));
                    expect(message.decrypt(recipient.publicKey()).decrypted).toBe(false);
                    expect(message.decrypt(stranger).decrypted).toBe(false);
                }
                else {
                    const message = CoseMac.parse(unhex(vector.cbor));
                    expect(message.verify(recipient.publicKey()).verified).toBe(false);
                    expect(message.verify(stranger).verified).toBe(false);
                }

            });

        });

    }

});


describe('ECDH-ES beyond the examples', () => {

    const plaintext = new TextEncoder().encode('a reading worth keeping private');
    const iv        = unhex('C9CF4DF2FE6C632BF7886413');

    // RFC 7748 Section 6.1's Alice and Bob: published X25519 key pairs.
    const alice = CoseKey.fromOkpPrivateKey(CoseCurves.X25519,
                      unhex('77076D0A7318A57D3C16C17251B26645DF4C2F87EBC0992AB177FBA51DB92C2A'));
    const bob   = CoseKey.fromOkpPrivateKey(CoseCurves.X25519,
                      unhex('5DAB087E624A8A4B79E17F8B83800EE66F3BB1292618B6FD1C2F8B27FF88E0EB'));

    it('derives RFC 7748\'s X25519 public keys and shared secret', () => {

        expect(hex(alice.x!)).toBe('8520F0098930A754748B7DDCB43EF75A0DBF3A0D26381AF4EBA4A98EAA9B4E6A');
        expect(hex(bob.x!)).toBe('DE9EDB7D7B7DC1B4D35B61C2ECE435373F8343C85B78674DADFC7E146F882B4F');
        expect(hex(ecdhSharedSecret(CoseCurves.X25519, alice.privateKeyBytes(), bob.publicKeyBytes())))
            .toBe('4A5D9D5BA4CE2DE1728E3BF480350F25E07E21C947D19E3376F09B3C1E161742');

    });

    it('works on X448 too, from either side', () => {

        const sender    = CoseKey.fromOkpPrivateKey(CoseCurves.X448, new Uint8Array(56).fill(0x11));
        const receiver  = CoseKey.fromOkpPrivateKey(CoseCurves.X448, new Uint8Array(56).fill(0x22));
        const { recipient, contentKey } = CoseRecipient.ecdhDirect(receiver.publicKey(), sender, CoseAlgorithms.A256GCM);
        const message   = CoseEncrypt.encrypt(plaintext, contentKey, [recipient], { iv });

        const opened = CoseEncrypt.parse(message.toBytes()).decrypt(receiver);

        expect(opened.decrypted && new TextDecoder().decode(opened.plaintext)).toBe('a reading worth keeping private');

    });

    it('works on the brainpool curves, which the examples do not cover', () => {

        const curve     = CoseCurves.brainpoolP256r1;
        const sender    = CoseKey.fromPrivateScalar(curve, new Uint8Array(32).fill(0x11));
        const receiver  = CoseKey.fromPrivateScalar(curve, new Uint8Array(32).fill(0x22));
        const recipient = CoseRecipient.ecdhKeyWrap(new Uint8Array(16).fill(7), receiver.publicKey(), sender,
                                                    CoseAlgorithms.ECDH_ES_A128KW);
        const message   = CoseEncrypt.encrypt(plaintext,
                                              CoseKey.fromSymmetricKey(new Uint8Array(16).fill(7), { algorithm: CoseAlgorithms.A128GCM }),
                                              [recipient], { iv });

        expect(CoseEncrypt.parse(message.toBytes()).decrypt(receiver).decrypted).toBe(true);

    });

    it('carries salt and party information, and derives a different key with them', () => {

        const options = {
            salt:    new TextEncoder().encode('salt'),
            partyU:  { identity: new TextEncoder().encode('lighting-client'), nonce: 7 },
            partyV:  { identity: new TextEncoder().encode('lighting-server'), other: unhex('0102') },
        };

        const plain   = CoseRecipient.ecdhDirect(bob.publicKey(), alice, CoseAlgorithms.A128GCM);
        const bound   = CoseRecipient.ecdhDirect(bob.publicKey(), alice, CoseAlgorithms.A128GCM, options);

        expect(hex(bound.contentKey.privateKeyBytes())).not.toBe(hex(plain.contentKey.privateKeyBytes()));

        for (const parameter of [HeaderLabel.salt, HeaderLabel.partyUIdentity, HeaderLabel.partyUNonce,
                                 HeaderLabel.partyVIdentity, HeaderLabel.partyVOther])
            expect(bound.recipient.unprotectedHeader.has(label(parameter)), String(parameter)).toBe(true);

        const message = CoseEncrypt.encrypt(plaintext, bound.contentKey, [bound.recipient], { iv });

        expect(CoseEncrypt.parse(message.toBytes()).decrypt(bob).decrypted).toBe(true);

    });

    it('sends the ephemeral key without its private half or its identifier', () => {

        const marked = CoseKey.fromOkpPrivateKey(CoseCurves.X25519, alice.privateKeyBytes(),
                                                 { keyIdentifier: new TextEncoder().encode('ephemeral') });
        const { recipient } = CoseRecipient.ecdhDirect(bob.publicKey(), marked, CoseAlgorithms.A128GCM);
        const sent = CoseKey.parse(recipient.unprotectedHeader.get(label(HeaderLabel.ephemeralKey))!);

        expect(sent.isPrivate).toBe(false);
        expect(sent.keyIdentifier).toBeNull();
        expect(hex(sent.x!)).toBe(hex(alice.x!));

    });

    it('lets several key-wrap recipients share a message, each with a key of their own', () => {

        const cek      = new Uint8Array(16).fill(9);
        const carol    = CoseKey.fromPrivateScalar(CoseCurves.P256, new Uint8Array(32).fill(0x33));
        const ephemeralP256 = CoseKey.fromPrivateScalar(CoseCurves.P256, new Uint8Array(32).fill(0x44));
        const message  = CoseEncrypt.encrypt(plaintext,
                                             CoseKey.fromSymmetricKey(cek, { algorithm: CoseAlgorithms.A128GCM }),
                                             [CoseRecipient.ecdhKeyWrap(cek, bob.publicKey(), alice, CoseAlgorithms.ECDH_ES_A128KW),
                                              CoseRecipient.ecdhKeyWrap(cek, carol.publicKey(), ephemeralP256, CoseAlgorithms.ECDH_ES_A256KW)],
                                             { iv });

        const parsed = CoseEncrypt.parse(message.toBytes());

        expect(parsed.decrypt(bob).decrypted).toBe(true);
        expect(parsed.decrypt(carol).decrypted).toBe(true);
        expect(parsed.decrypt(alice).decrypted).toBe(false);

    });

    it('refuses a direct agreement that would have to share its key', () => {

        const { recipient, contentKey } = CoseRecipient.ecdhDirect(bob.publicKey(), alice, CoseAlgorithms.A128GCM);
        const other = CoseRecipient.direct(contentKey);

        expect(() => CoseEncrypt.encrypt(plaintext, contentKey, [recipient, other], { iv }))
            .toThrow(/only that one recipient/u);

        expect(() => CoseMac.create(plaintext,
                                    CoseRecipient.ecdhDirect(bob.publicKey(), alice, CoseAlgorithms.HMAC256_256).contentKey,
                                    [recipient, other]))
            .toThrow(/only that one recipient/u);

    });

    it('refuses keys that cannot agree, and algorithms of the wrong kind', () => {

        const p256 = CoseKey.fromPrivateScalar(CoseCurves.P256, new Uint8Array(32).fill(0x55));
        const ed   = CoseKey.fromOkpPrivateKey(CoseCurves.Ed25519, new Uint8Array(32).fill(0x66));

        expect(() => CoseRecipient.ecdhDirect(bob.publicKey(), p256, CoseAlgorithms.A128GCM)).toThrow(CoseError);
        expect(() => CoseRecipient.ecdhDirect(ed.publicKey(), ed, CoseAlgorithms.A128GCM)).toThrow(CoseError);
        expect(() => CoseRecipient.ecdhDirect(bob.publicKey(), bob.publicKey(), CoseAlgorithms.A128GCM)).toThrow(CoseError);
        expect(() => CoseRecipient.ecdhDirect(bob.publicKey(), alice, CoseAlgorithms.ES256)).toThrow(CoseError);
        expect(() => CoseRecipient.ecdhDirect(bob.publicKey(), alice, CoseAlgorithms.A128GCM,
                                              { algorithm: CoseAlgorithms.ECDH_ES_A128KW })).toThrow(CoseError);
        expect(() => CoseRecipient.ecdhKeyWrap(new Uint8Array(16), bob.publicKey(), alice,
                                               CoseAlgorithms.ECDH_ES_HKDF_256)).toThrow(CoseError);

        expect(isEcdhCurve(CoseCurves.Ed25519)).toBe(false);
        expect(isEcdhCurve(CoseCurves.X25519)).toBe(true);
        expect(isEcdhCurve(CoseCurves.P256)).toBe(true);

    });

    it('refuses an X25519 public key of small order, whose secret everybody knows', () => {

        // u = 0 is the identity: every product with it is all zeroes.
        const lowOrder = CoseKey.fromOkpPublicKey(CoseCurves.X25519, new Uint8Array(32));

        expect(() => CoseRecipient.ecdhDirect(lowOrder, alice, CoseAlgorithms.A128GCM)).toThrow(CoseError);

    });

    it('opens nothing whose recipient structure was tampered with', () => {

        const { recipient, contentKey } = CoseRecipient.ecdhDirect(bob.publicKey(), alice, CoseAlgorithms.A128GCM);
        const message = CoseEncrypt.encrypt(plaintext, contentKey, [recipient], { iv });

        // The algorithm re-read as the 512-bit variant: the protected bucket is
        // in the derivation, so the key that comes out is a different one.
        const reread = new CoseRecipient(cbor.encode(cbor.map([[label(HeaderLabel.algorithm),
                                                                cbor.int(CoseAlgorithms.ECDH_ES_HKDF_512.id)]])),
                                         recipient.unprotectedHeader, recipient.ciphertext);

        // And the ephemeral key removed altogether.
        const bare = new CoseRecipient(recipient.protectedHeaderBytes, null, recipient.ciphertext);

        for (const tampered of [reread, bare]) {
            const forged = new CoseEncrypt(message.protectedHeaderBytes, message.unprotectedHeader,
                                           message.ciphertext, [tampered]);
            expect(forged.decrypt(bob).decrypted).toBe(false);
        }

        // Asked without the content algorithm, a direct recipient derives nothing.
        expect(recipient.contentKey(bob)).toBeNull();

    });

});


describe('an ECDH-ES recipient named by its certificate (x5t)', () => {

    const plaintext = new TextEncoder().encode('a command for this station only');
    const iv        = unhex('C9CF4DF2FE6C632BF7886413');

    // A station's key-agreement key and its certificate from the corpus,
    // shaped as EVQI Transport section 6.8 has them: P-256, keyUsage
    // keyAgreement and nothing else. "another" is the same station's renewed
    // certificate — the case x5t exists for, a recipient holding more than
    // one key at a time. Whether a certificate certifies the key it is used
    // with is for the caller to establish, not for x5t to say.
    type KeyAgreementName = 'stationKeyAgreement' | 'stationKeyAgreementRenewed';

    const corpusCertificate = (name: KeyAgreementName): X509Certificate =>
        X509Certificate.parse(unhex(certificates.certificates[name]));

    const sender    = CoseKey.fromPrivateScalar(CoseCurves.P256, new Uint8Array(32).fill(0x11));
    const receiver  = CoseKey.fromPrivateScalar(CoseCurves.P256,
                          unhex(certificates.privateKeys.stationKeyAgreement.keyD));

    const mine    = corpusCertificate('stationKeyAgreement');
    const another = corpusCertificate('stationKeyAgreementRenewed');

    it('uses a certificate that certifies the receiving key', () => {
        expect(hex(mine.publicKey.publicKeyBytes())).toBe(hex(receiver.publicKeyBytes()));
    });

    const encryptedFor = (certificate: X509Certificate | null): CoseEncrypt => {

        const { recipient, contentKey } = CoseRecipient.ecdhDirect(receiver.publicKey(), sender, CoseAlgorithms.A128GCM,
                                              { certificateThumbprint: certificate === null ? null : CoseCertificateHash.from(certificate),
                                                keyIdentifier: null });

        return CoseEncrypt.parse(CoseEncrypt.encrypt(plaintext, contentKey, [recipient], { iv }).toBytes());

    };

    it('writes the thumbprint as x5t, after the ephemeral key, and reads it back', () => {

        const thumbprint = CoseCertificateHash.from(mine);
        const message    = encryptedFor(mine);
        const recipient  = message.recipients[0]!;

        expect(recipient.certificateThumbprint?.algorithm).toBe(CoseAlgorithms.SHA256);
        expect(hex(recipient.certificateThumbprint!.value)).toBe(hex(thumbprint.value));
        expect(recipient.keyIdentifier).toBeNull();

        // Label 34, then [-16, h'…'] — SHA-256 by its RFC 9054 identifier.
        expect(hex(message.toBytes())).toContain(`1822822F5820${hex(thumbprint.value)}`);

    });

    it('opens for the certificate it names', () => {

        const opened = encryptedFor(mine).decrypt(receiver, { recipientCertificate: mine });

        expect(opened.decrypted && new TextDecoder().decode(opened.plaintext)).toBe('a command for this station only');

    });

    it('passes over a recipient that names another certificate, without trying the key', () => {

        const opened = encryptedFor(another).decrypt(receiver, { recipientCertificate: mine });

        expect(opened.decrypted).toBe(false);
        expect(!opened.decrypted && opened.reason).toMatch(/None of the recipients/u);

    });

    it('changes nothing for a caller who does not say which certificate the key has', () => {
        expect(encryptedFor(another).decrypt(receiver).decrypted).toBe(true);
    });

    it('still tries a recipient that names no certificate at all', () => {
        expect(encryptedFor(null).decrypt(receiver, { recipientCertificate: mine }).decrypted).toBe(true);
    });

    it('reads an x5t that is not a COSE_CertHash as naming somebody else', () => {

        const { recipient } = CoseRecipient.ecdhDirect(receiver.publicKey(), sender, CoseAlgorithms.A128GCM);
        const broken        = new CoseRecipient(recipient.protectedHeaderBytes,
                                                new CoseHeaders([...recipient.unprotectedHeader.parameters,
                                                                 [label(HeaderLabel.x5T), cbor.bytes(mine.thumbprint('sha256'))]]),
                                                NO_BYTES);

        expect(() => broken.certificateThumbprint).toThrow(CoseError);
        expect(broken.isFor(mine)).toBe(false);

    });

    it('selects the recipient in a COSE_Mac the same way', () => {

        const { recipient, contentKey } = CoseRecipient.ecdhDirect(receiver.publicKey(), sender, CoseAlgorithms.HMAC256_256,
                                              { certificateThumbprint: CoseCertificateHash.from(mine) });
        const message = CoseMac.parse(CoseMac.create(plaintext, contentKey, [recipient]).toBytes());

        expect(message.verify(receiver, { recipientCertificate: mine }).verified).toBe(true);
        expect(message.verify(receiver, { recipientCertificate: another }).verified).toBe(false);

    });

});
