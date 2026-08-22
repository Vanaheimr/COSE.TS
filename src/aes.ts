/*
 * Copyright (c) 2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr COSE <https://github.com/Vanaheimr/COSE.TS>
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * The two AES constructions COSE needs: **AES-GCM** for content encryption
 * [RFC 9053, Section 4.1] and **AES key wrap** for delivering a content key to
 * a recipient [RFC 9053, Section 6.2.1, RFC 3394].
 *
 * They do very different jobs and it is worth keeping them apart in one's head.
 * GCM protects a *payload*: it produces ciphertext plus an authentication tag,
 * and it authenticates additional data — the `Enc_structure` — that is never
 * encrypted. Key wrap protects a *key*: a short, high-entropy secret, under
 * another key, with no additional data and no nonce at all.
 *
 * That last point is the one that surprises people. AES key wrap is
 * deterministic: the same key wrapped under the same key-encryption key yields
 * the same 40 bytes every time. It is safe because what it wraps is a
 * uniformly random key rather than a message — RFC 3394 relies on that
 * squarely, and wrapping anything guessable with it is a mistake the API
 * cannot prevent.
 *
 * Both come from `@noble/ciphers` — the same audited family the curves, the
 * hashes and ML-DSA already come from — rather than from `node:crypto` or
 * WebCrypto: the former exists only under Node, the latter only behind an
 * `async` API, and this library runs wherever its CBOR codec runs, which
 * includes browsers.
 */

import { aeskw, gcm }  from '@noble/ciphers/aes.js';

import { CoseError }   from './errors.ts';


/** The nonce width AES-GCM is fixed to in COSE: 96 bits [RFC 9053, Section 4.1]. */
export const GCM_NONCE_SIZE = 12;

/** The authentication tag width AES-GCM is fixed to in COSE: 128 bits. */
export const GCM_TAG_SIZE = 16;

// The library checks key widths itself, but with its own error type and its
// own words. The refusal is this module's contract, so it happens here first.
function checkKeySize(keySize: number, what: string): void {

    if (keySize !== 16 && keySize !== 24 && keySize !== 32)
        throw new CoseError(`${what} needs a key of 16, 24 or 32 bytes, but a ${String(keySize)}-byte key was given!`);

}


/**
 * Encrypt with AES-GCM.
 *
 * The returned byte string is `ciphertext ‖ tag`, which is how COSE carries it
 * — the authentication tag is not a field of its own, it is the last sixteen
 * bytes of the ciphertext. An implementation keeping them apart interoperates
 * with nothing.
 *
 * `additionalData` is the encoded `Enc_structure`: authenticated, never
 * encrypted, and never transported, because the recipient rebuilds it from the
 * message.
 */
export function aesGcmEncrypt(key:             Uint8Array,
                              nonce:           Uint8Array,
                              plaintext:       Uint8Array,
                              additionalData:  Uint8Array): Uint8Array {

    if (nonce.length !== GCM_NONCE_SIZE)
        throw new CoseError(`AES-GCM within COSE uses a ${String(GCM_NONCE_SIZE)}-byte nonce [RFC 9053, Section 4.1], but a ${String(nonce.length)}-byte one was given!`);

    checkKeySize(key.length, 'AES-GCM');

    return gcm(key, nonce, additionalData).encrypt(plaintext);

}


/**
 * Decrypt with AES-GCM, or say why not.
 *
 * A failed decryption is not an exception here for the same reason a failed
 * signature verification is not: it is the expected outcome of processing
 * untrusted data. And an AEAD failure means the *whole* message is
 * unauthenticated, so there is no partial plaintext to hand back — anything
 * decrypted before the tag was checked must be discarded, which is precisely
 * what makes releasing unverified plaintext the classic AEAD mistake.
 */
export function aesGcmDecrypt(key:             Uint8Array,
                              nonce:           Uint8Array,
                              ciphertext:      Uint8Array,
                              additionalData:  Uint8Array): Uint8Array | null {

    if (nonce.length !== GCM_NONCE_SIZE)
        throw new CoseError(`AES-GCM within COSE uses a ${String(GCM_NONCE_SIZE)}-byte nonce [RFC 9053, Section 4.1], but a ${String(nonce.length)}-byte one was given!`);

    if (ciphertext.length < GCM_TAG_SIZE)
        return null;

    checkKeySize(key.length, 'AES-GCM');

    try {
        // The library takes `ciphertext ‖ tag` in one piece, exactly as COSE
        // carries it, and throws exactly when the tag does not check out.
        // There is nothing to report beyond that, and reporting more would be
        // a padding-oracle of one's own making.
        return gcm(key, nonce, additionalData).decrypt(ciphertext);
    }
    catch {
        return null;
    }

}


/**
 * Wrap a content key under a key-encryption key [RFC 3394].
 *
 * The result is eight bytes longer than the key: the integrity check value of
 * RFC 3394 travels with it, which is what makes an unwrap able to fail rather
 * than silently return rubbish.
 */
export function aesKeyWrap(keyEncryptionKey: Uint8Array,
                           contentKey:       Uint8Array): Uint8Array {

    if (contentKey.length % 8 !== 0 || contentKey.length < 16)
        throw new CoseError(`AES key wrap needs a key of at least 16 bytes and a multiple of 8 [RFC 3394], but a ${String(contentKey.length)}-byte key was given!`);

    checkKeySize(keyEncryptionKey.length, 'AES key wrap');

    return aeskw(keyEncryptionKey).encrypt(contentKey);

}


/**
 * Unwrap a content key, or return null when the integrity check fails.
 *
 * Failing is the useful behaviour: RFC 3394's check value is what tells a
 * recipient that this wrapped key was not meant for them, rather than handing
 * them a plausible-looking key that decrypts nothing.
 */
export function aesKeyUnwrap(keyEncryptionKey: Uint8Array,
                             wrapped:          Uint8Array): Uint8Array | null {

    if (wrapped.length % 8 !== 0 || wrapped.length < 24)
        return null;

    try {
        // A key-encryption key of the wrong width throws here too, which for
        // an *unwrap* is the right shape: null, like any other failure to
        // unwrap what was given.
        return aeskw(keyEncryptionKey).decrypt(wrapped);
    }
    catch {
        return null;
    }

}
