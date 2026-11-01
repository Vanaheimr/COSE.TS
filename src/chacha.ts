/*
 * Copyright (c) 2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr COSE <https://github.com/Vanaheimr/COSE.TS>
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * ChaCha20/Poly1305 [RFC 8439], the second content encryption algorithm COSE
 * registers beside AES-GCM [RFC 9053, Section 4.3].
 *
 * It earns its place where AES does not run fast: a controller without AES
 * instructions — the kind a charging station is built around — computes
 * ChaCha20 in constant time from additions, rotations and XORs, where a
 * software AES either runs slowly or leaks its key through cache timing.
 * EVQI Transport §7.2 names it beside AES-GCM.
 *
 * Within COSE it is shaped like AES-GCM on purpose, and every lesson of that
 * file applies here unchanged: one 256-bit key, a 96-bit nonce in the `iv`
 * header parameter, the 128-bit tag appended to the ciphertext rather than
 * given a field, and the `Enc_structure` as additional data. A nonce must
 * never repeat under one key — Poly1305's one-time key is derived from it,
 * and two messages under one nonce hand over the means to forge — so the
 * nonce is the caller's, as it is for AES-GCM.
 */

import { chacha20poly1305 }  from '@noble/ciphers/chacha.js';

import { CoseError }         from './errors.ts';


/** The nonce width ChaCha20/Poly1305 is fixed to in COSE: 96 bits [RFC 9053, Section 4.3]. */
export const CHACHA_NONCE_SIZE = 12;

/** The authentication tag width ChaCha20/Poly1305 is fixed to: 128 bits. */
export const CHACHA_TAG_SIZE = 16;

/** The one key width ChaCha20/Poly1305 has: 256 bits. */
export const CHACHA_KEY_SIZE = 32;


function checkKeyAndNonce(key: Uint8Array, nonce: Uint8Array): void {

    if (key.length !== CHACHA_KEY_SIZE)
        throw new CoseError(`ChaCha20/Poly1305 needs a key of ${String(CHACHA_KEY_SIZE)} bytes, but a ${String(key.length)}-byte key was given!`);

    if (nonce.length !== CHACHA_NONCE_SIZE)
        throw new CoseError(`ChaCha20/Poly1305 within COSE uses a ${String(CHACHA_NONCE_SIZE)}-byte nonce [RFC 9053, Section 4.3], but a ${String(nonce.length)}-byte one was given!`);

}


/**
 * Encrypt with ChaCha20/Poly1305, returning `ciphertext ‖ tag`, which is how
 * COSE carries it.
 */
export function chachaPolyEncrypt(key:             Uint8Array,
                                  nonce:           Uint8Array,
                                  plaintext:       Uint8Array,
                                  additionalData:  Uint8Array): Uint8Array {

    checkKeyAndNonce(key, nonce);

    return chacha20poly1305(key, nonce, additionalData).encrypt(plaintext);

}


/**
 * Decrypt with ChaCha20/Poly1305, or return null when the tag does not check
 * out — which is all there is to say about it, for the reasons `aes.ts` gives
 * for AES-GCM.
 */
export function chachaPolyDecrypt(key:             Uint8Array,
                                  nonce:           Uint8Array,
                                  ciphertext:      Uint8Array,
                                  additionalData:  Uint8Array): Uint8Array | null {

    checkKeyAndNonce(key, nonce);

    if (ciphertext.length < CHACHA_TAG_SIZE)
        return null;

    try {
        return chacha20poly1305(key, nonce, additionalData).decrypt(ciphertext);
    }
    catch {
        return null;
    }

}
