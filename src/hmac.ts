/*
 * Copyright (c) 2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr COSE <https://github.com/Vanaheimr/COSE.TS>
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * HMAC [RFC 2104], as COSE parameterizes it [RFC 9053, Section 3.1].
 *
 * A message authentication code is not a small signature, and the difference
 * is worth stating where the code lives. A MAC is **symmetric**: whoever can
 * verify one can produce one. It therefore answers "did this come from someone
 * holding the key", which is a question only a key holder can ask, and it
 * never answers "did this come from *that* party" to anybody else. A signature
 * does. That is why a metrological record is signed and not MACed — the
 * customer, the operator and the regulator all have to be able to check it,
 * and none of them may be able to forge it.
 *
 * What a MAC buys in return is size and speed: eight bytes and one pass of a
 * hash function, against sixty-four bytes and a curve multiplication for the
 * smallest signature here.
 *
 * Two things in this file exist only because of the symmetry, and both would
 * be pointless in the signature code beside it:
 *
 *   - **The comparison is constant time.** A byte-by-byte compare that returns
 *     early tells an attacker how many leading bytes of a guessed tag were
 *     right, which turns forging a 32-byte tag from 2^256 work into 32 × 256.
 *     Signature verification has no equivalent exposure, because everything it
 *     compares is public.
 *   - **Truncation is applied to the output**, never to the key: RFC 9053 keeps
 *     "the leftmost tag-length bits" of the full HMAC.
 */

import { createHmac, timingSafeEqual }  from 'node:crypto';

import { CoseError }                    from './errors.ts';
import type { DigestAlgorithm }         from './ecdsa.ts';


/**
 * The full HMAC of a message, before any truncation.
 *
 * The key is passed through as it is. RFC 9053 says the key SHOULD be as long
 * as the hash output, which is a recommendation about key management rather
 * than a rule about the primitive — RFC 2104 accepts any length, and the
 * published test vectors of RFC 4231 include a four-byte key. Refusing short
 * keys here would make those vectors unreproducible while protecting nobody
 * who was not already choosing their own key length.
 */
export const hmac = (hash: DigestAlgorithm, key: Uint8Array, message: Uint8Array): Uint8Array =>
    new Uint8Array(createHmac(hash, key).update(message).digest());


/**
 * The authentication tag of a message: the HMAC, truncated to the width the
 * algorithm names.
 *
 * `tagSize` is in bytes and is the algorithm's, never the caller's — the
 * whole point of `HMAC 256/64` being a registered identifier rather than a
 * parameter is that both parties know the width from the message.
 */
export function macTag(hash:     DigestAlgorithm,
                       tagSize:  number,
                       key:      Uint8Array,
                       message:  Uint8Array): Uint8Array {

    const full = hmac(hash, key, message);

    if (tagSize > full.length)
        throw new CoseError(`An HMAC over ${hash} is ${String(full.length)} bytes long and can not be truncated to ${String(tagSize)}!`);

    return tagSize === full.length ? full : full.subarray(0, tagSize);

}


/**
 * Whether two authentication tags are the same, without saying *where* they
 * first differ.
 *
 * The length check in front is not a leak: the width of a tag follows from the
 * algorithm, which travels in the message and is known to everybody. What must
 * not leak is the position of the first differing byte, and that is what the
 * constant-time comparison protects.
 */
export function tagsEqual(left: Uint8Array, right: Uint8Array): boolean {

    if (left.length !== right.length)
        return false;

    return timingSafeEqual(left, right);

}
