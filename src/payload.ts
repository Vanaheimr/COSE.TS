/*
 * Copyright (c) 2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr COSE <https://github.com/Vanaheimr/COSE.TS>
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * The payload of a COSE message is an opaque byte string: RFC 9052 says
 * nothing about what is inside it, and a signature covers those bytes rather
 * than their meaning.
 *
 * This module is about the one thing an application very often does want said
 * about it — that it is CBOR, and that it is written in the deterministic
 * encoding of RFC 8949 Section 4.2.1. The reason is not tidiness but
 * forwarding. A receiver that parses a signed record and serializes it again
 * gets the bytes *its* encoder produces — map entries sorted, heads at their
 * shortest, no indefinite lengths — and not the bytes it was handed. Where the
 * signer wrote a different spelling of the same data, the forwarded signature
 * no longer verifies, and nothing in the message says why: a signature cannot
 * tell being tampered with from being retyped.
 *
 * Signing the deterministic encoding removes the second spelling. There is
 * then one way to write the record down, and everybody who parses and
 * re-encodes it arrives at the very bytes the signature covers.
 *
 * The Styx counterpart is `Illias/COSE/COSEPayload.cs`, and the conformance
 * suite signs the same non-canonical payload with both.
 */

import { bytesEqual, cbor, DETERMINISTIC }  from './cbor.ts';


/**
 * Rewrite a payload in the deterministic encoding of RFC 8949 Section 4.2.1,
 * or return it unchanged where it is not one well-formed CBOR data item and
 * nothing else.
 *
 * Not being CBOR is not an error here: text, JSON, an image or a detached
 * hash have no canonical CBOR form to be rewritten into, and a COSE payload is
 * allowed to be any of them.
 */
export function canonicalizePayload(payload: Uint8Array): Uint8Array {

    try {
        // Decoded leniently on purpose: the non-deterministic spelling is
        // exactly what this function exists to accept and rewrite. Reading it
        // strictly would refuse the only input it can help with.
        return cbor.encode(cbor.decode(payload, { strict: false }), DETERMINISTIC);
    }
    catch {
        return payload;
    }

}


/**
 * Whether a payload survives being decoded and encoded again: whether it is
 * one well-formed CBOR data item whose deterministic encoding is the payload
 * itself.
 *
 * Deliberately the round trip rather than a strict decode. What a forwarding
 * receiver actually does is decode and re-encode, so the question worth
 * answering is whether that changes anything — not whether a list of rules is
 * satisfied.
 *
 * A payload that is not CBOR is not canonical: there is nothing here to have
 * an opinion about.
 */
export function isCanonicalPayload(payload: Uint8Array): boolean {

    try {
        return bytesEqual(cbor.encode(cbor.decode(payload, { strict: false }), DETERMINISTIC),
                          payload);
    }
    catch {
        return false;
    }

}
