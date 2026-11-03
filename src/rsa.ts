/*
 * Copyright (c) 2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr COSE <https://github.com/Vanaheimr/COSE.TS>
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * RSA signatures: RSASSA-PSS [RFC 8230] and RSASSA-PKCS1-v1_5 [RFC 8812].
 *
 * Both schemes drive the same primitive — one modular exponentiation with the
 * private exponent — and differ in what they hand it. RSASSA-PKCS1-v1_5 wraps
 * the digest in a DER `DigestInfo`, pads it with `0xFF` octets and is
 * deterministic. RSASSA-PSS hashes the digest together with a salt and masks
 * the result, which makes it randomized: the salt travels inside the signature
 * and is recovered by whoever verifies, never compared with anything
 * [RFC 8017, Section 9.1.2].
 *
 * **The salt is the caller's, and it defaults to zeroes.** This package draws
 * no randomness anywhere: the AES-GCM nonce is the caller's, so is the ECDH
 * ephemeral key, ECDSA is RFC 6979 and ML-DSA is the deterministic variant of
 * FIPS 204. A fixed PSS salt is not the hazard a repeated ECDSA nonce is — it
 * reveals nothing about the key, two signatures over one message merely become
 * equal, and no verifier can tell the difference, because the salt is read out
 * of the signature rather than checked against anything. Styx does the same
 * when it is asked for deterministic output, which is what lets two
 * implementations be compared byte for byte at all.
 *
 * **What this is not is constant time**, and a pure-JavaScript RSA cannot be:
 * `BigInt` offers no constant-time multiplication, and the control flow of
 * any square-and-multiply follows the exponent, which here is the secret. For
 * verifying that is no concern — the public exponent is public — and for
 * signing it is the concern every JavaScript RSA has. Where an attacker can
 * measure the signer, the signing key does not belong in this process.
 *
 * Signing goes through the Chinese remainder theorem, about four times faster
 * than one exponentiation with `d`, and then verifies its own output before
 * returning it. That second step is not ceremony: a CRT exponentiation that
 * goes wrong in one of its two halves — a flipped bit, a faulty machine —
 * hands whoever receives the signature the factorization of the modulus
 * (Boneh, DeMillo and Lipton, 1997). One exponentiation with a tiny public
 * exponent turns that into an error.
 */

import { mod, pow }                      from '@noble/curves/abstract/modular.js';
import { bitLen, bytesToNumberBE,
         concatBytes, equalBytes,
         hexToBytes, numberToBytesBE }   from '@noble/curves/utils.js';
import { digest, HASHES }                from './ecdsa.ts';
import type { DigestAlgorithm }          from './ecdsa.ts';
import { CoseError }                     from './errors.ts';


/** The smallest modulus these algorithms accept, in bits [RFC 8230, Section 6.1]. */
export const RSA_MINIMUM_MODULUS_BITS = 2048;


/** Which of the two schemes an algorithm names. */
export type RsaScheme = 'pss' | 'pkcs1';


/**
 * An RSA public key: the modulus and the public exponent, labels −1 and −2 of
 * RFC 8230 Section 4.
 *
 * Every parameter is an unsigned big-endian integer in the fewest octets that
 * represent it, which is how it travels in a COSE key — unlike the fixed-width
 * coordinates of an elliptic curve key, where leading zeroes are part of the
 * value and must be kept.
 */
export interface RsaPublicKey {

    /** The modulus n (label −1). */
    readonly n:     Uint8Array;

    /** The public exponent e (label −2). */
    readonly e:     Uint8Array;

}


/**
 * An RSA private key with two primes, which is every private key RFC 8230
 * Section 4 allows into a COSE key without the multi-prime `other` array: all
 * of n, e, d, p, q, dP, dQ and qInv are present, so nothing here is optional.
 */
export interface RsaPrivateKey extends RsaPublicKey {

    /** The private exponent d (label −3). */
    readonly d:     Uint8Array;

    /** The first prime factor p of n (label −4). */
    readonly p:     Uint8Array;

    /** The second prime factor q of n (label −5). */
    readonly q:     Uint8Array;

    /** dP, which is d mod (p − 1) (label −6). */
    readonly dP:    Uint8Array;

    /** dQ, which is d mod (q − 1) (label −7). */
    readonly dQ:    Uint8Array;

    /** The CRT coefficient qInv, which is q^(−1) mod p (label −8). */
    readonly qInv:  Uint8Array;

}


const ZERO = BigInt(0);
const ONE  = BigInt(1);


/**
 * The DER `DigestInfo` prefix each hash contributes to EMSA-PKCS1-v1_5, taken
 * from the note in RFC 8017 Section 9.2: an `AlgorithmIdentifier` with its
 * absent-parameter `NULL`, in front of the digest.
 *
 * Why RSASSA-PKCS1-v1_5 can be verified by re-encoding at all is this prefix:
 * the encoding is a function of the digest and nothing else, so a verifier
 * computes the expected octets and compares, rather than parsing attacker-held
 * DER. The parsing route is where Bleichenbacher's 2006 forgeries lived.
 */
const DIGEST_INFO: Record<DigestAlgorithm, Uint8Array> = {
    sha256:  hexToBytes('3031300d060960864801650304020105000420'),
    sha384:  hexToBytes('3041300d060960864801650304020205000430'),
    sha512:  hexToBytes('3051300d060960864801650304020305000440'),
};


/** The width of a hash in bytes, which is also the PSS salt length [RFC 8230, Section 2]. */
function hashSize(hash: DigestAlgorithm): number {
    return HASHES[hash].outputLen;
}


/** The modulus as an integer, with the width RFC 8230 Section 6.1 insists on. */
function modulusOf(key: RsaPublicKey): { n: bigint; bits: number; octets: number } {

    const n    = bytesToNumberBE(key.n);
    const bits = bitLen(n);

    if (bits < RSA_MINIMUM_MODULUS_BITS)
        throw new CoseError(`An RSA key must have a modulus of at least ${String(RSA_MINIMUM_MODULUS_BITS)} bits [RFC 8230, Section 6.1], but this one has ${String(bits)} bits!`);

    return { n, bits, octets: Math.ceil(bits / 8) };

}


/** I2OSP [RFC 8017, Section 4.1], and null where the value does not fit. */
function octetsOf(value: bigint, length: number): Uint8Array | null {

    try {
        return numberToBytesBE(value, length);
    }
    catch {
        return null;
    }

}


function xorInto(target: Uint8Array, mask: Uint8Array): Uint8Array {

    for (let index = 0; index < target.length; index++)
        target[index] = target[index]! ^ mask[index]!;

    return target;

}


/**
 * MGF1, the mask generation function of RFC 8017 Appendix B.2.1: the hash of
 * the seed and a four-octet counter, concatenated until long enough.
 */
function mgf1(hash: DigestAlgorithm, seed: Uint8Array, length: number): Uint8Array {

    const blocks: Uint8Array[] = [];

    for (let counter = 0, produced = 0; produced < length; counter++) {

        const block = digest(hash, concatBytes(seed, numberToBytesBE(BigInt(counter), 4)));

        blocks.push(block);
        produced += block.length;

    }

    return concatBytes(...blocks).subarray(0, length);

}


/**
 * EMSA-PKCS1-v1_5-ENCODE [RFC 8017, Section 9.2].
 *
 * `0x00 0x01`, then `0xFF` octets, then `0x00`, then the DER-wrapped digest —
 * the padding that makes the encoded message just under the modulus and
 * unambiguous about where the digest starts.
 */
function pkcs1Encode(hash: DigestAlgorithm, message: Uint8Array, emLen: number): Uint8Array {

    const digestInfo = concatBytes(DIGEST_INFO[hash], digest(hash, message));

    // "If emLen < tLen + 11, output 'intended encoded message length too
    // short'" — a 2048-bit modulus has room for all three hashes, so this is
    // reachable only with a modulus that Section 6.1 already refused.
    if (emLen < digestInfo.length + 11)
        throw new CoseError(`An RSASSA-PKCS1-v1_5 signature with ${hash} needs a modulus of at least ${String((digestInfo.length + 11) * 8)} bits, but this one has room for ${String(emLen * 8)}!`);

    return concatBytes(Uint8Array.of(0x00, 0x01),
                       new Uint8Array(emLen - digestInfo.length - 3).fill(0xff),
                       Uint8Array.of(0x00),
                       digestInfo);

}


/**
 * EMSA-PSS-ENCODE [RFC 8017, Section 9.1.1].
 *
 * `emBits` is one bit short of the modulus, so that the encoded message is
 * certainly smaller than it; the leftmost bits of the masked block are cleared
 * for the same reason.
 */
function pssEncode(hash:     DigestAlgorithm,
                   message:  Uint8Array,
                   salt:     Uint8Array,
                   emBits:   number): Uint8Array {

    const emLen = Math.ceil(emBits / 8);
    const mHash = digest(hash, message);
    const hLen  = mHash.length;

    if (emLen < hLen + salt.length + 2)
        throw new CoseError(`An RSASSA-PSS signature with ${hash} and a ${String(salt.length)}-byte salt needs a modulus of at least ${String((hLen + salt.length + 2) * 8)} bits, but this one has room for ${String(emLen * 8)}!`);

    // M' is eight zero octets, the digest and the salt — the eight octets are
    // what keeps the PSS input distinct from anything else that is hashed.
    const h  = digest(hash, concatBytes(new Uint8Array(8), mHash, salt));
    const db = new Uint8Array(emLen - hLen - 1);

    db[db.length - salt.length - 1] = 0x01;
    db.set(salt, db.length - salt.length);

    const masked = xorInto(db, mgf1(hash, h, db.length));

    masked[0] = masked[0]! & (0xff >> (8 * emLen - emBits));

    return concatBytes(masked, h, Uint8Array.of(0xbc));

}


/**
 * EMSA-PSS-VERIFY [RFC 8017, Section 9.1.2], which recovers the salt from the
 * encoded message rather than being told it: every failure is one verdict,
 * `false`, because a verifier distinguishing them tells an attacker which step
 * of the padding it got past.
 */
function pssVerify(hash:        DigestAlgorithm,
                   message:     Uint8Array,
                   em:          Uint8Array,
                   saltLength:  number,
                   emBits:      number): boolean {

    const emLen = Math.ceil(emBits / 8);
    const mHash = digest(hash, message);
    const hLen  = mHash.length;

    if (em.length !== emLen || emLen < hLen + saltLength + 2)
        return false;

    if (em[emLen - 1] !== 0xbc)
        return false;

    const unused = 8 * emLen - emBits;
    const masked = em.slice(0, emLen - hLen - 1);
    const h      = em.subarray(emLen - hLen - 1, emLen - 1);

    if (unused > 0 && (masked[0]! & ~(0xff >> unused) & 0xff) !== 0)
        return false;

    const db = xorInto(masked, mgf1(hash, h, masked.length));

    db[0] = db[0]! & (0xff >> unused);

    for (let index = 0; index < db.length - saltLength - 1; index++) {
        if (db[index] !== 0x00)
            return false;
    }

    if (db[db.length - saltLength - 1] !== 0x01)
        return false;

    const salt = db.subarray(db.length - saltLength);

    return equalBytes(digest(hash, concatBytes(new Uint8Array(8), mHash, salt)), h);

}


/** RSASP1 through the Chinese remainder theorem [RFC 8017, Section 5.1.2]. */
function exponentiate(key: RsaPrivateKey, m: bigint, n: bigint): bigint {

    const p = bytesToNumberBE(key.p);
    const q = bytesToNumberBE(key.q);

    // One multiplication, and it turns a mistyped parameter into a sentence
    // rather than into the fault-attack error below.
    if (p * q !== n)
        throw new CoseError('The prime factors of this RSA private key do not multiply to its modulus!');

    const m1 = pow(mod(m, p), bytesToNumberBE(key.dP), p);
    const m2 = pow(mod(m, q), bytesToNumberBE(key.dQ), q);
    const h  = mod((m1 - m2) * bytesToNumberBE(key.qInv), p);

    return m2 + q * h;

}


/**
 * Sign a message with RSA.
 *
 * The message is the whole `Sig_structure`, not a digest of it: both schemes
 * hash what they are given, so handing this a digest produces a signature over
 * the digest of a digest, which nobody will accept.
 *
 * `salt` applies to RSASSA-PSS only and must be as long as the hash
 * [RFC 8230, Section 2]. It defaults to zeroes — see the note at the top of
 * this module on why that is a choice rather than an oversight.
 */
export function rsaSign(hash:     DigestAlgorithm,
                        scheme:   RsaScheme,
                        key:      RsaPrivateKey,
                        message:  Uint8Array,
                        salt:     Uint8Array | null = null): Uint8Array {

    const { n, bits, octets } = modulusOf(key);
    const hLen                = hashSize(hash);

    if (salt !== null && salt.length !== hLen)
        throw new CoseError(`The salt of an RSASSA-PSS signature with ${hash} must be ${String(hLen)} bytes long [RFC 8230, Section 2], but a ${String(salt.length)}-byte salt was given!`);

    const em = scheme === 'pkcs1'
                   ? pkcs1Encode(hash, message, octets)
                   : pssEncode(hash, message, salt ?? new Uint8Array(hLen), bits - 1);

    const signature = octetsOf(exponentiate(key, bytesToNumberBE(em), n), octets);

    if (signature === null)
        throw new CoseError('This RSA signature came out wider than its own modulus, which is arithmetically impossible: the key is not a key!');

    // The fault check of the module note. It costs one exponentiation with the
    // public exponent, which is three multiplications for the usual 65537.
    if (!rsaVerify(hash, scheme, key, message, signature))
        throw new CoseError('This RSA signature does not verify under its own public key, so the computation went wrong: returning it would hand the recipient the factors of the modulus!');

    return signature;

}


/**
 * Whether an RSA signature is the right one for this message and this key.
 *
 * A signature of the wrong width, or one that is not smaller than the modulus,
 * is a wrong signature rather than an error: it is exactly what an attacker
 * sends, and this returns `false` for it like for any other forgery.
 */
export function rsaVerify(hash:       DigestAlgorithm,
                          scheme:     RsaScheme,
                          key:        RsaPublicKey,
                          message:    Uint8Array,
                          signature:  Uint8Array): boolean {

    const { n, bits, octets } = modulusOf(key);
    const e                   = bytesToNumberBE(key.e);

    if (e <= ONE || e >= n)
        throw new CoseError('The public exponent of this RSA key is not an exponent: it must be greater than one and smaller than the modulus!');

    if (signature.length !== octets)
        return false;

    const s = bytesToNumberBE(signature);

    if (s <= ZERO || s >= n)
        return false;

    const emLen = scheme === 'pkcs1' ? octets : Math.ceil((bits - 1) / 8);
    const em    = octetsOf(pow(s, e, n), emLen);

    if (em === null)
        return false;

    return scheme === 'pkcs1'
               ? equalBytes(em, pkcs1Encode(hash, message, octets))
               : pssVerify(hash, message, em, hashSize(hash), bits - 1);

}
