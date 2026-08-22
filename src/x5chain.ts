/*
 * Copyright (c) 2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr COSE <https://github.com/Vanaheimr/COSE.TS>
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * The X.509 header parameters of COSE [RFC 9360].
 *
 * Two of them are implemented here: `x5chain` (label 33), which carries a
 * chain of certificates, and `x5t` (label 34), which carries the hash of one.
 * `x5bag` and `x5u` are not — a bag is an unordered heap with no path to
 * follow, and a URI is a fetch, which a signature library has no business
 * performing.
 *
 * The distinction that matters most is between the two implemented ones. A
 * chain is evidence; a thumbprint is a *name*. `x5t` says which certificate
 * the sender meant, so that a recipient who already holds it can find it — it
 * is never a reason to trust one, and a recipient who does not have the
 * certificate learns nothing from its hash.
 */

import { algorithmById, CoseAlgorithms }               from './algorithm.ts';
import type { CoseAlgorithm }                          from './algorithm.ts';
import { cbor }                                        from './cbor.ts';
import type { CborValue }                              from './cbor.ts';
import { CoseError, notVerified, VERIFIED }            from './errors.ts';
import type { Verification }                           from './errors.ts';
import type { CoseKey }                                from './key.ts';
import { KeyUsage, X509Certificate }                   from './x509.ts';


/** How a chain is to be validated. */
export interface ChainValidationOptions {

    /**
     * The instant to check the validity periods at, now by default.
     *
     * Worth passing whenever the answer has to be reproducible — a conformance
     * vector, an archived message, a signature being re-checked years later —
     * because "now" makes the same input give different answers on different
     * days.
     */
    readonly at?:  Date;

}


// ------------------------------------------------------------------ chain ---

/**
 * A `COSE_X509` [RFC 9360, Section 2] — a chain of X.509 certificates.
 *
 * ```
 * COSE_X509 = bstr / [ 2*certs: bstr ]
 * ```
 *
 * A single certificate is a bare byte string; two or more form an array. The
 * order is end-entity first, then whoever signed it, and so on. The trust
 * anchor need not be present — the recipient is expected to have it already,
 * which is what makes it an anchor.
 *
 * A chain proves nothing on its own. It becomes an answer only once
 * {@link validate} has walked it to an anchor the recipient configured, and
 * once the key of its end-entity certificate turns out to be the key that
 * verified the signature — which is
 * {@link CoseSign1.verifyWithCertificateChain}'s half of the job.
 */
export class CoseCertificateChain {

    /** The certificates, end-entity first. */
    public readonly certificates: readonly X509Certificate[];


    public constructor(certificates: readonly X509Certificate[]) {

        if (certificates.length === 0)
            throw new CoseError('A certificate chain must hold at least one certificate!');

        this.certificates = [...certificates];

    }


    /** The certificate holding the key that is expected to have signed. */
    public get endEntity(): X509Certificate {
        return this.certificates[0]!;
    }


    /** The public key of the end-entity certificate. */
    public publicKey(): CoseKey {
        return this.endEntity.publicKey;
    }


    // ------------------------------------------------------------- parsing

    /** Read a `COSE_X509` from its CBOR form. */
    public static fromCbor(value: CborValue): CoseCertificateChain {

        const encoded: Uint8Array[] = [];

        if (value.type === 'bytes')
            encoded.push(value.value);

        else if (value.type === 'array') {

            // RFC 9360 spells the array as "2*certs": a chain of exactly one
            // certificate is a bare byte string, never an array of one.
            if (value.items.length < 2)
                throw new CoseError('A COSE_X509 of fewer than two certificates must be a bare byte string, not an array!');

            for (const item of value.items) {

                if (item.type !== 'bytes')
                    throw new CoseError('Every certificate of a COSE_X509 must be a byte string!');

                encoded.push(item.value);

            }

        }

        else
            throw new CoseError(`A COSE_X509 must be a byte string or an array of them, but was a CBOR ${value.type}!`);

        return new CoseCertificateChain(encoded.map((each, index) => {

            try {
                return X509Certificate.parse(each);
            }
            catch (exception) {
                throw new CoseError(`The certificate at position ${String(index)} of the COSE_X509 could not be read: ${exception instanceof Error ? exception.message : String(exception)}`,
                                    { cause: exception });
            }

        }));

    }


    /** The CBOR form: a bare byte string for one certificate, an array for several. */
    public toCbor(): CborValue {

        return this.certificates.length === 1
                   ? cbor.bytes(this.certificates[0]!.encoded)
                   : cbor.array(this.certificates.map(each => cbor.bytes(each.encoded)));

    }


    // ---------------------------------------------------------- validation

    /**
     * Walk this chain to one of the given trust anchors.
     *
     * Every certificate within its validity period, every certificate signed
     * by the next one, every issuing certificate actually allowed to issue,
     * the last one either an anchor or issued by one, and the end-entity
     * certificate allowed to sign.
     *
     * This answers "does this chain lead somewhere I trust". It does *not*
     * answer whether the key of the end-entity certificate is the key that
     * signed the message — without that binding a perfectly valid chain says
     * nothing about the message it travelled with.
     *
     * Not checked, and the same list as Styx so that the two agree about what
     * a pass means: revocation, name constraints, certificate policies, and
     * path length beyond the CA flag.
     */
    public validate(trustAnchors: readonly X509Certificate[],
                    options:      ChainValidationOptions = {}): Verification {

        const at = options.at ?? new Date();

        if (trustAnchors.length === 0)
            return notVerified('A certificate chain can not be validated without at least one trust anchor!');

        for (const certificate of this.certificates) {

            const valid = certificate.isValidAt(at);

            if (!valid.verified)
                return valid;

        }

        for (let index = 0; index < this.certificates.length - 1; index++) {

            const issuer  = this.certificates[index + 1]!;
            const issued  = this.certificates[index]!.verifySignedBy(issuer);

            if (!issued.verified)
                return issued;

            const allowed = mayIssue(issuer);

            if (!allowed.verified)
                return allowed;

        }

        const last = this.certificates[this.certificates.length - 1]!;

        // Either the chain ends *at* an anchor, or it ends at something an
        // anchor issued — the anchor itself need not travel.
        if (!trustAnchors.some(anchor => anchor.equals(last))) {

            const issuer = trustAnchors.find(anchor => last.issuer.equivalentTo(anchor.subject));

            if (issuer === undefined)
                return notVerified(`The certificate chain ends at '${last.subject.toString()}', which is neither a trust anchor nor issued by one!`);

            for (const check of [issuer.isValidAt(at), mayIssue(issuer), last.verifySignedBy(issuer)]) {

                if (!check.verified)
                    return check;

            }

        }

        if (!this.endEntity.allows(KeyUsage.digitalSignature))
            return notVerified(`The end-entity certificate '${this.endEntity.subject.toString()}' is not allowed to create digital signatures!`);

        return VERIFIED;

    }


    public toString(): string {
        return this.certificates.map(each => each.subject.toString()).join(' <- ');
    }

}


/** Whether a certificate was allowed to issue the one below it. */
function mayIssue(certificate: X509Certificate): Verification {

    if (!certificate.isCertificateAuthority)
        return notVerified(`The certificate '${certificate.subject.toString()}' issued another one although it is not a certification authority!`);

    if (!certificate.allows(KeyUsage.keyCertSign))
        return notVerified(`The certificate '${certificate.subject.toString()}' issued another one although it is not allowed to sign certificates!`);

    return VERIFIED;

}


// ------------------------------------------------------------- thumbprint ---

/**
 * A `COSE_CertHash` [RFC 9360, Section 2] — the hash of a DER encoded
 * certificate, as `x5t` carries it.
 *
 * ```
 * COSE_CertHash = [ hashAlg: (int / tstr), hashValue: bstr ]
 * ```
 */
export class CoseCertificateHash {

    /** The hash algorithm the thumbprint was computed with. */
    public readonly algorithm:  CoseAlgorithm;

    /** The hash of the certificate's DER encoding. */
    public readonly value:      Uint8Array;


    public constructor(algorithm: CoseAlgorithm, value: Uint8Array) {
        this.algorithm  = algorithm;
        this.value      = value;
    }


    /** Compute the thumbprint of a certificate, with SHA-256 unless told otherwise. */
    public static from(certificate: X509Certificate,
                       algorithm:   CoseAlgorithm = CoseAlgorithms.SHA256): CoseCertificateHash {

        if (algorithm.hash === null)
            throw new CoseError(`The COSE algorithm '${algorithm.name}' is not a hash algorithm!`);

        return new CoseCertificateHash(algorithm, certificate.thumbprint(algorithm.hash));

    }


    /** Read a `COSE_CertHash` from its CBOR form. */
    public static fromCbor(value: CborValue): CoseCertificateHash {

        if (value.type !== 'array')
            throw new CoseError(`A COSE_CertHash must be a CBOR array, but was a CBOR ${value.type}!`);

        if (value.items.length !== 2)
            throw new CoseError(`A COSE_CertHash must hold exactly two elements, but held ${String(value.items.length)}!`);

        const [algorithmValue, hashValue] = value.items as [CborValue, CborValue];

        if (hashValue.type !== 'bytes')
            throw new CoseError('The hash value of a COSE_CertHash must be a byte string!');

        if (algorithmValue.type !== 'int')
            throw new CoseError('The hash algorithm of a COSE_CertHash must be an integer, as no name is registered for one!');

        const algorithm = algorithmById(Number(algorithmValue.value));

        if (algorithm === null)
            throw new CoseError(`The COSE algorithm ${String(algorithmValue.value)} of the COSE_CertHash is not registered!`);

        if (algorithm.hash === null)
            throw new CoseError(`The COSE algorithm '${algorithm.name}' of the COSE_CertHash is not a hash algorithm!`);

        return new CoseCertificateHash(algorithm, hashValue.value);

    }


    /** The CBOR form. */
    public toCbor(): CborValue {
        return cbor.array([cbor.int(BigInt(this.algorithm.id)), cbor.bytes(this.value)]);
    }


    /**
     * Whether this thumbprint names the given certificate.
     *
     * A thumbprint that names a *different* certificate than the one that
     * travelled is not a detail to shrug at: the message states which
     * certificate it means, and the chain offers another. One of the two is
     * wrong and there is no way to tell which.
     */
    public matches(certificate: X509Certificate): Verification {

        if (this.algorithm.hash === null)
            return notVerified(`The COSE algorithm '${this.algorithm.name}' of the certificate thumbprint is not a hash algorithm!`);

        const computed = certificate.thumbprint(this.algorithm.hash);

        if (computed.length !== this.value.length ||
            !computed.every((each, index) => each === this.value[index]))
            return notVerified(`The certificate thumbprint of this message does not name the certificate '${certificate.subject.toString()}' that travelled with it!`);

        return VERIFIED;

    }

}
