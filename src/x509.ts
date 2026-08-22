/*
 * Copyright (c) 2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr COSE <https://github.com/Vanaheimr/COSE.TS>
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * X.509 certificates [RFC 5280], to the depth COSE needs them.
 *
 * COSE reaches X.509 through the header parameters of RFC 9360, and a chain
 * that travels in a message is untrusted input like everything else in it.
 * Reading one therefore means parsing it, walking it to an anchor, and — the
 * step that is easy to leave out — establishing that the key it ends in is the
 * key that actually signed. This module does the first of those; `x5chain.ts`
 * does the second, and `CoseSign1.verifyWithCertificateChain` the third.
 *
 * Why this is written out rather than taken from a library: verification here
 * has to reach every algorithm this package signs with, and that includes the
 * brainpool curves and the three ML-DSA parameter sets. The obvious
 * TypeScript X.509 libraries verify through WebCrypto, which supports neither
 * — so a certificate issued to a meter on brainpoolP256r1, which is the whole
 * point of the exercise, is exactly the certificate they cannot check. The
 * signature verification here goes through the same code path as every other
 * signature this package verifies, so whatever COSE can verify, a certificate
 * can be signed with.
 *
 * What is NOT done, matching Styx so that the two agree about what an answer
 * means: no revocation, no name constraints, no certificate policies, no path
 * length beyond the CA flag itself. And a certificate says "this key belongs
 * to that subject, attested by someone I trust" — whether the subject may
 * state what it states is never a question a certificate answers.
 */

import { contentsOf, contextTag, derBitString, derBitStringRaw,
         derBoolean, derInteger, derObjectIdentifier, derString,
         derTime, DerReader, Tag }        from './asn1.ts';
import type { Asn1Node }                  from './asn1.ts';
import { CoseAlgorithms, verifyWith }     from './algorithm.ts';
import type { CoseAlgorithm }             from './algorithm.ts';
import { CoseCurves }                     from './curve.ts';
import type { CoseCurve }                 from './curve.ts';
import { decompressY, digest }            from './ecdsa.ts';
import type { DigestAlgorithm }           from './ecdsa.ts';
import { CoseError, notVerified,
         VERIFIED }                       from './errors.ts';
import type { Verification }              from './errors.ts';
import { CoseKey }                        from './key.ts';


// ------------------------------------------------------------------- OIDs ---

/** The named curves of a `SubjectPublicKeyInfo`, by object identifier. */
const CURVE_OIDS: Readonly<Record<string, CoseCurve>> = {
    '1.2.840.10045.3.1.7':   CoseCurves.P256,             // prime256v1
    '1.3.132.0.34':          CoseCurves.P384,             // secp384r1
    '1.3.132.0.35':          CoseCurves.P521,             // secp521r1
    '1.3.132.0.10':          CoseCurves.secp256k1,
    '1.3.36.3.3.2.8.1.1.7':  CoseCurves.brainpoolP256r1,  // [RFC 5639, Appendix A]
    '1.3.36.3.3.2.8.1.1.9':  CoseCurves.brainpoolP320r1,
    '1.3.36.3.3.2.8.1.1.11': CoseCurves.brainpoolP384r1,
    '1.3.36.3.3.2.8.1.1.13': CoseCurves.brainpoolP512r1,
};

const OID_EC_PUBLIC_KEY  = '1.2.840.10045.2.1';
const OID_ED25519        = '1.3.101.112';
const OID_ED448          = '1.3.101.113';

/**
 * The ML-DSA identifiers of the NIST arc [FIPS 204, RFC 9881]. One object
 * identifier serves as both the key type and the signature algorithm, which is
 * what a fully-specified algorithm looks like in ASN.1.
 */
const OID_MLDSA44        = '2.16.840.1.101.3.4.3.17';
const OID_MLDSA65        = '2.16.840.1.101.3.4.3.18';
const OID_MLDSA87        = '2.16.840.1.101.3.4.3.19';

/**
 * How a certificate's signature was produced.
 *
 * ECDSA identifiers name the digest and leave the curve to the issuer's key,
 * exactly as the COSE algorithms this maps them to do — which is why the
 * curve-less `ES*` identifiers are the right target here and the fully
 * specified `ESP*`/`ESB*` ones are not.
 */
const SIGNATURE_OIDS: Readonly<Record<string, CoseAlgorithm>> = {
    '1.2.840.10045.4.3.2': CoseAlgorithms.ES256,    // ecdsa-with-SHA256
    '1.2.840.10045.4.3.3': CoseAlgorithms.ES384,    // ecdsa-with-SHA384
    '1.2.840.10045.4.3.4': CoseAlgorithms.ES512,    // ecdsa-with-SHA512
    [OID_ED25519]:         CoseAlgorithms.Ed25519,
    [OID_ED448]:           CoseAlgorithms.Ed448,
    [OID_MLDSA44]:         CoseAlgorithms.MLDSA44,
    [OID_MLDSA65]:         CoseAlgorithms.MLDSA65,
    [OID_MLDSA87]:         CoseAlgorithms.MLDSA87,
};

/** The attribute types a distinguished name is usually written with. */
const NAME_OIDS: Readonly<Record<string, string>> = {
    '2.5.4.3':                      'CN',
    '2.5.4.4':                      'SN',
    '2.5.4.5':                      'SERIALNUMBER',
    '2.5.4.6':                      'C',
    '2.5.4.7':                      'L',
    '2.5.4.8':                      'ST',
    '2.5.4.9':                      'STREET',
    '2.5.4.10':                     'O',
    '2.5.4.11':                     'OU',
    '2.5.4.12':                     'T',
    '2.5.4.42':                     'GIVENNAME',
    '1.2.840.113549.1.9.1':         'E',
    '0.9.2342.19200300.100.1.25':   'DC',
    '0.9.2342.19200300.100.1.1':    'UID',
};

const OID_BASIC_CONSTRAINTS = '2.5.29.19';
const OID_KEY_USAGE         = '2.5.29.15';


// ------------------------------------------------------------------ names ---

/** One attribute of a distinguished name. */
export interface NameAttribute {

    /** The attribute type, in dotted decimal. */
    readonly oid:    string;

    /** The attribute value, as text. */
    readonly value:  string;

}


/**
 * A distinguished name.
 *
 * Two names are compared the way RFC 5280 Section 7.1 asks for rather than by
 * their encodings: a `PrintableString` and a `UTF8String` holding the same
 * characters name the same entity, and a chain whose issuer field was written
 * in one and whose subject field was written in the other is a chain, not a
 * forgery. Byte equality is still tried first, because it is both cheaper and
 * the case that almost always applies.
 */
export class X509Name {

    /** The attributes, outermost relative name first, as they were encoded. */
    public readonly attributes:  readonly NameAttribute[];

    /** The DER encoding, kept because a name is also compared by its bytes. */
    public readonly encoded:     Uint8Array;


    public constructor(attributes: readonly NameAttribute[], encoded: Uint8Array) {
        this.attributes  = attributes;
        this.encoded     = encoded;
    }


    /** Parse an X.501 `Name`, which is a `SEQUENCE OF SET OF` attributes. */
    public static parse(node: Asn1Node, what: string): X509Name {

        const attributes:  NameAttribute[]  = [];
        const relatives                      = contentsOf(node, `${what}: the relative distinguished names`);

        while (!relatives.atEnd) {

            const set      = relatives.read(Tag.set);
            const members  = contentsOf(set, `${what}: a relative distinguished name`);

            while (!members.atEnd) {

                const pair  = contentsOf(members.read(Tag.sequence), `${what}: an attribute of the name`);
                const oid   = derObjectIdentifier(pair.read(Tag.objectIdentifier), `${what}: an attribute type`);
                const value = pair.read();

                pair.expectEnd();

                attributes.push({ oid, value: derString(value, `${what}: the value of the attribute ${oid}`) });

            }

        }

        return new X509Name(attributes, node.encoded);

    }


    /**
     * Whether this name and the given one name the same entity.
     *
     * The normalization is the practical part of RFC 4518: leading and
     * trailing whitespace removed, internal runs collapsed to one space, and
     * case folded. Not implemented, because no certificate in this project's
     * world uses them: the Unicode mapping and prohibition tables.
     */
    public equivalentTo(other: X509Name): boolean {

        if (bytesEqual(this.encoded, other.encoded))
            return true;

        if (this.attributes.length !== other.attributes.length)
            return false;

        return this.attributes.every((each, index) =>
            each.oid === other.attributes[index]!.oid &&
            normalize(each.value) === normalize(other.attributes[index]!.value));

    }


    /** The name in the usual `CN=…,O=…` notation. */
    public toString(): string {

        return this.attributes
                   .map(each => `${NAME_OIDS[each.oid] ?? each.oid}=${each.value}`)
                   .join(',');

    }

}


const normalize = (value: string): string =>
    value.trim().replace(/\s+/gu, ' ').toLowerCase();


const bytesEqual = (left: Uint8Array, right: Uint8Array): boolean =>
    left.length === right.length && left.every((each, index) => each === right[index]);


// ------------------------------------------------------------- extensions ---

/** The `basicConstraints` extension [RFC 5280, Section 4.2.1.9]. */
export interface BasicConstraints {

    /** Whether the certified key may sign other certificates. */
    readonly certificateAuthority:  boolean;

    /** How many intermediates may follow, when the extension says. */
    readonly pathLength:            number | null;

}


/**
 * The bits of the `keyUsage` extension [RFC 5280, Section 4.2.1.3], by name.
 *
 * The order is the ASN.1 one and it is load bearing: `digitalSignature` is bit
 * zero and `keyCertSign` bit five, and those two are the only ones a signature
 * with a certificate chain turns on.
 */
export const KeyUsage = {
    digitalSignature:  0,
    nonRepudiation:    1,
    keyEncipherment:   2,
    dataEncipherment:  3,
    keyAgreement:      4,
    keyCertSign:       5,
    cRLSign:           6,
    encipherOnly:      7,
    decipherOnly:      8,
} as const;


// ------------------------------------------------------------ certificate ---

/**
 * An X.509 certificate.
 *
 * Everything here is what the certificate *says*. None of it is a reason to
 * believe any of it: that comes from a chain to an anchor, which is
 * `CoseCertificateChain`'s business.
 */
export class X509Certificate {

    /** The DER encoding, exactly as it arrived. */
    public readonly encoded:          Uint8Array;

    /** The `tbsCertificate`, which is the part the signature covers. */
    public readonly tbsBytes:         Uint8Array;

    /** The version, 1 to 3. */
    public readonly version:          number;

    /** The serial number, which may be negative and is often very large. */
    public readonly serialNumber:     bigint;

    /** Who issued this certificate. */
    public readonly issuer:           X509Name;

    /** Whom it was issued to. */
    public readonly subject:          X509Name;

    /** The start of the validity period, inclusive. */
    public readonly notBefore:        Date;

    /** The end of the validity period, inclusive. */
    public readonly notAfter:         Date;

    /** The certified public key. */
    public readonly publicKey:        CoseKey;

    /** How this certificate was signed, as the COSE algorithm it corresponds to. */
    public readonly signatureAlgorithm: CoseAlgorithm;

    /** The signature, as it was encoded — DER for ECDSA, raw otherwise. */
    public readonly signatureValue:   Uint8Array;

    /** The `basicConstraints` extension, when present. */
    public readonly basicConstraints: BasicConstraints | null;

    /** The `keyUsage` extension as a bit array, when present. */
    public readonly keyUsage:         readonly boolean[] | null;

    /** The object identifiers of every extension marked critical. */
    public readonly criticalExtensions: readonly string[];


    private constructor(fields: {
        encoded:            Uint8Array;
        tbsBytes:           Uint8Array;
        version:            number;
        serialNumber:       bigint;
        issuer:             X509Name;
        subject:            X509Name;
        notBefore:          Date;
        notAfter:           Date;
        publicKey:          CoseKey;
        signatureAlgorithm: CoseAlgorithm;
        signatureValue:     Uint8Array;
        basicConstraints:   BasicConstraints | null;
        keyUsage:           readonly boolean[] | null;
        criticalExtensions: readonly string[];
    }) {
        this.encoded             = fields.encoded;
        this.tbsBytes            = fields.tbsBytes;
        this.version             = fields.version;
        this.serialNumber        = fields.serialNumber;
        this.issuer              = fields.issuer;
        this.subject             = fields.subject;
        this.notBefore           = fields.notBefore;
        this.notAfter            = fields.notAfter;
        this.publicKey           = fields.publicKey;
        this.signatureAlgorithm  = fields.signatureAlgorithm;
        this.signatureValue      = fields.signatureValue;
        this.basicConstraints    = fields.basicConstraints;
        this.keyUsage            = fields.keyUsage;
        this.criticalExtensions  = fields.criticalExtensions;
    }


    // ------------------------------------------------------------- parsing

    /**
     * Parse a DER encoded certificate.
     *
     * The `signatureAlgorithm` of the outer structure and the `signature`
     * field inside the `tbsCertificate` must agree, and it is checked: they
     * are the same statement written twice, and an implementation that reads
     * one while verifying with the other can be told two different things at
     * once.
     */
    public static parse(der: Uint8Array): X509Certificate {

        const what        = 'This X.509 certificate';
        const outer       = new DerReader(der, what);
        const certificate = outer.read(Tag.sequence);

        outer.expectEnd();

        const body                 = contentsOf(certificate, what);
        const tbs                  = body.read(Tag.sequence);
        const outerAlgorithmNode   = body.read(Tag.sequence);
        const signatureNode        = body.read(Tag.bitString);

        body.expectEnd();

        const outerAlgorithm  = algorithmIdentifier(outerAlgorithmNode, `${what}: the signature algorithm`);
        const fields          = contentsOf(tbs, `${what}: the certificate body`);

        // The version is [0] EXPLICIT and defaults to v1 when absent, which
        // is the only reason it is optional.
        const versionNode  = fields.readOptional(contextTag(0));
        const version      = versionNode === null
                                 ? 1
                                 : Number(derInteger(contentsOf(versionNode, `${what}: the version`).read(Tag.integer),
                                                     `${what}: the version`)) + 1;

        if (version < 1 || version > 3)
            throw new CoseError(`${what}: the version v${String(version)} is not one X.509 defines`);

        const serialNumber      = derInteger(fields.read(Tag.integer), `${what}: the serial number`);
        const innerAlgorithm    = algorithmIdentifier(fields.read(Tag.sequence), `${what}: the inner signature algorithm`);
        const issuer            = X509Name.parse(fields.read(Tag.sequence), `${what}: the issuer`);

        const validity          = contentsOf(fields.read(Tag.sequence), `${what}: the validity period`);
        const notBefore         = derTime(validity.read(), `${what}: the start of the validity period`);
        const notAfter          = derTime(validity.read(), `${what}: the end of the validity period`);

        validity.expectEnd();

        const subject           = X509Name.parse(fields.read(Tag.sequence), `${what}: the subject`);
        const publicKey         = subjectPublicKey(fields.read(Tag.sequence), what);

        if (outerAlgorithm.oid !== innerAlgorithm.oid)
            throw new CoseError(`${what}: says it was signed with '${outerAlgorithm.oid}' on the outside and with '${innerAlgorithm.oid}' within the body it signed`);

        const algorithm = SIGNATURE_OIDS[outerAlgorithm.oid];

        if (algorithm === undefined)
            throw new CoseError(`${what}: was signed with '${outerAlgorithm.oid}', which is not a signature algorithm this implementation knows`);

        // The unique identifiers of v2 are read past rather than kept: no
        // certificate anybody issues carries them, and skipping a field one
        // does not understand is not the same as ignoring it.
        fields.readOptional(0x81);
        fields.readOptional(0x82);

        const extensionsNode  = fields.readOptional(contextTag(3));
        const extensions      = extensionsNode === null
                                    ? { basicConstraints: null, keyUsage: null, critical: [] as string[] }
                                    : parseExtensions(extensionsNode, what);

        fields.expectEnd();

        if (extensionsNode !== null && version !== 3)
            throw new CoseError(`${what}: carries extensions, which only a v3 certificate may`);

        return new X509Certificate({
            encoded:             certificate.encoded,
            tbsBytes:            tbs.encoded,
            version,
            serialNumber,
            issuer,
            subject,
            notBefore,
            notAfter,
            publicKey,
            signatureAlgorithm:  algorithm,
            signatureValue:      derBitString(signatureNode, `${what}: the signature`),
            basicConstraints:    extensions.basicConstraints,
            keyUsage:            extensions.keyUsage,
            criticalExtensions:  extensions.critical,
        });

    }


    // -------------------------------------------------------------- checks

    /** Whether this certificate is within its validity period at the given instant. */
    public isValidAt(at: Date): Verification {

        if (at.getTime() < this.notBefore.getTime())
            return notVerified(`The certificate '${this.subject.toString()}' is not valid before ${iso(this.notBefore)}, and was checked at ${iso(at)}!`);

        if (at.getTime() > this.notAfter.getTime())
            return notVerified(`The certificate '${this.subject.toString()}' expired at ${iso(this.notAfter)}, and was checked at ${iso(at)}!`);

        return VERIFIED;

    }


    /** Whether the given key usage bit is set, an absent extension meaning unrestricted. */
    public allows(usage: number): boolean {

        if (this.keyUsage === null)
            return true;

        return this.keyUsage[usage] ?? false;

    }


    /** Whether the certified key may sign other certificates. */
    public get isCertificateAuthority(): boolean {

        return this.basicConstraints?.certificateAuthority ?? false;

    }


    /**
     * Whether this certificate was signed by the given one.
     *
     * Both halves are checked and neither implies the other: the issuer field
     * has to name the candidate's subject, and the signature has to verify
     * with the candidate's key. A name that matches without a signature is a
     * claim, and a signature that verifies under a different name is somebody
     * else's certificate.
     */
    public verifySignedBy(issuer: X509Certificate): Verification {

        if (!this.issuer.equivalentTo(issuer.subject))
            return notVerified(`The certificate '${this.subject.toString()}' names the issuer '${this.issuer.toString()}', which is not the subject of '${issuer.subject.toString()}'!`);

        const key = issuer.publicKey;

        let signature: Uint8Array;

        try {
            signature = this.signatureAlgorithm.family === 'ecdsa'
                            ? rawEcdsaSignature(this.signatureValue, key.curve, this.subject.toString())
                            : this.signatureValue;
        }
        catch (exception) {
            return notVerified(exception instanceof Error ? exception.message : String(exception));
        }

        let verified: boolean;

        try {
            verified = verifyWith(this.signatureAlgorithm,
                                  key.curve,
                                  this.tbsBytes,
                                  signature,
                                  key.publicKeyBytes());
        }
        catch (exception) {
            return notVerified(`The certificate '${this.subject.toString()}' could not be checked against '${issuer.subject.toString()}': ${exception instanceof Error ? exception.message : String(exception)}`);
        }

        return verified
                   ? VERIFIED
                   : notVerified(`The certificate '${this.subject.toString()}' was not signed by '${issuer.subject.toString()}'!`);

    }


    /** The hash of this certificate's DER encoding, which is what `x5t` carries. */
    public thumbprint(hash: DigestAlgorithm = 'sha256'): Uint8Array {
        return digest(hash, this.encoded);
    }


    /** Whether this is byte for byte the same certificate as the given one. */
    public equals(other: X509Certificate): boolean {
        return bytesEqual(this.encoded, other.encoded);
    }


    public toString(): string {
        return this.subject.toString();
    }

}


const iso = (value: Date): string => value.toISOString().replace(/\.\d{3}Z$/u, 'Z');


// ---------------------------------------------------------------- helpers ---

/** An `AlgorithmIdentifier`: an object identifier and whatever it parameterizes. */
function algorithmIdentifier(node: Asn1Node, what: string): { oid: string; parameters: Asn1Node | null } {

    const fields = contentsOf(node, what);
    const oid    = derObjectIdentifier(fields.read(Tag.objectIdentifier), what);

    const parameters = fields.atEnd ? null : fields.read();

    fields.expectEnd();

    return { oid, parameters };

}


/**
 * A `SubjectPublicKeyInfo`, as the COSE key it corresponds to.
 *
 * The three key types diverge here exactly as they do in COSE: an elliptic
 * curve key names its curve in the algorithm parameters and carries a point,
 * an Edwards key is its own algorithm and carries the whole public key, and an
 * ML-DSA key names its parameter set in the algorithm identifier — which is
 * the same reason an AKP COSE key has to carry `alg`.
 */
function subjectPublicKey(node: Asn1Node, what: string): CoseKey {

    const fields    = contentsOf(node, `${what}: the subject public key info`);
    const algorithm = algorithmIdentifier(fields.read(Tag.sequence), `${what}: the public key algorithm`);
    const bits      = derBitString(fields.read(Tag.bitString), `${what}: the public key`);

    fields.expectEnd();

    if (algorithm.oid === OID_EC_PUBLIC_KEY) {

        if (algorithm.parameters === null)
            throw new CoseError(`${what}: holds an elliptic curve key that does not name its curve, which this implementation does not support`);

        if (algorithm.parameters.tag !== Tag.objectIdentifier)
            throw new CoseError(`${what}: holds an elliptic curve key whose parameters are not a named curve, which this implementation does not support`);

        const oid   = derObjectIdentifier(algorithm.parameters, `${what}: the curve`);
        const curve = CURVE_OIDS[oid];

        if (curve === undefined)
            throw new CoseError(`${what}: holds a key on the curve '${oid}', which is not a curve this implementation knows`);

        return ecPublicKey(curve, bits, what);

    }

    if (algorithm.oid === OID_ED25519)
        return CoseKey.fromOkpPublicKey(CoseCurves.Ed25519, bits,
                                        { algorithm: CoseAlgorithms.Ed25519 });

    if (algorithm.oid === OID_ED448)
        return CoseKey.fromOkpPublicKey(CoseCurves.Ed448, bits,
                                        { algorithm: CoseAlgorithms.Ed448 });

    const mldsa = algorithm.oid === OID_MLDSA44 ? CoseAlgorithms.MLDSA44
                : algorithm.oid === OID_MLDSA65 ? CoseAlgorithms.MLDSA65
                : algorithm.oid === OID_MLDSA87 ? CoseAlgorithms.MLDSA87
                : null;

    if (mldsa !== null)
        return CoseKey.fromAkpPublicKey(mldsa, bits);

    throw new CoseError(`${what}: holds a key of type '${algorithm.oid}', which is not a key type this implementation knows`);

}


/**
 * An elliptic curve point as a COSE key.
 *
 * Uncompressed is what every certificate in practice carries; compressed is
 * accepted because RFC 5480 permits it and because the curve arithmetic to
 * recover `y` is already here for COSE keys, which permit it too.
 */
function ecPublicKey(curve: CoseCurve, point: Uint8Array, what: string): CoseKey {

    const width = curve.fieldSize;

    if (width === null)
        throw new CoseError(`${what}: holds a key on the curve '${curve.name}', which has no signature algorithm`);

    if (point.length === 0)
        throw new CoseError(`${what}: holds an empty elliptic curve point`);

    if (point[0] === 0x04) {

        if (point.length !== 1 + 2 * width)
            throw new CoseError(`${what}: holds an uncompressed point of ${String(point.length)} octets, where the curve '${curve.name}' needs ${String(1 + 2 * width)}`);

        return CoseKey.fromCoordinates(curve,
                                       point.subarray(1, 1 + width),
                                       point.subarray(1 + width));

    }

    if (point[0] === 0x02 || point[0] === 0x03) {

        if (point.length !== 1 + width)
            throw new CoseError(`${what}: holds a compressed point of ${String(point.length)} octets, where the curve '${curve.name}' needs ${String(1 + width)}`);

        const x = point.subarray(1);

        return CoseKey.fromCoordinates(curve, x, decompressY(curve, x, point[0] === 0x03));

    }

    throw new CoseError(`${what}: holds an elliptic curve point whose first octet is 0x${point[0]!.toString(16).padStart(2, '0')}, which is neither 0x04, 0x02 nor 0x03`);

}


/**
 * An ECDSA signature from a certificate, in the fixed-width form COSE uses.
 *
 * This is a real difference between the two worlds and not a formality: X.509
 * writes `SEQUENCE { INTEGER r, INTEGER s }`, whose length varies with the
 * leading zero bits of the two integers, and COSE writes `r ‖ s` padded to the
 * width of the group order. The same signature, two encodings, and an
 * implementation that hands one to the other verifies nothing.
 */
function rawEcdsaSignature(der: Uint8Array, curve: CoseCurve | null, subject: string): Uint8Array {

    const width = curve?.orderSize ?? null;

    if (width === null)
        throw new CoseError(`The signature of the certificate '${subject}' can not be read without knowing the issuer's curve!`);

    const what     = `The ECDSA signature of the certificate '${subject}'`;
    const outer    = new DerReader(der, what);
    const sequence = contentsOf(outer.read(Tag.sequence), what);

    outer.expectEnd();

    const r = derInteger(sequence.read(Tag.integer), `${what}: r`);
    const s = derInteger(sequence.read(Tag.integer), `${what}: s`);

    sequence.expectEnd();

    if (r <= 0n || s <= 0n)
        throw new CoseError(`${what}: both halves must be positive`);

    const raw = new Uint8Array(2 * width);

    writeBigInt(r, raw, 0,     width, what, 'r');
    writeBigInt(s, raw, width, width, what, 's');

    return raw;

}


function writeBigInt(value: bigint, into: Uint8Array, at: number,
                     width: number, what: string, half: string): void {

    let hex = value.toString(16);

    if (hex.length % 2 !== 0)
        hex = `0${hex}`;

    if (hex.length / 2 > width)
        throw new CoseError(`${what}: ${half} is ${String(hex.length / 2)} octets, which is wider than the group order`);

    const offset = at + width - hex.length / 2;

    for (let index = 0; index < hex.length / 2; index++)
        into[offset + index] = Number.parseInt(hex.slice(2 * index, 2 * index + 2), 16);

}


/** The extensions this implementation looks at, and the identity of the rest. */
function parseExtensions(node: Asn1Node, what: string): {
    basicConstraints: BasicConstraints | null;
    keyUsage:         readonly boolean[] | null;
    critical:         string[];
} {

    const list      = contentsOf(contentsOf(node, `${what}: the extensions`).read(Tag.sequence),
                                 `${what}: the extensions`);
    const critical: string[] = [];
    const seen                = new Set<string>();

    let basicConstraints: BasicConstraints | null   = null;
    let keyUsage:         readonly boolean[] | null = null;

    while (!list.atEnd) {

        const extension  = contentsOf(list.read(Tag.sequence), `${what}: an extension`);
        const oid        = derObjectIdentifier(extension.read(Tag.objectIdentifier), `${what}: an extension identifier`);

        if (seen.has(oid))
            throw new CoseError(`${what}: carries the extension '${oid}' more than once, which RFC 5280 forbids`);

        seen.add(oid);

        const criticalNode = extension.peekIs(Tag.boolean) ? extension.read(Tag.boolean) : null;

        if (criticalNode !== null && derBoolean(criticalNode, `${what}: the criticality of '${oid}'`))
            critical.push(oid);

        const value = extension.read(Tag.octetString);

        extension.expectEnd();

        if (oid === OID_BASIC_CONSTRAINTS)
            basicConstraints = parseBasicConstraints(value, what);

        else if (oid === OID_KEY_USAGE)
            keyUsage = parseKeyUsage(value, what);

    }

    return { basicConstraints, keyUsage, critical };

}


function parseBasicConstraints(value: Asn1Node, what: string): BasicConstraints {

    const where     = `${what}: the basicConstraints extension`;
    const outer     = new DerReader(value.content, where);
    const sequence  = contentsOf(outer.read(Tag.sequence), where);

    outer.expectEnd();

    // Both fields are DEFAULT/OPTIONAL, and DER omits a field at its default —
    // so `cA` absent means false, and an encoder writing FALSE explicitly is
    // the one in the wrong.
    const caNode   = sequence.peekIs(Tag.boolean) ? sequence.read(Tag.boolean) : null;
    const pathNode = sequence.peekIs(Tag.integer) ? sequence.read(Tag.integer) : null;

    sequence.expectEnd();

    return {
        certificateAuthority: caNode   === null ? false : derBoolean(caNode, where),
        pathLength:           pathNode === null ? null  : Number(derInteger(pathNode, where)),
    };

}


function parseKeyUsage(value: Asn1Node, what: string): readonly boolean[] {

    const where               = `${what}: the keyUsage extension`;
    const outer               = new DerReader(value.content, where);
    const { unusedBits, bytes } = derBitStringRaw(outer.read(Tag.bitString), where);

    outer.expectEnd();

    const bits: boolean[] = [];

    for (let index = 0; index < bytes.length * 8 - unusedBits; index++)
        bits.push((bytes[index >> 3]! & (0x80 >> (index & 7))) !== 0);

    return bits;

}


/** The COSE algorithm a certificate signature identifier corresponds to. */
export const signatureAlgorithmByOid = (oid: string): CoseAlgorithm | null =>
    SIGNATURE_OIDS[oid] ?? null;


/** The curve a `SubjectPublicKeyInfo` identifier names. */
export const curveByOid = (oid: string): CoseCurve | null =>
    CURVE_OIDS[oid] ?? null;


/** The object identifier of a curve, which is the inverse of {@link curveByOid}. */
export function oidOfCurve(curve: CoseCurve): string | null {

    for (const [oid, each] of Object.entries(CURVE_OIDS)) {
        if (each.id === curve.id)
            return oid;
    }

    return null;

}
