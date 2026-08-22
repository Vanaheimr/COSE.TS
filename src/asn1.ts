/*
 * Copyright (c) 2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr COSE <https://github.com/Vanaheimr/COSE.TS>
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * As much ASN.1 DER as an X.509 certificate needs, and not one rule more.
 *
 * This is a *reader*, never a writer: certificates arrive already encoded and
 * the only bytes this package ever hashes are the ones that arrived, so
 * re-encoding a parsed structure would be a way to get the wrong answer and
 * nothing else. Every node therefore keeps its own encoding, which is how
 * `tbsCertificate` is fed to a signature verification byte for byte.
 *
 * The rules enforced here are DER's rather than BER's, because a certificate
 * is DER by definition [RFC 5280, Section 4.1] and because the difference is
 * where parsing differentials live: an indefinite length or a non-minimal one
 * is the sort of thing one implementation shrugs at and another rejects, and
 * two implementations that disagree about where a certificate ends can be made
 * to disagree about what it says.
 *
 * What is deliberately absent: indefinite lengths, tags above 30 (no
 * multi-byte identifiers appear in a certificate), and every string type
 * beyond the handful X.509 names actually use.
 */

import { CoseError } from './errors.ts';


// ------------------------------------------------------------------- tags ---

/** The universal ASN.1 tags this package meets. */
export const Tag = {
    boolean:           0x01,
    integer:           0x02,
    bitString:         0x03,
    octetString:       0x04,
    null:              0x05,
    objectIdentifier:  0x06,
    utf8String:        0x0c,
    printableString:   0x13,
    teletexString:     0x14,
    ia5String:         0x16,
    utcTime:           0x17,
    generalizedTime:   0x18,
    bmpString:         0x1e,
    universalString:   0x1c,
    sequence:          0x30,
    set:               0x31,
} as const;


/** A context-specific constructed tag, e.g. `[0]` is `contextTag(0)`. */
export const contextTag = (number: number): number => 0xa0 | number;


/** The string tags an X.509 `DirectoryString` may carry. */
const STRING_TAGS: readonly number[] = [
    Tag.utf8String, Tag.printableString, Tag.teletexString,
    Tag.ia5String,  Tag.bmpString,       Tag.universalString,
];


// ------------------------------------------------------------------ nodes ---

/**
 * One tag-length-value record.
 *
 * `content` is the value octets and `encoded` the whole record — identifier,
 * length and value. Both matter: the content is what a field says, the
 * encoding is what a signature covers.
 */
export interface Asn1Node {

    /** The identifier octet. */
    readonly tag:      number;

    /** The value octets, without identifier or length. */
    readonly content:  Uint8Array;

    /** The complete record, exactly as it appeared. */
    readonly encoded:  Uint8Array;

}


/**
 * A cursor over a sequence of DER records.
 *
 * The `what` is carried only so that a failure can say which structure was
 * being read; a message naming a byte offset and nothing else is a message
 * that has to be debugged rather than read.
 */
export class DerReader {

    private readonly data:  Uint8Array;
    private readonly what:  string;
    private          at:    number;


    public constructor(data: Uint8Array, what: string) {
        this.data  = data;
        this.what  = what;
        this.at    = 0;
    }


    /** Whether every record has been read. */
    public get atEnd(): boolean {
        return this.at >= this.data.length;
    }


    /** The octets not yet read. */
    public get remaining(): Uint8Array {
        return this.data.subarray(this.at);
    }


    private fail(reason: string): never {
        throw new CoseError(`${this.what}: ${reason}`);
    }


    /**
     * Read the next record, optionally insisting on a tag.
     *
     * The length rules are DER's: definite always, short form below 128,
     * long form minimally encoded and never longer than eight octets — which
     * is far more than a certificate can need and still shorter than the point
     * where a length stops fitting a JavaScript number.
     */
    public read(expectedTag?: number): Asn1Node {

        const start = this.at;

        if (this.at + 2 > this.data.length)
            this.fail(`a DER record needs at least two octets, and only ${String(this.data.length - this.at)} remain`);

        const tag = this.data[this.at++]!;

        if ((tag & 0x1f) === 0x1f)
            this.fail('a DER identifier of more than one octet is not something a certificate contains');

        if (expectedTag !== undefined && tag !== expectedTag)
            this.fail(`expected the DER tag 0x${expectedTag.toString(16).padStart(2, '0')}, but found 0x${tag.toString(16).padStart(2, '0')}`);

        const first = this.data[this.at++]!;

        let length: number;

        if (first === 0x80)
            this.fail('an indefinite length is BER, not DER, and a certificate is DER');

        else if (first === 0xff)
            this.fail('0xFF is not a valid DER length octet');

        else if (first < 0x80)
            length = first;

        else {

            const count = first & 0x7f;

            if (count > 8)
                this.fail(`a length of ${String(count)} octets is longer than anything a certificate can hold`);

            if (this.at + count > this.data.length)
                this.fail('the long-form length runs past the end of the data');

            if (this.data[this.at] === 0x00)
                this.fail('a DER length must not be encoded with a leading zero octet');

            length = 0;

            for (let index = 0; index < count; index++)
                length = length * 256 + this.data[this.at++]!;

            if (length < 0x80)
                this.fail(`the length ${String(length)} must be encoded in the short form`);

            if (!Number.isSafeInteger(length))
                this.fail('the length is larger than this implementation can address');

        }

        if (this.at + length > this.data.length)
            this.fail(`a record claims ${String(length)} octets, and only ${String(this.data.length - this.at)} remain`);

        const content = this.data.subarray(this.at, this.at + length);

        this.at += length;

        return { tag, content, encoded: this.data.subarray(start, this.at) };

    }


    /** Read the next record when it carries the given tag, else read nothing. */
    public readOptional(tag: number): Asn1Node | null {

        if (this.atEnd || this.data[this.at] !== tag)
            return null;

        return this.read(tag);

    }


    /** Whether a record with the given tag comes next. */
    public peekIs(tag: number): boolean {
        return !this.atEnd && this.data[this.at] === tag;
    }


    /** Insist that nothing follows, which is how trailing data is caught. */
    public expectEnd(): void {

        if (!this.atEnd)
            this.fail(`${String(this.data.length - this.at)} octets follow the structure and should not`);

    }

}


/** A cursor over the contents of a constructed record. */
export const contentsOf = (node: Asn1Node, what: string): DerReader =>
    new DerReader(node.content, what);


// ------------------------------------------------------------- primitives ---

/**
 * A DER INTEGER as a bigint, two's complement and minimally encoded.
 *
 * Certificates hold signed integers here — a serial number is defined as one
 * — so a leading 0x00 before a high bit is padding and a leading 0x00 before
 * anything else is a violation.
 */
export function derInteger(node: Asn1Node, what: string): bigint {

    const bytes = node.content;

    if (bytes.length === 0)
        throw new CoseError(`${what}: a DER INTEGER must not be empty`);

    if (bytes.length > 1 &&
        ((bytes[0] === 0x00 && (bytes[1]! & 0x80) === 0) ||
         (bytes[0] === 0xff && (bytes[1]! & 0x80) !== 0)))
        throw new CoseError(`${what}: a DER INTEGER must be minimally encoded`);

    let value = 0n;

    for (const each of bytes)
        value = (value << 8n) | BigInt(each);

    // Negative when the high bit of the first octet is set.
    return (bytes[0]! & 0x80) === 0
               ? value
               : value - (1n << BigInt(8 * bytes.length));

}


/**
 * A DER BIT STRING, as whole octets.
 *
 * Every bit string a certificate carries a key or a signature in is octet
 * aligned, so an unused-bit count other than zero is refused rather than
 * shifted — `keyUsage` is the one exception and reads the count itself.
 */
export function derBitString(node: Asn1Node, what: string): Uint8Array {

    const { unusedBits, bytes } = derBitStringRaw(node, what);

    if (unusedBits !== 0)
        throw new CoseError(`${what}: expected an octet-aligned BIT STRING, but ${String(unusedBits)} bits are unused`);

    return bytes;

}


/** A DER BIT STRING with its unused-bit count, which `keyUsage` needs. */
export function derBitStringRaw(node: Asn1Node, what: string): { unusedBits: number; bytes: Uint8Array } {

    if (node.content.length === 0)
        throw new CoseError(`${what}: a DER BIT STRING needs at least its unused-bit count`);

    const unusedBits = node.content[0]!;

    if (unusedBits > 7)
        throw new CoseError(`${what}: a DER BIT STRING can not have ${String(unusedBits)} unused bits`);

    if (unusedBits !== 0 && node.content.length === 1)
        throw new CoseError(`${what}: an empty DER BIT STRING must declare zero unused bits`);

    return { unusedBits, bytes: node.content.subarray(1) };

}


/** A DER BOOLEAN. DER admits exactly two encodings, and 0x01 is not one of them. */
export function derBoolean(node: Asn1Node, what: string): boolean {

    if (node.content.length !== 1)
        throw new CoseError(`${what}: a DER BOOLEAN is one octet`);

    if (node.content[0] === 0x00)
        return false;

    if (node.content[0] === 0xff)
        return true;

    throw new CoseError(`${what}: a DER BOOLEAN is 0x00 or 0xFF, but was 0x${node.content[0]!.toString(16).padStart(2, '0')}`);

}


/**
 * A DER OBJECT IDENTIFIER, in dotted decimal.
 *
 * The first two arcs share one octet — `40·first + second` — which is why
 * `2.16.840…` and `1.2.840…` both begin with a byte in the eighties, and why
 * the first arc is recovered by division rather than by lookup.
 */
export function derObjectIdentifier(node: Asn1Node, what: string): string {

    const bytes = node.content;

    if (bytes.length === 0)
        throw new CoseError(`${what}: a DER OBJECT IDENTIFIER must not be empty`);

    const arcs: string[] = [];

    let value    = 0n;
    let started  = false;

    for (let index = 0; index < bytes.length; index++) {

        const octet = bytes[index]!;

        if (!started && octet === 0x80)
            throw new CoseError(`${what}: an arc of a DER OBJECT IDENTIFIER must be minimally encoded`);

        started = true;
        value   = (value << 7n) | BigInt(octet & 0x7f);

        if ((octet & 0x80) !== 0) {

            if (index === bytes.length - 1)
                throw new CoseError(`${what}: a DER OBJECT IDENTIFIER ends in the middle of an arc`);

            continue;

        }

        if (arcs.length === 0) {

            // 0.x is below 40, 1.x below 80, 2.x everything above — and 2.x
            // is unbounded, so the third case has no upper limit to check.
            const first = value < 40n ? 0n : value < 80n ? 1n : 2n;

            arcs.push(first.toString());
            arcs.push((value - first * 40n).toString());

        }

        else
            arcs.push(value.toString());

        value    = 0n;
        started  = false;

    }

    return arcs.join('.');

}


/** A DER string, in whichever of the X.509 string types it was written. */
export function derString(node: Asn1Node, what: string): string {

    if (!STRING_TAGS.includes(node.tag))
        throw new CoseError(`${what}: 0x${node.tag.toString(16).padStart(2, '0')} is not a string type an X.509 name may use`);

    // BMPString is UTF-16BE and UniversalString UTF-32BE; both are rare and
    // both appear in the wild, so neither is worth refusing.
    if (node.tag === Tag.bmpString)
        return decodeWide(node.content, 2, what);

    if (node.tag === Tag.universalString)
        return decodeWide(node.content, 4, what);

    // TeletexString is Latin-1 in every certificate anybody actually issues.
    if (node.tag === Tag.teletexString)
        return Array.from(node.content, each => String.fromCharCode(each)).join('');

    try {
        return new TextDecoder('utf-8', { fatal: true }).decode(node.content);
    }
    catch {
        // `fatal: true` makes the platform throw its own TypeError, which was
        // the one untyped escape this reader had — found by the fuzz suite,
        // and a hostile certificate is exactly who sends invalid UTF-8.
        throw new CoseError(`${what}: the content is not valid UTF-8`);
    }

}


function decodeWide(bytes: Uint8Array, width: number, what: string): string {

    if (bytes.length % width !== 0)
        throw new CoseError(`${what}: a ${String(width * 8)}-bit string must be a whole number of characters`);

    let text = '';

    for (let index = 0; index < bytes.length; index += width) {

        let point = 0;

        for (let byte = 0; byte < width; byte++)
            point = point * 256 + bytes[index + byte]!;

        // Refused rather than passed to the platform: String.fromCodePoint
        // answers a value beyond U+10FFFF with a RangeError of its own, which
        // would be an untyped escape. (Appending one character at a time is
        // deliberate too — a spread over the whole array is a stack overflow
        // waiting for a large enough string.)
        if (point > 0x10FFFF)
            throw new CoseError(`${what}: 0x${point.toString(16)} is not a Unicode code point`);

        text += String.fromCodePoint(point);

    }

    return text;

}


/**
 * A DER UTCTime or GeneralizedTime.
 *
 * DER admits exactly one form of each: seconds present, no fractional part,
 * and Zulu — so anything else is refused rather than guessed at. The
 * two-digit year of a UTCTime is windowed as RFC 5280 Section 4.1.2.5.1
 * requires, 50 and above being the twentieth century.
 */
export function derTime(node: Asn1Node, what: string): Date {

    const text = Array.from(node.content, each => String.fromCharCode(each)).join('');

    if (node.tag === Tag.utcTime) {

        const match = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(text);

        if (match === null)
            throw new CoseError(`${what}: '${text}' is not a DER UTCTime of the form YYMMDDHHMMSSZ`);

        const year = Number(match[1]);

        return utc(year >= 50 ? 1900 + year : 2000 + year,
                   Number(match[2]), Number(match[3]),
                   Number(match[4]), Number(match[5]), Number(match[6]),
                   text, what);

    }

    if (node.tag === Tag.generalizedTime) {

        const match = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(text);

        if (match === null)
            throw new CoseError(`${what}: '${text}' is not a DER GeneralizedTime of the form YYYYMMDDHHMMSSZ`);

        return utc(Number(match[1]), Number(match[2]), Number(match[3]),
                   Number(match[4]), Number(match[5]), Number(match[6]),
                   text, what);

    }

    throw new CoseError(`${what}: 0x${node.tag.toString(16).padStart(2, '0')} is not a time type`);

}


/**
 * Build a UTC instant, refusing what `Date.UTC` would otherwise roll over.
 *
 * `Date.UTC(2026, 1, 31)` is the 3rd of March and reports no error at all,
 * which is exactly the wrong behaviour for a validity period: a certificate
 * claiming to expire on the 31st of February would silently gain two days.
 */
function utc(year: number, month: number, day: number,
             hour: number, minute: number, second: number,
             text: string, what: string): Date {

    const value = new Date(Date.UTC(year, month - 1, day, hour, minute, second));

    if (value.getUTCFullYear() !== year  || value.getUTCMonth()   !== month - 1 ||
        value.getUTCDate()     !== day   || value.getUTCHours()   !== hour      ||
        value.getUTCMinutes()  !== minute || value.getUTCSeconds() !== second)
        throw new CoseError(`${what}: '${text}' is not a point in time that exists`);

    return value;

}
