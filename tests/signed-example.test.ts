/*
 * Copyright (c) 2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr COSE <https://github.com/Vanaheimr/COSE.TS>
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * The worked signed record of the specification, end to end.
 *
 * These bytes were produced by the C# reference implementation and published
 * in `MetrologicalCBOR/tag-44252-signed-example.md`: one charging transaction,
 * two meter readings with their GUM uncertainties signed by the meter, bundled
 * and signed by the charging station, countersigned by the operator. This
 * implementation never saw them being made.
 *
 * It is the test that ties the two halves of this repository together. A
 * metrological reading encodes to a pure function of its value, unit, prefix
 * and uncertainty, so the same reading always produces the same bytes — and
 * therefore the same signature. If the TypeScript and the C# codecs disagreed
 * about one byte of one reading, the meter's signature would fail here, and it
 * would fail in a way no amount of unit testing on either side would find.
 *
 * The example keys are the specification's own. They secure nothing.
 */

import { describe, expect, it }              from 'vitest';

import { cbor, CoseAlgorithms, CoseCurves,
         CoseKey, CoseSign1, signWith }      from '../src/index.ts';
import { hex, unhex }                        from './vectors.ts';

import { formatMetrologicalValue,
         METROLOGICAL_VALUE_TAG,
         metrologicalValueFromCbor }         from '@vanaheimr/metrological-cbor';


/** Section 6 of `tag-44252-signed-example.md`. */
const SIGNED_RECORD =
    'D28443A10126A204484F4E4267CBA434400B8344A1013822A104486B1F337BA0EC88BB58' +
    '6056AA831918D6215BFE6ABAA02791C8FB619E0C2661F55E8C1F95967A67A02863E1ACC9' +
    'EB090F4A2DD5BE6134380A29D65BA71661A2BA7D337C84C4E4C2C2D87F8925618D0CC7EF' +
    '3E1EBD6D4279B55514A156B4E5315237488B681C20118283175901FFA36F636861726769' +
    '6E6753746174696F6E7244452A4745462A4531323334353637382A316B7472616E736163' +
    '74696F6E6861346631633965326872656164696E67738258DDD28445A101390108A10448' +
    'C6738177A6E6D04B5886A5656D657465726E31495341303030303030303034326B747261' +
    '6E73616374696F6E68613466316339653267636F6E74657874715472616E73616374696F' +
    '6E2E426567696E6474696D65C074323032362D30382D31355430383A31343A30305A6665' +
    '6E65726779D9ACDC84C482221A0012D6870203A401C48220187B020203C48221185F0401' +
    '58406A40B66B6D228217D87F6751D1919BA82CCA959F079EFC98F805BAE4CBC340A3611A' +
    'BAC58B3AA2E1FB51EA85CACB978C03DCF78F407039DA41A2E653A60E138958DBD28445A1' +
    '01390108A10448C6738177A6E6D04B5884A5656D657465726E3149534130303030303030' +
    '3034326B7472616E73616374696F6E68613466316339653267636F6E746578746F547261' +
    '6E73616374696F6E2E456E646474696D65C074323032362D30382D31355430393A30323A' +
    '30305A66656E65726779D9ACDC84C482221A0013395D0203A401C48220187E020203C482' +
    '21185F040158401D92018570E22306441FDD0E1645124C03F63CDE0D75A154B7ECD78411' +
    '2020F25834508FD5D9A6A016025A85B8BD7F5DF27056B33EDFC7A823E55449061562CC58' +
    '40C521E083F44F35D056F5B6F75893B7B2AD8E32CFB2F60DFEAA405466083C16267C6E92' +
    '56110BDBD204D81878E195A9E4BE644FE034BC7A640A42F82CC931AA2E';


/** Section 7 of the specification. */
const KEYS = {
    meter: CoseKey.fromPrivateScalar(
        CoseCurves.brainpoolP256r1,
        unhex('08F001BB03BEF4FBD1C59F10B50555CD37D2B53421331DBFA98815A581326FB3'),
        { algorithm: CoseAlgorithms.ESB256 }),
    station: CoseKey.fromPrivateScalar(
        CoseCurves.P256,
        unhex('875E51ECF18073E8B970E6DCC5A115433456E13DF966034A5A782945D2B684D3'),
        { algorithm: CoseAlgorithms.ES256 }),
    operator: CoseKey.fromPrivateScalar(
        CoseCurves.P384,
        unhex('6952487A0A16EACE6E9A69EFD062D7671D68D23FF68722326348827C3A94E2A1' +
              '743A1DF8901B948412CCA26CA4372CED'),
        { algorithm: CoseAlgorithms.ES384 }),
} as const;

/** The key identifiers the record names, which are RFC 9679 thumbprints. */
const KEY_IDENTIFIERS = {
    meter:    'C6738177A6E6D04B',
    station:  '4F4E4267CBA43440',
    operator: '6B1F337BA0EC88BB',
} as const;


const record = CoseSign1.parse(unhex(SIGNED_RECORD));


/** The meter's readings, each a COSE_Sign1 of its own. */
function readings(): CoseSign1[] {

    const payload = cbor.decode(record.payload!, { strict: false });

    if (payload.type !== 'map')
        throw new Error('the station payload is not a map');

    const found = payload.entries.find(([key]) => key.type === 'text' && key.value === 'readings')?.[1];

    if (found?.type !== 'array')
        throw new Error('the station payload has no readings');

    return found.items.map(item => {

        if (item.type !== 'bytes')
            throw new Error('a reading is not a byte string');

        return CoseSign1.parse(item.value);

    });

}


describe('the signed record of the specification', () => {

    it('is a 713-byte COSE_Sign1 signed by the charging station', () => {

        expect(unhex(SIGNED_RECORD)).toHaveLength(713);
        expect(record.isTagged).toBe(true);
        expect(record.algorithm?.name).toBe('ES256');
        expect(hex(record.keyIdentifier!)).toBe(KEY_IDENTIFIERS.station);

    });

    it('verifies against the station key', () => {
        expect(record.verify(KEYS.station.publicKey())).toStrictEqual({ verified: true });
    });

    it('is reproduced byte for byte by signing the structure this library builds', () => {

        // The stronger claim. RFC 6979 makes the signature a function of what
        // it signs, so if this library assembled a Sig_structure differing from
        // the signer's by a single byte, this signature would differ entirely.
        const again = signWith(CoseAlgorithms.ES256,
                               CoseCurves.P256,
                               record.toBeSigned(),
                               KEYS.station.privateKeyBytes());

        expect(hex(again)).toBe(hex(record.signature));

    });

    it('re-encodes to the very bytes it was read from', () => {
        expect(hex(record.toBytes())).toBe(SIGNED_RECORD.toUpperCase());
    });

});


describe('the meter readings inside it', () => {

    const meterReadings = readings();

    it('are two COSE_Sign1 messages on brainpoolP256r1', () => {

        expect(meterReadings).toHaveLength(2);

        for (const reading of meterReadings) {
            expect(reading.algorithm?.name).toBe('ESB256');
            expect(hex(reading.keyIdentifier!)).toBe(KEY_IDENTIFIERS.meter);
        }

    });

    it('each verify against the meter key', () => {

        for (const reading of meterReadings)
            expect(reading.verify(KEYS.meter.publicKey())).toStrictEqual({ verified: true });

    });

    it('are each reproduced byte for byte', () => {

        for (const reading of meterReadings) {

            const again = signWith(CoseAlgorithms.ESB256,
                                   CoseCurves.brainpoolP256r1,
                                   reading.toBeSigned(),
                                   KEYS.meter.privateKeyBytes());

            expect(hex(again)).toBe(hex(reading.signature));

        }

    });

    it('carry the metrological values the specification prints', () => {

        const stated: string[] = [];

        for (const reading of meterReadings) {

            cbor.walk(cbor.decode(reading.payload!, { strict: false }), value => {
                if (cbor.isTagged(value, METROLOGICAL_VALUE_TAG))
                    stated.push(formatMetrologicalValue(metrologicalValueFromCbor(value, { strict: false })));
            });

        }

        // Read by this library out of the very bytes the meter's signature
        // covers — which is the whole point of signing a metrological value.
        // Section 4 of the example document prints the same two readings.
        expect(stated).toStrictEqual([
            '(1234.567 ±12.3) kWh, k=2, p=0.95, dist=normal',
            '(1259.869 ±12.6) kWh, k=2, p=0.95, dist=normal',
        ]);

    });

});


describe('the operator countersignature', () => {

    it('vouches for the station signature without changing it', () => {

        expect(record.countersignatures).toHaveLength(1);

        const countersignature = record.countersignatures[0]!;

        expect(countersignature.algorithm?.name).toBe('ES384');
        expect(hex(countersignature.keyIdentifier!)).toBe(KEY_IDENTIFIERS.operator);

        expect(record.verifyCountersignature(countersignature,
                                             KEYS.operator.publicKey())).toStrictEqual({ verified: true });

    });

    it('is not accepted with the wrong party\'s key', () => {

        expect(record.verifyCountersignature(record.countersignatures[0]!,
                                             KEYS.station.publicKey()).verified).toBe(false);

    });

});


describe('the key identifiers of the record', () => {

    it('are the leading bytes of each key\'s RFC 9679 thumbprint', () => {

        // Everyone holding the public key can recompute the identifier, so no
        // registry is needed beyond an agreement on its length.
        for (const [party, stated] of Object.entries(KEY_IDENTIFIERS))
            expect(hex(KEYS[party as keyof typeof KEYS].thumbprintKeyIdentifier(8))).toBe(stated);

    });

    it('are the same for the public and the private half of a key', () => {

        for (const key of Object.values(KEYS))
            expect(hex(key.thumbprint())).toBe(hex(key.publicKey().thumbprint()));

    });

});
