/*
 * Copyright (c) 2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr COSE <https://github.com/Vanaheimr/COSE.TS>
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * The library, in a browser.
 *
 * "Runs in a browser" is usually a claim rather than a test, and a library
 * acquires a Node dependency the way it acquires a float: one convenient call
 * at a time, in a file nobody re-reads. Rather than start a headless browser
 * to find that out, this bundles `src/index.ts` for the browser platform —
 * where esbuild refuses `node:*` outright, in this package and in every
 * dependency — and runs the result in a V8 context that has *no* Node globals
 * at all: no `process`, no `require`, no `Buffer`, no `__dirname`, and only
 * the globals a browser actually provides.
 *
 * That is a stricter environment than a browser, not a looser one: anything
 * that passes here would pass there, and the usual failure mode (a `Buffer`
 * that happened to be in scope) cannot hide.
 *
 * The bundle is built here from source rather than read from `dist/`, so the
 * guard holds on every test run and not only after `npm run build`. What is
 * checked against `dist/` — and therefore skips where `dist/` is absent — is
 * the one invariant `scripts/finish-build.ts` maintains: a single
 * `sourceMappingURL` comment at the end of the published bundle.
 */

import { createContext, runInContext }  from 'node:vm';
import { existsSync, readFileSync }     from 'node:fs';
import { dirname, resolve }             from 'node:path';
import { fileURLToPath }                from 'node:url';

import { buildSync }                    from 'esbuild';
import { beforeAll, describe, expect, it } from 'vitest';


const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');


/** The whole dependency graph, bundled as a browser would receive it. */
function browserBundle(): string {

    const result = buildSync({
        absWorkingDir:  root,
        entryPoints:    ['src/index.ts'],
        bundle:         true,
        platform:       'browser',
        format:         'cjs',
        target:         'es2023',
        write:          false,
        logLevel:       'silent',
    });

    const output = result.outputFiles[0];

    if (output === undefined)
        throw new Error('esbuild produced no output!');

    return output.text;

}


/** The bundle, loaded into a context holding only what a browser guarantees. */
function inABrowser(): Record<string, unknown> {

    const sandbox: Record<string, unknown> = {
        // What a browser has, and this library may use.
        TextEncoder,
        TextDecoder,
        Uint8Array,
        DataView,
        ArrayBuffer,
        BigInt,
        Math,
        JSON,
        Object,
        Array,
        String,
        Number,
        Boolean,
        Error,
        TypeError,
        RangeError,
        Map,
        Set,
        Symbol,
        Reflect,
        Proxy,
        RegExp,
        Function,
        Promise,
        Intl,
        // Filled in below: a sandbox has to be able to refer to itself.
        globalThis: undefined,

        // What it is being loaded as.
        module:  { exports: {} },
        exports: {},
    };

    sandbox['globalThis'] = sandbox;

    const context = createContext(sandbox);

    runInContext(browserBundle(), context, { filename: 'cose.browser.cjs' });

    // Everything below runs *inside* the context, so that every byte string
    // is a native of that realm rather than a tourist from this one, and only
    // primitives cross back.
    const exercise = (code: string): unknown =>
        runInContext(
            `(() => {
                const cose  = { ...exports, ...module.exports };
                const hex   = (u8) => Array.from(u8).map(b => b.toString(16).padStart(2, '0')).join('');
                const bytes = (h)  => new Uint8Array((h.match(/../g) ?? []).map(x => parseInt(x, 16)));
                return (${code});
            })()`,
            context);

    return {
        exercise,
        ...(sandbox['exports'] as Record<string, unknown>),
        ...((sandbox['module'] as { exports: Record<string, unknown> }).exports),
    };

}


describe('the bundle, with no Node global in sight', () => {

    let library: Record<string, unknown>;
    let exercise: (code: string) => unknown;

    beforeAll(() => {
        library  = inABrowser();
        exercise = library['exercise'] as (code: string) => unknown;
    });

    it('loads at all', () => {

        // If the bundle reaches for `process`, `require` or `Buffer` at load
        // time, `beforeAll` is where it throws — and the message names what
        // it wanted. This spells out that the load produced the library.
        expect(typeof library['CoseSign1']).toBe('function');
        expect(typeof library['CoseKey']).toBe('function');
        expect(typeof library['signWith']).toBe('function');

    });

    it('computes the digests', () => {
        expect(exercise(`hex(cose.digest('sha256', bytes('')))`))
            .toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    });

    it('computes the HMAC of RFC 4231, test case 2', () => {
        expect(exercise(
            `hex(cose.hmac('sha256', new TextEncoder().encode('Jefe'),
                           new TextEncoder().encode('what do ya want for nothing?')))`))
            .toBe('5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843');
    });

    it('wraps the key of RFC 3394, Section 4.1', () => {
        expect(exercise(
            `hex(cose.aesKeyWrap(bytes('000102030405060708090a0b0c0d0e0f'),
                                 bytes('00112233445566778899aabbccddeeff')))`))
            .toBe('1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5');
    });

    it('encrypts, decrypts, and refuses damage', () => {
        expect(exercise(
            `(() => {
                const key       = bytes('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
                const nonce     = bytes('000102030405060708090a0b');
                const aad       = new TextEncoder().encode('Enc_structure');
                const plaintext = new TextEncoder().encode('a reading worth signing');
                const sealed    = cose.aesGcmEncrypt(key, nonce, plaintext, aad);
                const opened    = cose.aesGcmDecrypt(key, nonce, sealed, aad);
                const damaged   = sealed.slice(); damaged[0] ^= 0x01;
                return hex(opened) === hex(plaintext)
                    && cose.aesGcmDecrypt(key, nonce, damaged, aad) === null;
            })()`))
            .toBe(true);
    });

});


describe.runIf(existsSync(resolve(root, 'dist', 'index.js')))('the published bundle', () => {

    it('ends with exactly one source map comment', () => {

        const source  = readFileSync(resolve(root, 'dist', 'index.js'), 'utf8');
        const matches = source.match(/\/\/# sourceMappingURL=/g) ?? [];

        expect(matches).toHaveLength(1);
        expect(source.trimEnd().split('\n').at(-1)).toMatch(/^\/\/# sourceMappingURL=index\.js\.map$/);

    });

});
