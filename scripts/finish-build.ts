/*
 * Copyright (c) 2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr COSE <https://github.com/Vanaheimr/COSE.TS>
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Tidies what the bundler leaves behind.
 *
 * tsup writes the `sourceMappingURL` comment twice — once itself and once
 * through esbuild — so the bundle ends with the same line repeated. Nothing
 * breaks: a browser and every tool that reads source maps take the last one,
 * and the two are identical. It is still wrong in an artifact that goes to a
 * registry and stays there, and a reader who notices it learns something false
 * about how carefully the thing was assembled.
 *
 * `tests/bundle.test.ts` asserts the result, so this cannot quietly stop
 * working.
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve }            from 'node:path';
import { fileURLToPath }               from 'node:url';

const dist = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'dist');

/** `//# sourceMappingURL=…` at the very end, however many times it appears. */
const TRAILING_MAP_COMMENTS = /(?:\s*\/\/# sourceMappingURL=[^\n]*)+\s*$/;

for (const file of ['index.js']) {

    const path   = resolve(dist, file);
    const source = readFileSync(path, 'utf8');
    const match  = TRAILING_MAP_COMMENTS.exec(source);

    if (match === null) {
        console.log(`${file}: no source map comment`);
        continue;
    }

    const comments = match[0].trim().split(/\s*\n\s*/);
    const kept     = comments.at(-1) ?? '';
    const tidied   = `${source.slice(0, match.index)}\n${kept}\n`;

    if (tidied === source) {
        console.log(`${file}: one source map comment`);
        continue;
    }

    writeFileSync(path, tidied, 'utf8');
    console.log(`${file}: ${String(comments.length)} source map comments, kept one`);

}
