import { defineConfig } from 'tsup';

export default defineConfig({
    entry:      ['src/index.ts'],
    // ESM only, deliberately: every runtime dependency — the @noble family —
    // ships as ESM without a `require` entry, so a `.cjs` build of this
    // package would promise a compatibility its own imports cannot honour.
    // Node that can `require(esm)` (20.19+) loads the ESM build fine.
    format:     ['esm'],
    target:     'es2023',
    platform:   'neutral',
    // Type declarations are emitted by tsc (npm run build:types) rather than
    // by tsup's bundler, which injects the deprecated baseUrl option and so
    // fails on TypeScript 6. Emitting them directly also keeps the
    // declarations a faithful projection of the source rather than a rollup.
    dts:        false,
    sourcemap:  true,
    clean:      true,
    treeshake:  true,
    splitting:  false,
    tsconfig:   'tsconfig.build.json',
});
