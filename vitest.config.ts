import { defineConfig } from 'vitest/config';

export default defineConfig({
    test: {
        include:     ['tests/**/*.test.ts'],
        environment: 'node',

        // The fuzz suites are property-based and run thousands of cases,
        // which takes seconds rather than milliseconds. The 5 s default is a
        // tripwire that a loaded machine trips and an idle one does not, and
        // a test that fails only under load is worse than a slow one: it
        // reports a timeout with no counterexample, which reads exactly like
        // a real defect.
        testTimeout: 120_000,

        coverage: {
            provider: 'v8',
            reporter: ['text', 'lcov'],
            include:  ['src/**/*.ts'],
            // index.ts is re-exports alone; counting it dilutes the number
            // without guarding anything.
            exclude:  ['src/index.ts'],
        },
    },
});
