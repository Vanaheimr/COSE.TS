import js       from '@eslint/js';
import globals  from 'globals';
import tseslint from 'typescript-eslint';

export default tseslint.config(

  {
    ignores: [
      'dist/**',
      'docs/api/**',
      'coverage/**',
      '**/node_modules/**',
    ],
  },

  js.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,
  ...tseslint.configs.stylisticTypeChecked,

  {
    languageOptions: {
      globals: { ...globals.node },
      parserOptions: {
        projectService:  true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      '@typescript-eslint/consistent-type-imports': ['error', { fixStyle: 'inline-type-imports' }],
      '@typescript-eslint/no-unnecessary-condition': 'error',
      // A `default` that throws counts as handling the rest: signWith and
      // verifyWith refuse every non-signature family by design — a family
      // added later SHOULD land in that refusal, not force a new case.
      '@typescript-eslint/switch-exhaustiveness-check': ['error', { considerDefaultExhaustiveForUnions: true }],
      'eqeqeq':     ['error', 'always'],
      'no-console': ['error', { allow: ['error', 'warn'] }],
    },
  },

  {
    // Build scripts exist to narrate what they did — printing is the point.
    files: ['scripts/**/*.ts'],
    rules: {
      'no-console': 'off',
    },
  },

  {
    files: ['**/*.js'],
    ...tseslint.configs.disableTypeChecked,
  },

);
