import js from '@eslint/js'
import tseslint from 'typescript-eslint'

export default tseslint.config(
  {
    ignores: [
      'node_modules/**',
      'contracts/out/**',
      'contracts/cache/**',
      'contracts/lib/**',
      'audit/**',
      'coverage/**',
      'public/**',
      // Config itself is outside the TS project; linting it type-aware would
      // require adding it to tsconfig, which would then typecheck it as source.
      'eslint.config.js',
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        projectService: {
          // playwright.config.ts belongs to e2e/tsconfig.json, but the project
          // service resolves from the nearest tsconfig — which is the root one,
          // and that deliberately covers Node sources only. Allow it as a
          // default-project file so it is still linted, rather than adding it to
          // `ignores` and leaving a config file unchecked.
          allowDefaultProject: ['playwright.config.ts'],
        },
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      // Unused args are meaningful in interface implementations; allow the
      // conventional underscore opt-out rather than deleting the parameter.
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],
      // The KeeperHub API is untyped at the boundary. We cast once, deliberately,
      // inside the client — flagging every such cast would train us to ignore it.
      '@typescript-eslint/no-unsafe-assignment': 'off',
      '@typescript-eslint/no-unsafe-member-access': 'off',
      '@typescript-eslint/no-unsafe-argument': 'off',
      // Float-vs-void is a real bug class in an agent that must not drop a
      // pending revoke. Keep it, but allow explicit `void` marking.
      '@typescript-eslint/no-floating-promises': 'error',
    },
  },
  {
    // Scripts are operator tools: printing is the point.
    files: ['scripts/**/*.ts'],
    rules: { 'no-console': 'off' },
  },
  {
    // starter/ is a standalone template: no tsconfig, no dependencies, meant to
    // be copied out of this repo and run. Type-aware rules cannot resolve it,
    // so lint it as plain JS rather than excluding it — it ships to users.
    files: ['starter/**/*.mjs'],
    ...tseslint.configs.disableTypeChecked,
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: 'module',
      // Explicitly OFF. Flat config merges the earlier project-wide block into
      // this one, so projectService stays enabled unless it is turned off here —
      // and it cannot resolve a file that has no tsconfig.
      parserOptions: { projectService: false, project: null },
      globals: { process: 'readonly', console: 'readonly', fetch: 'readonly', setTimeout: 'readonly' },
    },
    rules: {
      // Spread FIRST: a bare `rules` object replaces disableTypeChecked's
      // rules rather than merging with them, which leaves the type-aware rules
      // active on a file that has no type information.
      ...tseslint.configs.disableTypeChecked.rules,
      'no-console': 'off',
      'no-empty': 'off',
    },
  },
)
