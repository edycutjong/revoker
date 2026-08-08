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
        projectService: true,
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
)
