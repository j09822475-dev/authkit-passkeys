import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

const webcryptoShim = fileURLToPath(
  new URL('./src/core/crypto/webcrypto-shim.node.ts', import.meta.url),
);

export default defineConfig({
  resolve: {
    alias: {
      '#webcrypto-shim': webcryptoShim,
    },
  },
  test: {
    include: ['src/__tests__/**/*.test.ts'],
    environment: 'node',
    globals: false,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov'],
      include: ['src/**/*.ts'],
      exclude: [
        'src/**/index.ts',
        'src/types/**',
        'src/__tests__/**',
        'src/core/crypto/webcrypto-shim.ts',
        'src/core/crypto/webcrypto-shim.node.ts',
      ],
      thresholds: {
        lines: 90,
        functions: 90,
        branches: 80,
        statements: 90,
      },
    },
  },
});
