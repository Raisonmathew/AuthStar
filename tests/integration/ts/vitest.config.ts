import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    testTimeout: 30_000,
    hookTimeout: 15_000,
    // Run suites serially — they share one backend and a single admin session
    // so parallel execution would cause race conditions on seeded data.
    pool: 'forks',
    poolOptions: { forks: { singleFork: true } },
  },
});
