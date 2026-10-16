import { defineConfig } from 'tsup';

// The core barrel (`.`) stays runtime-agnostic; integrations with an A2A SDK ship as separate entry
// points so a consumer that does not use one never pulls it into its bundle.
export default defineConfig({
  entry: {
    index: 'src/index.ts',
    'a2a/index': 'src/a2a/index.ts',
  },
  format: ['esm'],
  target: 'es2023',
  dts: true,
  clean: true,
  sourcemap: true,
  treeshake: true,
});
