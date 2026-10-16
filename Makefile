.DEFAULT_GOAL := help
.PHONY: help env/init env/sync test test/target lint format build spec/sync spec/check clean __require_target__

help:
	@echo 'auditable-a2a-sdk (TypeScript) — development commands'
	@echo ''
	@echo '  make env/init      Install dependencies (npm ci if a lockfile exists, else npm install)'
	@echo '  make env/sync      Reinstall dependencies from package.json'
	@echo ''
	@echo '  make test          Run the test suite (unit + conformance vectors)'
	@echo '  make test/target   Run a specific test (TARGET=tests/verify.test.ts)'
	@echo '  make lint          biome check + tsc --noEmit'
	@echo '  make format        biome check --write (format + safe fixes)'
	@echo '  make build         Bundle ESM + type declarations to dist/'
	@echo ''
	@echo '  make spec/check    Fail if the vendored spec/ drifted from its source'
	@echo '  make spec/sync     Re-vendor spec/ from ../auditable-a2a/spec'
	@echo ''
	@echo '  make clean         Remove caches and build artifacts'

# Environment: Node is pinned via .nvmrc / volta; npm is the installer.
env/init:
	@if [ -f package-lock.json ]; then npm ci; else npm install; fi
	@echo '✅ Environment ready'

env/sync:
	npm install

test:
	npx vitest run 2>&1

test/target: __require_target__
	npx vitest run $(TARGET) 2>&1

lint:
	npx biome check . 2>&1 && npx tsc --noEmit 2>&1

format:
	npx biome check --write . 2>&1

build:
	npx tsup 2>&1

# Vendored spec integrity: the conformance vectors must reproduce byte-for-byte (spec §12).
spec/check:
	npx tsx scripts/sync-spec.ts --check 2>&1

spec/sync:
	npx tsx scripts/sync-spec.ts 2>&1

clean:
	rm -rf dist coverage node_modules/.cache *.tsbuildinfo

__require_target__:
	@[ -n "$(TARGET)" ] || (echo "[ERROR] Parameter [TARGET] is required" 1>&2 && echo "(e.g) make test/target TARGET=tests/verify.test.ts" 1>&2 && exit 1)
