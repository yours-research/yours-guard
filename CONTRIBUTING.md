# Contributing to `@yours/guard`

Thank you for helping secure local browser AI agents!

## Development Setup

Requirements:
- Node.js `>= 20.0.0`
- npm `>= 10`

```bash
npm install
npm run typecheck
npm run build
npm test
```

## Coding & Security Guidelines

- **Zero External Runtime Dependencies:** Keep `dependencies` empty in `package.json`. Do not introduce Node-only built-ins (`node:fs`, `node:crypto`, `Buffer`) inside `src/` so the library runs cleanly in Chrome MV3 service workers and browsers.
- **Zero External Network Requests:** `@yours/guard` must remain 100% offline and deterministic.
- **Strict TypeScript:** All code must pass `tsc --noEmit` (`strict: true`, `noUncheckedIndexedAccess: true`) and build cleanly with `tsc -p tsconfig.build.json`.
- **Contract Alignment:** Any changes to `SanitizedContent`, `GuardVerdict`, `GuardDecision`, or `GuardPolicyContext` must stay aligned with [docs/ECOSYSTEM_CONTRACTS.md](./docs/ECOSYSTEM_CONTRACTS.md).
- **Red-Team & Benign Regressions:** Every new detection rule or sanitizer pass should include both:
  1. An adversarial fixture in `tests/fixtures/adversarial-corpus.ts`, and
  2. A benign documentation check verifying zero false positives in `tests/fixtures/benign-corpus.ts`.

## Pull Request Checklist

1. Run `npm run typecheck && npm run build && npm test` and verify all checks pass.
2. Keep commits focused and well-scoped.
3. Update `README.md` or `ARCHITECTURE.md` if public APIs or policy rules change.

## License

By contributing, you agree that your contributions will be licensed under the [Apache-2.0 License](./LICENSE).
