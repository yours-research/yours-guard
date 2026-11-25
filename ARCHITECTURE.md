# Architecture — `@yours/guard`

`@yours/guard` is structured as a zero-dependency, pure TypeScript security layer designed to execute identically inside Chrome MV3 service workers, Web Workers, browser pages, and Node.js test environments.

## Design Principles

1. **Zero Cloud & Zero Dynamic Execution:** No external network requests, no `eval()`, and no DOM parser dependency (`DOMParser` / `jsdom` are not required), allowing deterministic execution inside MV3 service workers.
2. **Defense-in-Depth Across Three Layers:**
   - **Ingestion Sanitization (`src/sanitizer/`)** strips concealed instructions before untrusted text enters the LLM context window.
   - **Provenance Taint Tracking (`src/taint/`)** preserves origin metadata and detects exfiltration or memory poisoning across multi-step tool chains.
   - **Capability Policy Firewall (`src/policy/`)** gates every tool call against origin blocklists, taint sinks, and the Lethal Trifecta rule.

---

## 1. Multi-Pass Sanitizer Pipeline (`src/sanitizer/`)

```text
rawInput + sourceUrl
   │
   ├─► Pass 0: sourceUrl #HashJack Check
   │
   ├─► Pass 1: Stack-Based HTML/CSS/SVG Tokenizer (html-sanitizer.ts)
   │      • Strips <!-- comments --> (records comment payload for scoring)
   │      • Strips <script>, <style>, <noscript>, <template>, <iframe>, <object>, <embed>
   │      • Extracts unconditional .class / #id hiding rules from <style> (ignores @media)
   │      • Strips CSS-hidden subtrees (display:none, visibility:hidden, opacity:0,
   │        font-size:<1px, color/bg collisions, text-indent:-9999px, 1px clips, offscreen pos)
   │      • Strips aria-hidden="true", hidden attributes, and <svg> text/metadata/foreignObject
   │      • Inspects href/src/inline URLs for #HashJack prompt fragments
   │
   ├─► Pass 2: Unicode & Control Sanitizer (unicode-sanitizer.ts)
   │      • Strips U+200B..U+200F, U+2060..U+2064, U+FEFF, U+00AD, U+034F, U+180E
   │      • Strips Bidi overrides & isolates (U+202A..U+202E, U+2066..U+2069)
   │      • Decodes & strips Unicode Tag smuggling (U+E0000..U+E007F)
   │
   ├─► Pass 3: Deterministic Heuristic Risk Scorer (risk-scorer.ts)
   │      • Evaluates visible text AND stripped hidden payloads
   │      • Outputs clamped injectionRiskScore ∈ [0..1] + flaggedPatterns[]
   │
   └─► Pass 4: Structural Spotlighting Builder (spotlighting.ts)
          • Escapes breakout tokens ([BEGIN/END UNTRUSTED CONTENT], <|im_start|>, [INST])
          • Wraps cleanText in [BEGIN UNTRUSTED CONTENT id="..." origin="..." tainted="true" risk="..."]
```

---

## 2. Provenance Taint Tracker (`src/taint/`)

`TaintedValue<T>` wraps untrusted or private values alongside deduplicated `TaintProvenance[]` records and extracted substring fingerprints.

- **`deriveTaintedValue` & `concatTainted`:** Propagate upstream origins through string formatting, summarization, and multi-tool pipelines.
- **`TaintTracker.inspectSink(sinkKind, payload)`:** Inspects outgoing arguments for `network_url`, `webhook_query_param`, `clipboard`, `memory_profile_write`, `dom_mutation`, and `sandbox_eval`. For tracked private secrets/data, checks raw, URL-decoded, `encodeURIComponent`, and UTF-8 Base64 encodings to stop encoded exfiltration.

---

## 3. Capability Policy Engine (`src/policy/`)

`evaluatePolicy(context, options)` evaluates rules in strict precedence order:

1. **Dangerous URL Schemes (`deny`):** `javascript:`, `vbscript:`, `data:text/html`, `data:application/xhtml+xml`, `data:image/svg+xml` (immune to allowlists).
2. **Sensitive Origin & Sandbox Guard (`deny`):** `chrome://`, `chrome-extension://`, `edge://`, `about:`, `devtools://`, `view-source:`, `file://`, URL embedded credentials (`user:pass@host`), cloud metadata IPs (`169.254.169.254`), password managers, banking domains, OAuth/SSO endpoints, and localhost credential/secret paths.
3. **#HashJack Outbound URL Check (`deny`):** Rejects outbound URLs carrying prompt injection fragments.
4. **Taint Sink Checks (`deny` / `require_approval`):** Denies private data flowing into network/clipboard sinks and gates untrusted values writing to `memory_save` (`tier: 'profile'`).
5. **Lethal Trifecta Breaker (`deny` / `require_approval` / `allow`):**
   - Active when `contextHasUntrustedContent && sessionAccessedPrivateData`.
   - Any `networkHint`, external navigation, URL with query parameters, or consequential mutation (`consequentialHint` / `!readOnlyHint`):
     - `deny` if an unapproved URL carries suspicious exfiltration query parameters (`secret=`, `token=`, `cookie=`, `data=`, etc.).
     - `require_approval` (`lethalTrifectaRisk: true`) unless all target origins are present in `explicitlyApprovedOrigins`.
6. **Baseline Network & Consequential Gates:** Gates unapproved `networkHint` and `consequentialHint` actions with `require_approval`, while permitting pure `readOnlyHint` / local compute tools on permitted origins (`allow`).
