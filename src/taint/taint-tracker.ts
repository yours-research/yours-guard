/**
 * Provenance Taint Tracker for multi-step browser AI tool chains.
 * Keeps `TaintedValue<T>` provenance envelopes attached across derived strings
 * and detects tainted/private substring flows into sensitive sinks.
 */

import type { CanonicalToolName, ToolExecutionResult } from '../contracts.js';

export type TaintSourceKind =
  | 'web-page'
  | 'document'
  | 'hash-fragment'
  | 'tool-output'
  | 'private-data'
  | 'derived';

export interface TaintProvenance {
  id: string;
  origin: string;
  sourceKind: TaintSourceKind;
  toolName?: CanonicalToolName | string;
  timestampMs: number;
  injectionRiskScore?: number;
}

export interface TaintedValue<T = string> {
  readonly value: T;
  readonly tainted: true;
  readonly provenance: readonly TaintProvenance[];
  readonly fingerprints: readonly string[];
}

export type SensitiveSinkKind =
  | 'network_url'
  | 'webhook_query_param'
  | 'clipboard'
  | 'memory_profile_write'
  | 'dom_mutation'
  | 'sandbox_eval';

export interface TaintFlowReport {
  tainted: boolean;
  hasUntrustedFlow: boolean;
  hasPrivateDataExfil: boolean;
  sinkKind: SensitiveSinkKind;
  matchedProvenance: TaintProvenance[];
  matchedSubstrings: string[];
  riskReason?: string;
}

export interface CreateProvenanceInput {
  id?: string;
  origin: string;
  sourceKind: TaintSourceKind;
  toolName?: CanonicalToolName | string;
  timestampMs?: number;
  injectionRiskScore?: number;
}

interface TrackedFingerprint {
  token: string;
  encodedVariants: string[];
  provenance: TaintProvenance;
  isPrivate: boolean;
}

let nextTaintSeq = 1;

function nextId(prefix = 'taint'): string {
  return `${prefix}-${nextTaintSeq++}`;
}

function toBase64Utf8(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]!);
  }
  return btoa(binary);
}

function safeDecodeURIComponent(value: string): string {
  try {
    return decodeURIComponent(value.replace(/\+/g, ' '));
  } catch {
    return value;
  }
}

function extractFingerprints(value: unknown): string[] {
  if (typeof value !== 'string') {
    if (value !== null && value !== undefined) {
      const serialized = JSON.stringify(value);
      return serialized && serialized.length >= 12 ? [serialized.slice(0, 128)] : [];
    }
    return [];
  }

  const trimmed = value.trim();
  if (trimmed.length < 8) return [];

  const tokens = new Set<string>();

  // Keep full string if reasonably sized
  if (trimmed.length <= 256) {
    tokens.add(trimmed);
  }

  // Extract distinctive long tokens (secrets, identifiers, phrases, URLs)
  const wordMatches = trimmed.match(/[^\s"'`<>]{10,}/g);
  if (wordMatches) {
    for (const w of wordMatches.slice(0, 32)) {
      tokens.add(w);
    }
  }

  // Sliding 32-char chunks for longer prose / payloads
  if (trimmed.length >= 24) {
    for (let i = 0; i <= trimmed.length - 24 && tokens.size < 40; i += 24) {
      const chunk = trimmed.slice(i, i + 24).trim();
      if (chunk.length >= 16) {
        tokens.add(chunk);
      }
    }
  }

  return [...tokens];
}

function dedupeProvenance(list: readonly TaintProvenance[]): TaintProvenance[] {
  const seen = new Map<string, TaintProvenance>();
  for (const item of list) {
    const key = `${item.sourceKind}|${item.origin}|${item.toolName ?? ''}`;
    if (!seen.has(key)) {
      seen.set(key, item);
    }
  }
  return [...seen.values()];
}

/**
 * Type guard checking whether a runtime value is a `TaintedValue<T>` envelope.
 */
export function isTaintedValue<T = unknown>(
  value: unknown,
): value is TaintedValue<T> {
  return (
    typeof value === 'object' &&
    value !== null &&
    (value as Partial<TaintedValue<unknown>>).tainted === true &&
    'value' in value &&
    Array.isArray((value as Partial<TaintedValue<unknown>>).provenance)
  );
}

/**
 * Unwraps a `TaintedValue<T>` or returns a plain value unchanged.
 */
export function unwrapTainted<T>(value: TaintedValue<T> | T): T {
  return isTaintedValue<T>(value) ? value.value : value;
}

/**
 * Wraps a value in a `TaintedValue<T>` provenance envelope.
 */
export function createTaintedValue<T>(
  value: T,
  provenanceInput: CreateProvenanceInput,
): TaintedValue<T> {
  const provenance: TaintProvenance = {
    id: provenanceInput.id ?? nextId(),
    origin: provenanceInput.origin,
    sourceKind: provenanceInput.sourceKind,
    toolName: provenanceInput.toolName,
    timestampMs: provenanceInput.timestampMs ?? Date.now(),
    injectionRiskScore: provenanceInput.injectionRiskScore,
  };

  return {
    value,
    tainted: true,
    provenance: [provenance],
    fingerprints: extractFingerprints(value),
  };
}

/**
 * Propagates taint across derived values (e.g. summaries, extracted fields,
 * template interpolations) while preserving all upstream origins.
 */
export function deriveTaintedValue<T>(
  inputs: ReadonlyArray<TaintedValue<unknown> | unknown>,
  derivedValue: T,
  extraProvenance?: Partial<CreateProvenanceInput>,
): TaintedValue<T> {
  const collected: TaintProvenance[] = [];
  const fingerprints = new Set<string>(extractFingerprints(derivedValue));

  for (const input of inputs) {
    if (isTaintedValue(input)) {
      collected.push(...input.provenance);
      for (const fp of input.fingerprints) {
        fingerprints.add(fp);
      }
    }
  }

  if (extraProvenance?.origin) {
    collected.push({
      id: extraProvenance.id ?? nextId('derived'),
      origin: extraProvenance.origin,
      sourceKind: extraProvenance.sourceKind ?? 'derived',
      toolName: extraProvenance.toolName,
      timestampMs: extraProvenance.timestampMs ?? Date.now(),
      injectionRiskScore: extraProvenance.injectionRiskScore,
    });
  }

  if (collected.length === 0) {
    collected.push({
      id: nextId('derived'),
      origin: 'unknown',
      sourceKind: 'derived',
      timestampMs: Date.now(),
    });
  }

  return {
    value: derivedValue,
    tainted: true,
    provenance: dedupeProvenance(collected),
    fingerprints: [...fingerprints],
  };
}

/**
 * Concatenates string / `TaintedValue<string>` segments, returning a
 * `TaintedValue<string>` if any input segment was tainted.
 */
export function concatTainted(
  parts: ReadonlyArray<TaintedValue<string> | string>,
  separator = '',
): TaintedValue<string> | string {
  const joined = parts.map((p) => unwrapTainted(p)).join(separator);
  const taintedInputs = parts.filter((p) => isTaintedValue(p));
  if (taintedInputs.length === 0) {
    return joined;
  }
  return deriveTaintedValue(taintedInputs, joined);
}

/**
 * Stateful session taint tracker monitoring untrusted origins, private data,
 * and sensitive exfiltration/mutation sinks.
 */
export class TaintTracker {
  private readonly tracked: TrackedFingerprint[] = [];

  trackUntrustedContent(
    value: string,
    provenanceInput: Omit<CreateProvenanceInput, 'sourceKind'> & {
      sourceKind?: TaintSourceKind;
    },
  ): TaintedValue<string> {
    const envelope = createTaintedValue(value, {
      ...provenanceInput,
      sourceKind: provenanceInput.sourceKind ?? 'web-page',
    });
    this.registerFingerprints(envelope.fingerprints, envelope.provenance[0]!, false);
    return envelope;
  }

  trackPrivateData(
    value: string,
    origin: string,
    toolName?: CanonicalToolName | string,
  ): TaintedValue<string> {
    const envelope = createTaintedValue(value, {
      origin,
      sourceKind: 'private-data',
      toolName,
    });
    this.registerFingerprints(envelope.fingerprints, envelope.provenance[0]!, true);
    return envelope;
  }

  registerTaintedEnvelope<T>(envelope: TaintedValue<T>): TaintedValue<T> {
    const isPrivate = envelope.provenance.some((p) => p.sourceKind === 'private-data');
    const primary = envelope.provenance[0] ?? {
      id: nextId(),
      origin: 'unknown',
      sourceKind: 'derived' as const,
      timestampMs: Date.now(),
    };
    this.registerFingerprints(envelope.fingerprints, primary, isPrivate);
    return envelope;
  }

  recordToolResult(result: ToolExecutionResult<unknown>): TaintedValue<string> | null {
    if (!result.tainted) return null;
    const envelope = this.trackUntrustedContent(result.formatted, {
      origin: result.sourceOrigin ?? 'unknown',
      sourceKind: 'tool-output',
      toolName: result.toolName,
    });
    if (typeof result.data === 'string' && result.data.trim().length >= 8) {
      this.registerFingerprints(
        extractFingerprints(result.data),
        envelope.provenance[0]!,
        false,
      );
    }
    return envelope;
  }

  /**
   * Checks whether `payload` (or any nested field) carries a `TaintedValue`
   * envelope or tracked tainted/private substrings into a sensitive sink.
   */
  inspectSink(sinkKind: SensitiveSinkKind, payload: unknown): TaintFlowReport {
    const matchedProvenance: TaintProvenance[] = [];
    const matchedSubstrings = new Set<string>();
    const rawStrings: string[] = [];
    let hasPrivateDataExfil = false;
    let hasUntrustedFlow = false;

    const visit = (node: unknown): void => {
      if (isTaintedValue(node)) {
        for (const prov of node.provenance) {
          matchedProvenance.push(prov);
          if (prov.sourceKind === 'private-data') {
            hasPrivateDataExfil = true;
          } else {
            hasUntrustedFlow = true;
          }
        }
        visit(node.value);
        return;
      }

      if (typeof node === 'string') {
        rawStrings.push(node);
        return;
      }

      if (Array.isArray(node)) {
        for (const item of node) visit(item);
        return;
      }

      if (typeof node === 'object' && node !== null) {
        for (const val of Object.values(node)) {
          visit(val);
        }
      }
    };

    visit(payload);

    // Build searchable candidate texts including URL-decoded representations
    const searchTexts: string[] = [];
    for (const str of rawStrings) {
      searchTexts.push(str);
      const decoded = safeDecodeURIComponent(str);
      if (decoded !== str) searchTexts.push(decoded);
    }

    for (const entry of this.tracked) {
      for (const candidate of searchTexts) {
        const hit =
          candidate.includes(entry.token) ||
          entry.encodedVariants.some((variant) => candidate.includes(variant));
        if (hit) {
          matchedProvenance.push(entry.provenance);
          matchedSubstrings.add(entry.token);
          if (entry.isPrivate) {
            hasPrivateDataExfil = true;
          } else {
            hasUntrustedFlow = true;
          }
        }
      }
    }

    const deduped = dedupeProvenance(matchedProvenance);
    const tainted = deduped.length > 0;

    let riskReason: string | undefined;
    if (tainted) {
      const origins = deduped.map((p) => p.origin).join(', ');
      if (hasPrivateDataExfil) {
        riskReason = `Private data from [${origins}] flowed into sensitive sink "${sinkKind}".`;
      } else {
        riskReason = `Untrusted tainted content from [${origins}] flowed into sensitive sink "${sinkKind}".`;
      }
    }

    return {
      tainted,
      hasUntrustedFlow,
      hasPrivateDataExfil,
      sinkKind,
      matchedProvenance: deduped,
      matchedSubstrings: [...matchedSubstrings],
      riskReason,
    };
  }

  clear(): void {
    this.tracked.length = 0;
  }

  private registerFingerprints(
    fingerprints: readonly string[],
    provenance: TaintProvenance,
    isPrivate: boolean,
  ): void {
    for (const token of fingerprints) {
      if (token.length < 8) continue;
      const encodedVariants: string[] = [];
      const urlEncoded = encodeURIComponent(token);
      if (urlEncoded !== token) encodedVariants.push(urlEncoded);
      if (isPrivate || token.length <= 128) {
        const b64 = toBase64Utf8(token);
        if (b64.length >= 8) encodedVariants.push(b64);
      }

      this.tracked.push({
        token,
        encodedVariants,
        provenance,
        isPrivate,
      });
    }
  }
}
