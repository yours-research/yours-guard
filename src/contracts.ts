/**
 * Shared TypeScript contracts for `@yours/guard` implementing
 * Yours Research Ecosystem Architecture & Shared TypeScript Contracts (v1.0).
 */

export type CanonicalToolName =
  | 'read_active_tab'
  | 'list_tabs'
  | 'read_tab'
  | 'interact_page'
  | 'run_sandbox'
  | 'read_document'
  | 'search_web_tab'
  | 'fetch_background_tab'
  | 'memory_recall'
  | 'memory_save';

export interface ToolSafetyHints {
  /** True for pure reads/compute; false for state mutations. */
  readOnlyHint: boolean;
  /** True for form submit, click/type side-effects, memory writes, external requests. */
  consequentialHint: boolean;
  /** True only if live internet navigation/search is invoked. */
  networkHint: boolean;
  /** True when output embeds external/DOM/PDF text (requires IDPI spotlighting). */
  untrustedContentHint: boolean;
}

export interface ToolDefinition {
  name: CanonicalToolName;
  aliases?: string[];
  description: string;
  parameters: {
    type: 'object';
    properties: Record<string, unknown>;
    required?: string[];
    additionalProperties?: false;
  };
  safety: ToolSafetyHints;
}

export interface ToolInvocationContext {
  environment: 'chrome-mv3' | 'web-demo' | 'node-test';
  sessionId: string;
  origin?: string;
  abortSignal?: AbortSignal;
}

export interface ToolExecutionResult<TData = unknown> {
  ok: boolean;
  toolName: CanonicalToolName;
  data?: TData;
  formatted: string;
  /** Propagated to @yours/guard. */
  tainted: boolean;
  sourceOrigin?: string;
  error?: string;
  needsPermission?: boolean;
  requiresApproval?: boolean;
  blockedByCaptcha?: boolean;
  manualUrl?: string;
}

export interface SanitizedContent {
  cleanText: string;
  spotlightedPromptBlock: string;
  /** e.g., ['hidden-css', 'zero-width-unicode', 'svg-foreign-text', 'hashjack'] */
  strippedSignals: string[];
  /** Heuristic IDPI risk score clamped to [0..1]. */
  injectionRiskScore: number;
  flaggedPatterns: string[];
  tainted: true;
}

export type GuardVerdict = 'allow' | 'require_approval' | 'deny';

export interface GuardDecision {
  verdict: GuardVerdict;
  reason: string;
  triggeredRule?: string;
  lethalTrifectaRisk?: boolean;
}

export interface GuardPolicyContext {
  tool: ToolDefinition;
  arguments: Record<string, unknown>;
  contextHasUntrustedContent: boolean;
  sessionAccessedPrivateData: boolean;
  activeOrigin?: string;
  explicitlyApprovedOrigins?: string[];
}
