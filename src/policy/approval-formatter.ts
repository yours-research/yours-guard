/**
 * Human-readable Approval Prompt Request Formatter for UI confirmation dialogs.
 */

import type { GuardDecision, GuardPolicyContext } from '../contracts.js';
import { unwrapTainted } from '../taint/taint-tracker.js';
import { extractUrlsFromArguments, normalizeOrigin } from './origin-guard.js';

export interface ApprovalPromptRequest {
  verdict: GuardDecision['verdict'];
  title: string;
  /** Plain-language summary of what the agent wants to do. */
  what: string;
  /** Plain-language explanation of why the action was flagged or blocked. */
  why: string;
  toolName: string;
  targetOrigins: string[];
  sanitizedArguments: Record<string, unknown>;
  triggeredRule?: string;
  lethalTrifectaRisk: boolean;
  recommendedUiAction: 'allow_once' | 'allow_origin' | 'block';
  formattedText: string;
}

const TOOL_VERB_MAP: Record<string, string> = {
  fetch_background_tab: 'Fetch an external URL in the background',
  search_web_tab: 'Perform a live web search',
  interact_page: 'Interact with or mutate the active webpage',
  memory_save: 'Write data to persistent local memory',
  memory_recall: 'Query local memory',
  read_active_tab: 'Read the currently active browser tab',
  read_tab: 'Read a browser tab',
  list_tabs: 'List open browser tabs',
  read_document: 'Read an external document',
  run_sandbox: 'Execute code inside the local sandbox',
};

function sanitizeArgPreview(value: unknown, depth = 0): unknown {
  if (depth > 3) return '[truncated]';
  const unwrapped = unwrapTainted(value);
  if (typeof unwrapped === 'string') {
    const clean = unwrapped.replace(/[\u0000-\u001F\u007F]/g, ' ').trim();
    return clean.length > 160 ? `${clean.slice(0, 157)}...` : clean;
  }
  if (Array.isArray(unwrapped)) {
    return unwrapped.slice(0, 10).map((item) => sanitizeArgPreview(item, depth + 1));
  }
  if (typeof unwrapped === 'object' && unwrapped !== null) {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(unwrapped).slice(0, 12)) {
      if (/(?:token|password|secret|authorization|cookie|api[-_]?key)/i.test(k)) {
        out[k] = '[REDACTED]';
      } else {
        out[k] = sanitizeArgPreview(v, depth + 1);
      }
    }
    return out;
  }
  return unwrapped;
}

/**
 * Formats a `GuardPolicyContext` and `GuardDecision` into a clear, human-readable
 * confirmation prompt suitable for Chrome extension / Web UI approval dialogs.
 */
export function formatApprovalPrompt(
  context: GuardPolicyContext,
  decision: GuardDecision,
): ApprovalPromptRequest {
  const urls = extractUrlsFromArguments(context.arguments);
  const originsSet = new Set<string>();
  for (const url of urls) {
    const norm = normalizeOrigin(url);
    if (norm) originsSet.add(norm);
  }
  if (originsSet.size === 0 && context.activeOrigin) {
    const normActive = normalizeOrigin(context.activeOrigin) ?? context.activeOrigin;
    originsSet.add(normActive);
  }

  const targetOrigins = [...originsSet];
  const targetLabel =
    targetOrigins.length > 0 ? targetOrigins.join(', ') : 'local / unspecified origin';

  const verb =
    TOOL_VERB_MAP[context.tool.name] ?? `Invoke tool "${context.tool.name}"`;
  const what = `${verb} (${context.tool.name}) targeting ${targetLabel}.`;

  const lethalTrifectaRisk = Boolean(decision.lethalTrifectaRisk);
  const sanitizedArguments = sanitizeArgPreview(context.arguments) as Record<
    string,
    unknown
  >;

  const title =
    decision.verdict === 'deny'
      ? `Blocked: ${context.tool.name}`
      : decision.verdict === 'require_approval'
        ? lethalTrifectaRisk
          ? `Lethal Trifecta Approval Required: ${context.tool.name}`
          : `Approval Required: ${context.tool.name}`
        : `Allowed: ${context.tool.name}`;

  const recommendedUiAction: ApprovalPromptRequest['recommendedUiAction'] =
    decision.verdict === 'deny'
      ? 'block'
      : lethalTrifectaRisk
        ? 'allow_once'
        : 'allow_origin';

  const lines = [
    title,
    `What: ${what}`,
    `Why: ${decision.reason}`,
    `Target Origin(s): ${targetLabel}`,
    `Lethal Trifecta Risk: ${lethalTrifectaRisk ? 'YES (untrusted content + private state + external/mutation capability)' : 'No'}`,
    `Arguments: ${JSON.stringify(sanitizedArguments)}`,
  ];
  if (decision.triggeredRule) {
    lines.push(`Rule: ${decision.triggeredRule}`);
  }

  return {
    verdict: decision.verdict,
    title,
    what,
    why: decision.reason,
    toolName: context.tool.name,
    targetOrigins,
    sanitizedArguments,
    triggeredRule: decision.triggeredRule,
    lethalTrifectaRisk,
    recommendedUiAction,
    formattedText: lines.join('\n'),
  };
}
