/**
 * Capability Policy Engine & Lethal Trifecta Breaker.
 * Evaluates `GuardPolicyContext` -> `GuardDecision` (`allow | require_approval | deny`).
 */

import type { GuardDecision, GuardPolicyContext } from '../contracts.js';
import { inspectAndStripHashJack } from '../sanitizer/html-sanitizer.js';
import {
  TaintTracker,
  isTaintedValue,
  type SensitiveSinkKind,
} from '../taint/taint-tracker.js';
import {
  formatApprovalPrompt,
  type ApprovalPromptRequest,
} from './approval-formatter.js';
import {
  extractUrlsFromArguments,
  inspectOriginSafety,
  normalizeOrigin,
  type OriginGuardOptions,
} from './origin-guard.js';

export interface PolicyEngineOptions extends OriginGuardOptions {
  /** Optional stateful TaintTracker to inspect argument sink flows. */
  taintTracker?: TaintTracker;
}

const SUSPICIOUS_EXFIL_PARAM_REGEX =
  /[?&](?:data|secret|secrets|token|cookie|cookies|session|exfil|leak|password|pwd|key|apikey|api_key|payload|dump|body|private)=/i;

function isOriginExplicitlyApproved(
  originOrUrl: string,
  approvedList?: readonly string[],
): boolean {
  if (!approvedList || approvedList.length === 0) return false;
  const targetOrigin = normalizeOrigin(originOrUrl) ?? originOrUrl.toLowerCase();
  for (const approved of approvedList) {
    if (approved === '*') return true;
    const normApproved = normalizeOrigin(approved) ?? approved.toLowerCase();
    if (targetOrigin === normApproved) return true;
  }
  return false;
}

function hasQueryParams(urlString: string): boolean {
  try {
    const parsed = new URL(urlString);
    return parsed.search.length > 1;
  } catch {
    return /\?[^=]+=/.test(urlString);
  }
}

function resolveRelevantSinkKind(context: GuardPolicyContext): SensitiveSinkKind | null {
  if (context.tool.safety.networkHint) {
    const urls = extractUrlsFromArguments(context.arguments);
    if (urls.some(hasQueryParams)) {
      return 'webhook_query_param';
    }
    return 'network_url';
  }
  if (context.tool.name === 'memory_save') {
    const tier = context.arguments.tier;
    if (tier === undefined || tier === 'profile') {
      return 'memory_profile_write';
    }
  }
  if (context.tool.name === 'interact_page') {
    const action = String(context.arguments.action ?? '').toLowerCase();
    if (action.includes('clipboard') || action.includes('copy')) {
      return 'clipboard';
    }
    return 'dom_mutation';
  }
  if (context.tool.name === 'run_sandbox') {
    return 'sandbox_eval';
  }
  return null;
}

function containsTaintedEnvelope(value: unknown): boolean {
  if (isTaintedValue(value)) return true;
  if (Array.isArray(value)) return value.some(containsTaintedEnvelope);
  if (typeof value === 'object' && value !== null) {
    return Object.values(value).some(containsTaintedEnvelope);
  }
  return false;
}

/**
 * Evaluates a tool invocation against the Sensitive Origin Blocklist,
 * Taint Sink rules, and the Lethal Trifecta Breaker.
 */
export function evaluatePolicy(
  context: GuardPolicyContext,
  options: PolicyEngineOptions = {},
): GuardDecision {
  const isLethalTrifecta =
    context.contextHasUntrustedContent && context.sessionAccessedPrivateData;

  const targetUrls = extractUrlsFromArguments(context.arguments);
  const allCandidateOrigins = [...targetUrls];
  if (context.activeOrigin) {
    allCandidateOrigins.push(context.activeOrigin);
  }

  // 1. Sensitive Origin Blocklist & Dangerous URL Scheme Guard
  for (const candidate of allCandidateOrigins) {
    const safety = inspectOriginSafety(candidate, options);
    if (!safety.allowed) {
      return {
        verdict: 'deny',
        reason: safety.reason ?? `Access to "${candidate}" is blocked by policy.`,
        triggeredRule: safety.triggeredRule ?? 'sensitive-origin-blocklist',
        lethalTrifectaRisk: isLethalTrifecta,
      };
    }
  }

  // 2. Reject #HashJack URL payloads in outbound navigations/fetches
  for (const url of targetUrls) {
    const hashCheck = inspectAndStripHashJack(url);
    if (hashCheck.hashJackDetected) {
      return {
        verdict: 'deny',
        reason: `Blocked URL containing suspicious #HashJack prompt injection fragment.`,
        triggeredRule: 'hashjack-url-blocked',
        lethalTrifectaRisk: isLethalTrifecta,
      };
    }
  }

  // 3. Taint Flow Sink Inspection (private exfiltration or tainted memory poisoning)
  const sinkKind = resolveRelevantSinkKind(context);
  if (sinkKind && options.taintTracker) {
    const flow = options.taintTracker.inspectSink(sinkKind, context.arguments);
    if (flow.tainted) {
      if (
        flow.hasPrivateDataExfil &&
        (sinkKind === 'network_url' ||
          sinkKind === 'webhook_query_param' ||
          sinkKind === 'clipboard')
      ) {
        return {
          verdict: 'deny',
          reason:
            flow.riskReason ??
            `Blocked attempted exfiltration of private data into "${sinkKind}".`,
          triggeredRule: 'taint-exfiltration-blocked',
          lethalTrifectaRisk: isLethalTrifecta,
        };
      }

      if (flow.hasUntrustedFlow && sinkKind === 'memory_profile_write') {
        const highRisk = flow.matchedProvenance.some(
          (p) => (p.injectionRiskScore ?? 0) >= 0.5,
        );
        if (highRisk) {
          return {
            verdict: 'deny',
            reason:
              flow.riskReason ??
              'Blocked high-risk untrusted content from poisoning profile memory.',
            triggeredRule: 'tainted-memory-profile-poisoning',
            lethalTrifectaRisk: isLethalTrifecta,
          };
        }
        return {
          verdict: 'require_approval',
          reason:
            flow.riskReason ??
            'Untrusted tainted content cannot write to profile memory without user approval.',
          triggeredRule: 'tainted-memory-profile-write',
          lethalTrifectaRisk: isLethalTrifecta,
        };
      }
    }
  }

  // Also detect direct TaintedValue<T> envelopes on memory_save(profile) without tracker
  if (
    context.tool.name === 'memory_save' &&
    (context.arguments.tier === undefined || context.arguments.tier === 'profile') &&
    containsTaintedEnvelope(context.arguments)
  ) {
    return {
      verdict: 'require_approval',
      reason:
        'Tainted untrusted value requires explicit user approval before writing to profile memory.',
      triggeredRule: 'tainted-memory-profile-write',
      lethalTrifectaRisk: isLethalTrifecta,
    };
  }

  // Compute approval status for target origins (or activeOrigin if no external URLs)
  const targetOrigins = targetUrls
    .map((u) => normalizeOrigin(u) ?? u)
    .filter((v, idx, arr) => arr.indexOf(v) === idx);
  const activeNorm = context.activeOrigin
    ? (normalizeOrigin(context.activeOrigin) ?? context.activeOrigin.toLowerCase())
    : undefined;

  const originsToApprove =
    targetOrigins.length > 0 ? targetOrigins : activeNorm ? [activeNorm] : [];

  const allApproved =
    originsToApprove.length > 0 &&
    originsToApprove.every((orig) =>
      isOriginExplicitlyApproved(orig, context.explicitlyApprovedOrigins),
    );

  const hasExternalNavigation =
    targetOrigins.length > 0 &&
    (!activeNorm || targetOrigins.some((orig) => orig !== activeNorm));

  const hasExternalUrlWithParams =
    targetUrls.some(hasQueryParams) &&
    (!activeNorm ||
      targetUrls.some(
        (u) => hasQueryParams(u) && (normalizeOrigin(u) ?? u) !== activeNorm,
      ));

  const isConsequentialMutation =
    context.tool.safety.consequentialHint || !context.tool.safety.readOnlyHint;

  // 4. The "Lethal Trifecta" Rule
  if (isLethalTrifecta) {
    const triggersTrifecta =
      context.tool.safety.networkHint ||
      hasExternalNavigation ||
      hasExternalUrlWithParams ||
      isConsequentialMutation;

    if (triggersTrifecta) {
      // Unapproved URL with suspicious exfil query params under Lethal Trifecta -> hard deny
      if (
        !allApproved &&
        targetUrls.some((u) => SUSPICIOUS_EXFIL_PARAM_REGEX.test(u))
      ) {
        return {
          verdict: 'deny',
          reason:
            'Lethal Trifecta violation: blocked external URL with suspicious exfiltration parameters while session has untrusted content and private state.',
          triggeredRule: 'lethal-trifecta-exfil-blocked',
          lethalTrifectaRisk: true,
        };
      }

      if (!allApproved) {
        const triggeredRule = context.tool.safety.networkHint
          ? 'lethal-trifecta-network'
          : hasExternalNavigation || hasExternalUrlWithParams
            ? 'lethal-trifecta-navigation'
            : 'lethal-trifecta-mutation';

        return {
          verdict: 'require_approval',
          reason:
            `Lethal Trifecta triggered: session has read untrusted content and accessed private state; "${context.tool.name}" requires explicit user approval for ${originsToApprove.join(', ') || 'this target'}.`,
          triggeredRule,
          lethalTrifectaRisk: true,
        };
      }

      return {
        verdict: 'allow',
        reason: `Permitted under Lethal Trifecta because target origin(s) [${originsToApprove.join(', ')}] were explicitly approved by the user.`,
        triggeredRule: 'explicitly-approved-origin',
        lethalTrifectaRisk: false,
      };
    }
  }

  // 5. Baseline Network Request Gate
  if (context.tool.safety.networkHint) {
    if (allApproved) {
      return {
        verdict: 'allow',
        reason: `Network capability "${context.tool.name}" permitted for explicitly approved origin(s) [${originsToApprove.join(', ')}].`,
        triggeredRule: 'explicitly-approved-origin',
        lethalTrifectaRisk: false,
      };
    }

    return {
      verdict: 'require_approval',
      reason: `Network tool "${context.tool.name}" requires explicit origin approval before making external requests.`,
      triggeredRule: 'network-approval-required',
      lethalTrifectaRisk: false,
    };
  }

  // 6. Baseline Consequential Mutation Gate
  if (isConsequentialMutation) {
    if (allApproved) {
      return {
        verdict: 'allow',
        reason: `Consequential action "${context.tool.name}" permitted on explicitly approved origin [${originsToApprove.join(', ')}].`,
        triggeredRule: 'explicitly-approved-origin',
        lethalTrifectaRisk: false,
      };
    }

    return {
      verdict: 'require_approval',
      reason: context.contextHasUntrustedContent
        ? `Consequential action "${context.tool.name}" requires user approval while untrusted content is in context.`
        : `Consequential action "${context.tool.name}" requires user approval for unapproved origin.`,
      triggeredRule: context.contextHasUntrustedContent
        ? 'untrusted-context-consequential-action'
        : 'consequential-action-approval',
      lethalTrifectaRisk: false,
    };
  }

  // 7. Read-only / local compute tools on permitted origins
  return {
    verdict: 'allow',
    reason: `Read-only or local compute tool "${context.tool.name}" permitted.`,
    triggeredRule: 'read-only-allowed',
    lethalTrifectaRisk: false,
  };
}

/**
 * High-level stateful firewall combining policy evaluation, taint tracking,
 * and UI approval prompt formatting.
 */
export class GuardFirewall {
  readonly taintTracker: TaintTracker;
  private readonly options: Omit<PolicyEngineOptions, 'taintTracker'>;

  constructor(options: Omit<PolicyEngineOptions, 'taintTracker'> = {}) {
    this.taintTracker = new TaintTracker();
    this.options = options;
  }

  evaluate(context: GuardPolicyContext): GuardDecision {
    return evaluatePolicy(context, {
      ...this.options,
      taintTracker: this.taintTracker,
    });
  }

  evaluateWithPrompt(context: GuardPolicyContext): {
    decision: GuardDecision;
    approvalPrompt?: ApprovalPromptRequest;
  } {
    const decision = this.evaluate(context);
    if (decision.verdict === 'allow') {
      return { decision };
    }
    return {
      decision,
      approvalPrompt: formatApprovalPrompt(context, decision),
    };
  }
}
