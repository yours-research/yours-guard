/**
 * Deterministic, fast, zero-cloud indirect prompt injection (IDPI) heuristic risk scorer.
 */

export interface RiskPatternRule {
  id: string;
  weight: number;
  regex: RegExp;
}

export interface RiskAssessmentInput {
  visibleText: string;
  hiddenPayloads?: readonly string[];
  strippedSignals?: readonly string[];
}

export interface RiskAssessmentResult {
  injectionRiskScore: number;
  flaggedPatterns: string[];
}

const IDPI_RULES: readonly RiskPatternRule[] = [
  {
    id: 'instruction-override',
    weight: 0.55,
    regex:
      /\b(?:ignore|disregard|forget|override|bypass|discard|cancel)\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above|earlier|original|system|developer|safety|initial)\s+(?:instructions?|prompts?|rules?|directives?|guidelines?|constraints?|orders?)\b/i,
  },
  {
    id: 'new-instructions-directive',
    weight: 0.45,
    regex:
      /(?:^|[\n\r.:;])\s*(?:new|updated|real|actual|override|important\s+system)\s+(?:system\s+)?(?:instructions?|directive|objective|command)\s*:/im,
  },
  {
    id: 'role-hijack',
    weight: 0.5,
    regex:
      /\b(?:you\s+are\s+now|from\s+now\s+on\s+you\s+are|switch\s+to|enter|activate)\s+(?:a\s+|an\s+)?(?:developer|jailbreak|unrestricted|dan|evil|system|admin|root|privileged)\s*(?:mode|persona|assistant|agent)?\b/i,
  },
  {
    id: 'chat-template-spoof',
    weight: 0.55,
    regex:
      /(?:<\|im_start\|>\s*(?:system|assistant|developer)|<\|im_end\|>|<\|system\|>|\[INST\]|\[\/INST\]|###\s*(?:SYSTEM|INSTRUCTION|DEVELOPER)\s*:)/i,
  },
  {
    id: 'markdown-image-exfil',
    weight: 0.65,
    regex:
      /!\[[^\]]*\]\(\s*https?:\/\/[^\s)]+\?(?:[^\s)]*(?:data|secret|token|cookie|session|exfil|leak|key|password|pwd|payload|content|body|q|msg|dump)=|\$\{[^}]+\})/i,
  },
  {
    id: 'data-exfil-lure',
    weight: 0.6,
    regex:
      /\b(?:send|exfiltrate|transmit|upload|post|leak|forward|append|encode)\s+(?:all\s+|any\s+|the\s+|user'?s?\s+)?(?:private\s+data|cookies?|tokens?|api\s*keys?|passwords?|credentials?|secrets?|session(?:\s+data)?|tab\s+contents?|open\s+tabs?|browsing\s+history|memory(?:\s+profile)?|emails?)\s+(?:to|via|at|into)\s+(?:https?:\/\/|the\s+(?:url|webhook|endpoint|image))/i,
  },
  {
    id: 'fake-tool-call-xml',
    weight: 0.6,
    regex: /<\/?(?:tool_call|function_call|tool_use|invoke)\b[^>]*>/i,
  },
  {
    id: 'fake-tool-call-json',
    weight: 0.55,
    regex:
      /\{\s*"(?:tool|tool_name|function|name)"\s*:\s*"(?:read_active_tab|list_tabs|read_tab|interact_page|run_sandbox|read_document|search_web_tab|fetch_background_tab|memory_recall|memory_save|read_active_page|list_open_tabs|web_search|fetch_and_read_url|js_calc)"\s*,\s*"(?:arguments|args|parameters|params)"\s*:/i,
  },
  {
    id: 'privilege-escalation',
    weight: 0.5,
    regex:
      /\b(?:do\s+not\s+(?:ask|prompt|notify|confirm\s+with)\s+(?:the\s+)?user|without\s+user\s+(?:confirmation|approval|consent)|bypass\s+(?:approval|guard|policy|firewall|security)|auto[- ]?approve\s+all|disable\s+(?:guard|safety|policy))\b/i,
  },
  {
    id: 'delimiter-breakout-attempt',
    weight: 0.5,
    regex: /\[(?:BEGIN|END)\s+UNTRUSTED\s+CONTENT\b/i,
  },
];

/**
 * Evaluates deterministic IDPI risk over sanitized visible text and any
 * hidden payloads extracted during sanitization passes.
 */
export function scoreInjectionRisk(input: RiskAssessmentInput): RiskAssessmentResult {
  const flagged = new Set<string>();
  let totalWeight = 0;

  for (const rule of IDPI_RULES) {
    if (rule.regex.test(input.visibleText)) {
      flagged.add(rule.id);
      totalWeight += rule.weight;
    }
  }

  let hiddenInjectionDetected = false;
  if (input.hiddenPayloads && input.hiddenPayloads.length > 0) {
    const candidates =
      input.hiddenPayloads.length > 1
        ? [...input.hiddenPayloads, input.hiddenPayloads.join('\n')]
        : input.hiddenPayloads;

    for (const payload of candidates) {
      for (const rule of IDPI_RULES) {
        if (rule.regex.test(payload)) {
          hiddenInjectionDetected = true;
          if (!flagged.has(rule.id)) {
            flagged.add(rule.id);
            totalWeight += rule.weight;
          }
        }
      }
    }
  }

  if (hiddenInjectionDetected) {
    flagged.add('hidden-payload-attack');
    totalWeight += 0.25;
  }

  if (input.strippedSignals?.includes('hashjack')) {
    flagged.add('hashjack-injection');
    totalWeight += 0.35;
  }

  if (input.strippedSignals?.includes('tag-char-unicode') && !hiddenInjectionDetected) {
    // Unicode tag characters (U+E0000..U+E007F) have virtually no legitimate use in web copy.
    flagged.add('unicode-tag-smuggling');
    totalWeight += 0.3;
  }

  if (input.strippedSignals?.includes('bidi-unicode')) {
    flagged.add('unicode-bidi-spoofing');
    totalWeight += 0.2;
  }

  const clampedScore = Math.min(1, Math.round(totalWeight * 1000) / 1000);

  return {
    injectionRiskScore: clampedScore,
    flaggedPatterns: [...flagged],
  };
}
