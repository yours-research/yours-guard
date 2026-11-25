/**
 * Structural Spotlighting Delimiter Builder.
 * Escapes boundary-like tokens inside untrusted text so payloads cannot
 * break out of `[BEGIN UNTRUSTED CONTENT ...]` fences.
 */

export interface SpotlightingOptions {
  /** Optional origin label included in the spotlight header. */
  origin?: string;
  /** Optional deterministic delimiter ID; defaults to an FNV-1a hash of content + origin. */
  delimiterId?: string;
  /** Optional risk score rendered in the spotlight fence metadata. */
  injectionRiskScore?: number;
}

function fnv1aHex(input: string): string {
  let hash = 0x811c9dc5;
  for (let i = 0; i < input.length; i++) {
    hash ^= input.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  return (hash >>> 0).toString(16).padStart(8, '0');
}

function sanitizeAttributeValue(value: string): string {
  return value
    .replace(/[\r\n\t"\\[\]]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 200);
}

/**
 * Escapes boundary and chat-template tokens inside untrusted content so it
 * cannot terminate or spoof structural spotlighting fences.
 */
export function escapeSpotlightBoundaries(text: string): string {
  return text
    .replace(
      /\[\s*(BEGIN|END)\s+UNTRUSTED\s+CONTENT\b/gi,
      (_m, dir: string) => `[ESCAPED_${dir.toUpperCase()}_UNTRUSTED_CONTENT`,
    )
    .replace(
      /\b(BEGIN|END)\s+UNTRUSTED\s+CONTENT\b/gi,
      (_m, dir: string) => `ESCAPED_${dir.toUpperCase()}_UNTRUSTED_CONTENT`,
    )
    .replace(/<\|(im_start|im_end|endoftext|system|user|assistant)\|>/gi, '<\\|$1\\|>')
    .replace(/\[(\/?INST)\]/gi, '[ESCAPED_$1]')
    .replace(/<\/?(untrusted_content)\b([^>]*)>/gi, '[ESCAPED_$1$2]');
}

/**
 * Wraps sanitized untrusted content in an escaped spotlighting fence.
 */
export function buildSpotlightedBlock(
  cleanText: string,
  options: SpotlightingOptions = {},
): string {
  const origin = sanitizeAttributeValue(options.origin ?? 'unknown');
  const id = sanitizeAttributeValue(
    options.delimiterId ?? `ug-${fnv1aHex(`${origin}\n${cleanText}`)}`,
  );
  const risk =
    options.injectionRiskScore !== undefined
      ? options.injectionRiskScore.toFixed(2)
      : '0.00';

  const escapedBody = escapeSpotlightBoundaries(cleanText);

  return [
    `[BEGIN UNTRUSTED CONTENT id="${id}" origin="${origin}" tainted="true" risk="${risk}"]`,
    escapedBody,
    `[END UNTRUSTED CONTENT id="${id}"]`,
  ].join('\n');
}
