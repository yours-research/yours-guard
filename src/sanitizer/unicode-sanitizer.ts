/**
 * Deterministic zero-width, bidirectional override, control-character,
 * and Unicode Tag (U+E0000..U+E007F) smuggling sanitizer.
 */

export interface UnicodeSanitizationResult {
  text: string;
  strippedSignals: string[];
  decodedTagPayloads: string[];
}

const ZERO_WIDTH_REGEX =
  /[\u00AD\u034F\u180E\u200B-\u200F\u2060-\u2064\uFEFF]/g;

const BIDI_CONTROL_REGEX = /[\u202A-\u202E\u2066-\u2069]/g;

const UNICODE_TAG_REGEX = /[\u{E0000}-\u{E007F}]/gu;

const ASCII_CONTROL_REGEX = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g;

/**
 * Decodes invisible ASCII characters smuggled inside the Unicode Tags block
 * (U+E0000..U+E007F) so the risk scorer can still inspect hidden payloads
 * even after the invisible characters are stripped from `cleanText`.
 */
function extractTagSmuggledAscii(input: string): string[] {
  const payloads: string[] = [];
  let current = '';

  for (const ch of input) {
    const cp = ch.codePointAt(0);
    if (cp !== undefined && cp >= 0xe0000 && cp <= 0xe007f) {
      const ascii = cp - 0xe0000;
      if (ascii >= 0x20 && ascii <= 0x7e) {
        current += String.fromCharCode(ascii);
      } else if (ascii === 0x0a || ascii === 0x0d || ascii === 0x09) {
        current += ' ';
      }
    } else if (current.length > 0) {
      if (current.trim().length > 0) {
        payloads.push(current.trim());
      }
      current = '';
    }
  }

  if (current.trim().length > 0) {
    payloads.push(current.trim());
  }

  return payloads;
}

/**
 * Strips zero-width characters, bidi overrides/isolates, Unicode tag smuggling,
 * and unsafe ASCII control characters from untrusted text.
 */
export function sanitizeUnicode(input: string): UnicodeSanitizationResult {
  const signals = new Set<string>();
  let text = input;

  const decodedTagPayloads = extractTagSmuggledAscii(text);

  if (UNICODE_TAG_REGEX.test(text)) {
    signals.add('tag-char-unicode');
    text = text.replace(UNICODE_TAG_REGEX, '');
  }

  if (BIDI_CONTROL_REGEX.test(text)) {
    signals.add('bidi-unicode');
    text = text.replace(BIDI_CONTROL_REGEX, '');
  }

  if (ZERO_WIDTH_REGEX.test(text)) {
    signals.add('zero-width-unicode');
    text = text.replace(ZERO_WIDTH_REGEX, '');
  }

  if (ASCII_CONTROL_REGEX.test(text)) {
    signals.add('control-char-unicode');
    text = text.replace(ASCII_CONTROL_REGEX, '');
  }

  return {
    text,
    strippedSignals: [...signals],
    decodedTagPayloads,
  };
}
