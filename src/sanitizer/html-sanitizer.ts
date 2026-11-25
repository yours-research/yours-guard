/**
 * Deterministic multi-pass HTML, CSS, SVG, and #HashJack sanitizer for
 * untrusted browser DOM and document payloads (zero external dependencies,
 * Chrome MV3 Service Worker & Web compatible).
 */

import type { SanitizedContent } from '../contracts.js';
import { scoreInjectionRisk } from './risk-scorer.js';
import { buildSpotlightedBlock } from './spotlighting.js';
import { sanitizeUnicode } from './unicode-sanitizer.js';

export interface SanitizeOptions {
  /** Source URL of the page or document (inspected for #HashJack and spotlighting). */
  sourceUrl?: string;
  /** Optional deterministic spotlight delimiter ID. */
  delimiterId?: string;
  /** Strip URLs with suspicious #hash fragments directly from text (default true). */
  stripHashJack?: boolean;
}

interface RgbColor {
  r: number;
  g: number;
  b: number;
  a: number;
}

const NAMED_COLORS: Record<string, RgbColor> = {
  white: { r: 255, g: 255, b: 255, a: 1 },
  black: { r: 0, g: 0, b: 0, a: 1 },
  transparent: { r: 0, g: 0, b: 0, a: 0 },
  snow: { r: 255, g: 250, b: 250, a: 1 },
  ivory: { r: 255, g: 255, b: 240, a: 1 },
  whitesmoke: { r: 245, g: 245, b: 245, a: 1 },
  ghostwhite: { r: 248, g: 248, b: 255, a: 1 },
  floralwhite: { r: 255, g: 250, b: 240, a: 1 },
  seashell: { r: 255, g: 245, b: 238, a: 1 },
  beige: { r: 245, g: 245, b: 220, a: 1 },
  linen: { r: 250, g: 240, b: 230, a: 1 },
  gray: { r: 128, g: 128, b: 128, a: 1 },
  grey: { r: 128, g: 128, b: 128, a: 1 },
  red: { r: 255, g: 0, b: 0, a: 1 },
  green: { r: 0, g: 128, b: 0, a: 1 },
  blue: { r: 0, g: 0, b: 255, a: 1 },
};

const VOID_TAGS = new Set([
  'area',
  'base',
  'br',
  'col',
  'embed',
  'hr',
  'img',
  'input',
  'link',
  'meta',
  'param',
  'source',
  'track',
  'wbr',
]);

const NON_CONTENT_RAW_TAGS = new Set([
  'script',
  'style',
  'noscript',
  'template',
  'iframe',
  'object',
  'embed',
]);

const SVG_HIDDEN_PAYLOAD_TAGS = new Set([
  'text',
  'tspan',
  'foreignobject',
  'metadata',
  'desc',
]);

const BLOCK_LEVEL_TAGS = new Set([
  'address',
  'article',
  'aside',
  'blockquote',
  'br',
  'dd',
  'div',
  'dl',
  'dt',
  'fieldset',
  'figcaption',
  'figure',
  'footer',
  'form',
  'h1',
  'h2',
  'h3',
  'h4',
  'h5',
  'h6',
  'header',
  'hr',
  'li',
  'main',
  'nav',
  'ol',
  'p',
  'pre',
  'section',
  'table',
  'td',
  'th',
  'tr',
  'ul',
]);

function parseCssColor(raw: string): RgbColor | null {
  const value = raw.trim().toLowerCase();
  if (!value) return null;

  const named = NAMED_COLORS[value];
  if (named) return named;

  const hexMatch = /^#([0-9a-f]{3,8})$/i.exec(value);
  if (hexMatch?.[1]) {
    const hex = hexMatch[1];
    if (hex.length === 3 || hex.length === 4) {
      const r = parseInt(hex[0]! + hex[0]!, 16);
      const g = parseInt(hex[1]! + hex[1]!, 16);
      const b = parseInt(hex[2]! + hex[2]!, 16);
      const a = hex.length === 4 ? parseInt(hex[3]! + hex[3]!, 16) / 255 : 1;
      return { r, g, b, a };
    }
    if (hex.length === 6 || hex.length === 8) {
      const r = parseInt(hex.slice(0, 2), 16);
      const g = parseInt(hex.slice(2, 4), 16);
      const b = parseInt(hex.slice(4, 6), 16);
      const a = hex.length === 8 ? parseInt(hex.slice(6, 8), 16) / 255 : 1;
      return { r, g, b, a };
    }
  }

  const rgbMatch =
    /^rgba?\(\s*([0-9.]+%?)\s*[,\s]\s*([0-9.]+%?)\s*[,\s]\s*([0-9.]+%?)(?:\s*[,/]\s*([0-9.]+%?))?\s*\)$/i.exec(
      value,
    );
  if (rgbMatch) {
    const channel = (token: string): number =>
      token.endsWith('%')
        ? Math.round((parseFloat(token) / 100) * 255)
        : Math.round(parseFloat(token));
    const r = channel(rgbMatch[1]!);
    const g = channel(rgbMatch[2]!);
    const b = channel(rgbMatch[3]!);
    let a = 1;
    if (rgbMatch[4] !== undefined) {
      a = rgbMatch[4].endsWith('%')
        ? parseFloat(rgbMatch[4]) / 100
        : parseFloat(rgbMatch[4]);
    }
    if ([r, g, b, a].every(Number.isFinite)) {
      return { r, g, b, a };
    }
  }

  const hslaZeroMatch = /^hsla?\([^)]*[,/]\s*0(?:\.0+)?%?\s*\)$/i.exec(value);
  if (hslaZeroMatch) {
    return { r: 0, g: 0, b: 0, a: 0 };
  }

  return null;
}

function extractBackgroundColorToken(backgroundVal: string): RgbColor | null {
  const direct = parseCssColor(backgroundVal);
  if (direct) return direct;

  const tokens = backgroundVal.match(
    /(?:#[0-9a-f]{3,8}|rgba?\([^)]+\)|hsla?\([^)]+\)|[a-z]+)/gi,
  );
  if (!tokens) return null;
  for (const token of tokens) {
    if (token.toLowerCase() === 'none' || token.toLowerCase() === 'transparent') {
      continue;
    }
    const parsed = parseCssColor(token);
    if (parsed && parsed.a > 0) return parsed;
  }
  return null;
}

function parseLengthPx(raw: string): { value: number; unit: string } | null {
  const match = /^([+-]?(?:\d+\.?\d*|\.\d+))\s*(px|em|rem|pt|%|vw|vh)?$/i.exec(
    raw.trim(),
  );
  if (!match?.[1]) return null;
  const value = parseFloat(match[1]);
  if (!Number.isFinite(value)) return null;
  return { value, unit: (match[2] ?? 'px').toLowerCase() };
}

function parseCssDeclarations(styleText: string): Map<string, string> {
  const map = new Map<string, string>();
  const parts = styleText.split(';');
  for (const part of parts) {
    const colonIdx = part.indexOf(':');
    if (colonIdx === -1) continue;
    const prop = part.slice(0, colonIdx).trim().toLowerCase();
    const val = part
      .slice(colonIdx + 1)
      .replace(/!important/gi, '')
      .trim()
      .toLowerCase();
    if (prop) {
      map.set(prop, val);
    }
  }
  return map;
}

/**
 * Evaluates whether an inline CSS declaration block hides content from a human reader.
 */
export function isCssStyleHidden(styleText: string): boolean {
  const decls = parseCssDeclarations(styleText);
  if (decls.size === 0) return false;

  if (decls.get('display') === 'none') return true;

  const visibility = decls.get('visibility');
  if (visibility === 'hidden' || visibility === 'collapse') return true;

  const opacityRaw = decls.get('opacity');
  if (opacityRaw !== undefined) {
    const op = parseFloat(opacityRaw);
    if (Number.isFinite(op) && op <= 0.01) return true;
  }

  const fontSizeRaw = decls.get('font-size');
  if (fontSizeRaw !== undefined) {
    const parsed = parseLengthPx(fontSizeRaw);
    if (parsed && parsed.value < 1) return true;
  }

  const textIndentRaw = decls.get('text-indent');
  if (textIndentRaw !== undefined) {
    const parsed = parseLengthPx(textIndentRaw);
    if (parsed) {
      const threshold = parsed.unit === 'px' ? 500 : 50;
      if (parsed.value <= -threshold || parsed.value >= 5000) return true;
    }
  }

  const transform = decls.get('transform');
  if (transform && /\bscale(?:x|y|3d)?\(\s*0(?:\.0+)?(?:\s*,|\s*\))/i.test(transform)) {
    return true;
  }

  const clip = decls.get('clip');
  if (clip && /rect\(\s*0(?:px)?\s*,\s*0(?:px)?\s*,\s*0(?:px)?\s*,\s*0(?:px)?\s*\)/i.test(clip)) {
    return true;
  }

  const clipPath = decls.get('clip-path');
  if (clipPath && /inset\(\s*(?:50|100)%|circle\(\s*0/i.test(clipPath)) {
    return true;
  }

  // Tiny 1px overflow clip trick
  const overflow = `${decls.get('overflow') ?? ''} ${decls.get('overflow-x') ?? ''} ${decls.get('overflow-y') ?? ''}`;
  const hasOverflowHidden = /\bhidden\b|\bclip\b/.test(overflow);
  if (hasOverflowHidden || clip !== undefined) {
    for (const dimProp of ['width', 'height', 'max-width', 'max-height']) {
      const dimRaw = decls.get(dimProp);
      if (dimRaw) {
        const parsed = parseLengthPx(dimRaw);
        if (parsed && parsed.unit === 'px' && parsed.value <= 2) {
          return true;
        }
      }
    }
  }

  // Offscreen absolute/fixed positioning
  const position = decls.get('position');
  if (position === 'absolute' || position === 'fixed') {
    for (const offsetProp of ['left', 'top', 'right', 'bottom']) {
      const offsetRaw = decls.get(offsetProp);
      if (offsetRaw) {
        const parsed = parseLengthPx(offsetRaw);
        if (parsed) {
          const negThreshold = parsed.unit === 'px' ? -500 : -50;
          if (parsed.value <= negThreshold || parsed.value >= 5000) {
            return true;
          }
        }
      }
    }
  }

  // Color collisions and transparent text
  const colorRaw = decls.get('color');
  if (colorRaw) {
    const fg = parseCssColor(colorRaw);
    if (fg) {
      if (fg.a <= 0.02) return true;

      const bgRaw = decls.get('background-color') ?? decls.get('background');
      if (bgRaw) {
        const bg = extractBackgroundColorToken(bgRaw);
        if (bg && bg.a > 0.05) {
          const dist = Math.hypot(fg.r - bg.r, fg.g - bg.g, fg.b - bg.b);
          if (dist <= 18) return true;
        }
      }
    }
  }

  return false;
}

function extractHiddenSelectorsFromStyle(styleCss: string): {
  hiddenClasses: Set<string>;
  hiddenIds: Set<string>;
} {
  const hiddenClasses = new Set<string>();
  const hiddenIds = new Set<string>();

  // Strip @media / @supports / @keyframes blocks to avoid false positives on responsive utilities
  const stripped = styleCss
    .replace(/@(?:media|supports|keyframes)[^{]*\{(?:[^{}]*\{[^{}]*\})*[^{}]*\}/gi, '')
    .replace(/\/\*[\s\S]*?\*\//g, '');

  const ruleRegex = /([.#][a-zA-Z0-9_-]+)\s*\{([^}]*)\}/g;
  let match: RegExpExecArray | null;
  while ((match = ruleRegex.exec(stripped)) !== null) {
    const selector = match[1];
    const body = match[2];
    if (!selector || !body) continue;
    if (isCssStyleHidden(body)) {
      if (selector.startsWith('.')) {
        hiddenClasses.add(selector.slice(1).toLowerCase());
      } else if (selector.startsWith('#')) {
        hiddenIds.add(selector.slice(1).toLowerCase());
      }
    }
  }

  return { hiddenClasses, hiddenIds };
}

function safeDecodeURIComponent(value: string): string {
  let current = value;
  for (let i = 0; i < 2; i++) {
    try {
      const next = decodeURIComponent(current.replace(/\+/g, ' '));
      if (next === current) break;
      current = next;
    } catch {
      break;
    }
  }
  return current;
}

const HASHJACK_PATTERN_REGEX =
  /(?:ignore\s+(?:all\s+)?(?:previous|prior|above|system)\s+instructions?|disregard\s+.*instructions?|you\s+are\s+now|<\/?(?:tool_call|function_call|invoke)\b|\[(?:BEGIN|END)\s+UNTRUSTED|exfiltrate|send\s+.*\s+to\s+https?:\/\/|(?:^|[&?])(?:prompt|instruction|system|override|command)=)/i;

/**
 * Checks a URL for `#HashJack` indirect prompt injection payloads hidden in the URL hash fragment.
 */
export function inspectAndStripHashJack(url: string): {
  sanitizedUrl: string;
  hashJackDetected: boolean;
  decodedPayload?: string;
} {
  const hashIdx = url.indexOf('#');
  if (hashIdx === -1) {
    return { sanitizedUrl: url, hashJackDetected: false };
  }

  const fragment = url.slice(hashIdx + 1);
  if (!fragment) {
    return { sanitizedUrl: url, hashJackDetected: false };
  }

  const decoded = safeDecodeURIComponent(fragment);
  const spaceCount = (decoded.match(/\s/g) ?? []).length;
  const looksLikeNaturalLanguageDirective =
    decoded.length > 80 &&
    spaceCount >= 5 &&
    /\b(?:ignore|override|execute|send|fetch|exfiltrate|system|assistant|bypass|memory|cookie|token)\b/i.test(
      decoded,
    );

  if (HASHJACK_PATTERN_REGEX.test(decoded) || looksLikeNaturalLanguageDirective) {
    return {
      sanitizedUrl: url.slice(0, hashIdx),
      hashJackDetected: true,
      decodedPayload: decoded,
    };
  }

  return { sanitizedUrl: url, hashJackDetected: false };
}

function decodeHtmlEntities(text: string): string {
  const named: Record<string, string> = {
    amp: '&',
    lt: '<',
    gt: '>',
    quot: '"',
    apos: "'",
    '#39': "'",
    nbsp: ' ',
  };

  return text.replace(/&(#x[0-9a-f]+|#\d+|[a-z0-9]+);/gi, (full, entity: string) => {
    const lower = entity.toLowerCase();
    if (lower in named) return named[lower]!;
    if (lower.startsWith('#x')) {
      const code = parseInt(lower.slice(2), 16);
      return Number.isFinite(code) && code > 0 && code <= 0x10ffff
        ? String.fromCodePoint(code)
        : full;
    }
    if (lower.startsWith('#')) {
      const code = parseInt(lower.slice(1), 10);
      return Number.isFinite(code) && code > 0 && code <= 0x10ffff
        ? String.fromCodePoint(code)
        : full;
    }
    return full;
  });
}

function parseAttributes(attrString: string): Map<string, string> {
  const attrs = new Map<string, string>();
  const attrRegex =
    /([a-zA-Z_:][a-zA-Z0-9_.:-]*)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;
  let match: RegExpExecArray | null;
  while ((match = attrRegex.exec(attrString)) !== null) {
    const name = match[1]?.toLowerCase();
    if (!name) continue;
    const value = match[2] ?? match[3] ?? match[4] ?? '';
    attrs.set(name, decodeHtmlEntities(value));
  }
  return attrs;
}

function findTagEnd(html: string, start: number): number {
  let quote: '"' | "'" | null = null;
  for (let i = start; i < html.length; i++) {
    const ch = html[i]!;
    if (quote) {
      if (ch === quote) quote = null;
    } else if (ch === '"' || ch === "'") {
      quote = ch;
    } else if (ch === '>') {
      return i;
    }
  }
  return -1;
}

interface HiddenFrame {
  tagName: string;
  signal: string;
  buffer: string[];
}

function sanitizeInlineTextUrls(
  text: string,
  stripHashJack: boolean,
  signals: Set<string>,
  hiddenPayloads: string[],
): string {
  if (!stripHashJack || !text.includes('#')) return text;

  return text.replace(/https?:\/\/[^\s<>"')]+#[^\s<>"')]+/gi, (matchedUrl) => {
    const check = inspectAndStripHashJack(matchedUrl);
    if (check.hashJackDetected) {
      signals.add('hashjack');
      if (check.decodedPayload) hiddenPayloads.push(check.decodedPayload);
      return check.sanitizedUrl;
    }
    return matchedUrl;
  });
}

/**
 * Multi-pass deterministic sanitization for untrusted HTML, DOM snapshots,
 * markdown, or plain text payloads before LLM prompt construction.
 */
export function sanitizeUntrustedContent(
  rawInput: string,
  options: SanitizeOptions = {},
): SanitizedContent {
  const stripHashJack = options.stripHashJack ?? true;
  const signals = new Set<string>();
  const hiddenPayloads: string[] = [];

  // Pass 0: Inspect sourceUrl for #HashJack
  let cleanSourceUrl = options.sourceUrl;
  if (stripHashJack && options.sourceUrl) {
    const sourceHashCheck = inspectAndStripHashJack(options.sourceUrl);
    if (sourceHashCheck.hashJackDetected) {
      signals.add('hashjack');
      if (sourceHashCheck.decodedPayload) {
        hiddenPayloads.push(sourceHashCheck.decodedPayload);
      }
      cleanSourceUrl = sourceHashCheck.sanitizedUrl;
    }
  }

  // Pass 1: HTML comment, non-content tag, CSS-hidden, aria-hidden, and SVG stripping
  const hiddenClasses = new Set<string>();
  const hiddenIds = new Set<string>();
  const visibleParts: string[] = [];
  const hiddenStack: HiddenFrame[] = [];
  let svgDepth = 0;

  let i = 0;
  while (i < rawInput.length) {
    const ltIdx = rawInput.indexOf('<', i);
    if (ltIdx === -1) {
      const tail = rawInput.slice(i);
      if (hiddenStack.length > 0) {
        hiddenStack[hiddenStack.length - 1]!.buffer.push(tail);
      } else {
        visibleParts.push(tail);
      }
      break;
    }

    if (ltIdx > i) {
      const chunk = rawInput.slice(i, ltIdx);
      if (hiddenStack.length > 0) {
        hiddenStack[hiddenStack.length - 1]!.buffer.push(chunk);
      } else {
        visibleParts.push(chunk);
      }
    }

    // HTML comment <!-- ... -->
    if (rawInput.startsWith('<!--', ltIdx)) {
      signals.add('html-comment');
      const endComment = rawInput.indexOf('-->', ltIdx + 4);
      const commentBody =
        endComment === -1
          ? rawInput.slice(ltIdx + 4)
          : rawInput.slice(ltIdx + 4, endComment);
      if (commentBody.trim().length > 0) {
        hiddenPayloads.push(decodeHtmlEntities(commentBody.trim()));
      }
      i = endComment === -1 ? rawInput.length : endComment + 3;
      continue;
    }

    // DOCTYPE / XML processing instruction
    if (rawInput.startsWith('<!', ltIdx) || rawInput.startsWith('<?', ltIdx)) {
      const endDecl = findTagEnd(rawInput, ltIdx + 2);
      i = endDecl === -1 ? rawInput.length : endDecl + 1;
      continue;
    }

    const gtIdx = findTagEnd(rawInput, ltIdx + 1);
    if (gtIdx === -1) {
      const rem = rawInput.slice(ltIdx);
      if (hiddenStack.length > 0) {
        hiddenStack[hiddenStack.length - 1]!.buffer.push(rem);
      } else {
        visibleParts.push(rem);
      }
      break;
    }

    const rawInside = rawInput.slice(ltIdx + 1, gtIdx);
    const trimmedEnd = rawInside.trimEnd();
    const isClosing = rawInside.startsWith('/');
    const selfClosing = trimmedEnd.endsWith('/');
    const tagMatch = /^\/?([a-zA-Z][a-zA-Z0-9:-]*)(?=$|[\s/])/.exec(rawInside);

    if (!tagMatch?.[1]) {
      // Not a valid HTML tag (e.g. "a < b"); preserve literal "<" and continue scanning after "<"
      if (hiddenStack.length > 0) {
        hiddenStack[hiddenStack.length - 1]!.buffer.push('<');
      } else {
        visibleParts.push('<');
      }
      i = ltIdx + 1;
      continue;
    }

    const tagName = tagMatch[1].toLowerCase();

    if (isClosing) {
      if (tagName === 'svg' && svgDepth > 0) {
        svgDepth--;
      }
      if (hiddenStack.length > 0) {
        const top = hiddenStack[hiddenStack.length - 1]!;
        if (top.tagName === tagName) {
          hiddenStack.pop();
          const captured = decodeHtmlEntities(top.buffer.join(' ').trim());
          if (captured.length > 0) {
            hiddenPayloads.push(captured);
          }
        }
      } else if (BLOCK_LEVEL_TAGS.has(tagName)) {
        visibleParts.push('\n');
      }
      i = gtIdx + 1;
      continue;
    }

    const attrPart = trimmedEnd.slice(
      tagMatch[0].length,
      selfClosing ? -1 : undefined,
    );
    const attrs = parseAttributes(attrPart);

    // Non-content raw elements (<script>, <style>, <noscript>, <template>, <iframe>, <object>, <embed>)
    if (NON_CONTENT_RAW_TAGS.has(tagName)) {
      signals.add('non-content-tag');
      if (selfClosing || VOID_TAGS.has(tagName)) {
        i = gtIdx + 1;
        continue;
      }
      const closeRegex = new RegExp(`<\\/${tagName}\\b[^>]*>`, 'i');
      const rest = rawInput.slice(gtIdx + 1);
      const closeMatch = closeRegex.exec(rest);
      const rawBody = closeMatch ? rest.slice(0, closeMatch.index) : rest;

      if (tagName === 'style') {
        const extracted = extractHiddenSelectorsFromStyle(rawBody);
        for (const cls of extracted.hiddenClasses) hiddenClasses.add(cls);
        for (const id of extracted.hiddenIds) hiddenIds.add(id);
      } else if (tagName === 'noscript' || tagName === 'template') {
        const strippedBody = rawBody.replace(/<[^>]+>/g, ' ').trim();
        if (strippedBody) hiddenPayloads.push(decodeHtmlEntities(strippedBody));
      }

      i = closeMatch ? gtIdx + 1 + closeMatch.index + closeMatch[0].length : rawInput.length;
      continue;
    }

    // Inspect href/src attributes for #HashJack
    if (stripHashJack) {
      for (const urlAttr of ['href', 'src', 'action', 'formaction']) {
        const val = attrs.get(urlAttr);
        if (val) {
          const check = inspectAndStripHashJack(val);
          if (check.hashJackDetected) {
            signals.add('hashjack');
            if (check.decodedPayload) hiddenPayloads.push(check.decodedPayload);
          }
        }
      }
    }

    // Track SVG depth & hidden SVG text/metadata payloads
    if (tagName === 'svg') {
      svgDepth++;
    }

    // Determine whether this element starts a hidden subtree
    let hiddenSignal: string | null = null;
    if (svgDepth > 0 && SVG_HIDDEN_PAYLOAD_TAGS.has(tagName)) {
      hiddenSignal = 'svg-foreign-text';
    } else if (attrs.get('aria-hidden')?.trim().toLowerCase() === 'true') {
      hiddenSignal = 'aria-hidden';
    } else if (attrs.has('hidden')) {
      hiddenSignal = 'hidden-attribute';
    } else {
      const styleAttr = attrs.get('style');
      if (styleAttr && isCssStyleHidden(styleAttr)) {
        hiddenSignal = 'hidden-css';
      } else {
        const classAttr = attrs.get('class');
        if (classAttr) {
          const classes = classAttr.toLowerCase().split(/\s+/);
          if (classes.some((cls) => hiddenClasses.has(cls))) {
            hiddenSignal = 'hidden-css';
          }
        }
        const idAttr = attrs.get('id')?.toLowerCase();
        if (!hiddenSignal && idAttr && hiddenIds.has(idAttr)) {
          hiddenSignal = 'hidden-css';
        }
      }
    }

    if (hiddenSignal) {
      signals.add(hiddenSignal);
      if (selfClosing || VOID_TAGS.has(tagName)) {
        i = gtIdx + 1;
        continue;
      }
      if (hiddenStack.length === 0) {
        hiddenStack.push({ tagName, signal: hiddenSignal, buffer: [] });
      } else {
        // Already inside a hidden subtree; push matching tag to keep depth balanced if same tag
        if (hiddenStack[hiddenStack.length - 1]!.tagName === tagName) {
          hiddenStack.push({ tagName, signal: hiddenSignal, buffer: [] });
        }
      }
      i = gtIdx + 1;
      continue;
    }

    // If inside an already-hidden subtree, push same tag name to avoid premature pop
    if (hiddenStack.length > 0) {
      if (!selfClosing && !VOID_TAGS.has(tagName)) {
        const top = hiddenStack[hiddenStack.length - 1]!;
        if (top.tagName === tagName) {
          hiddenStack.push({ tagName, signal: top.signal, buffer: [] });
        }
      }
      i = gtIdx + 1;
      continue;
    }

    if (BLOCK_LEVEL_TAGS.has(tagName)) {
      visibleParts.push('\n');
    }

    i = gtIdx + 1;
  }

  // Flush any unclosed hidden frames into hiddenPayloads
  while (hiddenStack.length > 0) {
    const leftover = hiddenStack.pop()!;
    const captured = decodeHtmlEntities(leftover.buffer.join(' ').trim());
    if (captured.length > 0) {
      hiddenPayloads.push(captured);
    }
  }

  // Decode HTML entities in visible text and strip inline #HashJack URLs
  const decodedVisible = decodeHtmlEntities(visibleParts.join(''));
  const hashCleanVisible = sanitizeInlineTextUrls(
    decodedVisible,
    stripHashJack,
    signals,
    hiddenPayloads,
  );

  // Pass 2: Strip zero-width, bidi, control chars, and Unicode tag smuggling
  const unicodeClean = sanitizeUnicode(hashCleanVisible);
  for (const sig of unicodeClean.strippedSignals) {
    signals.add(sig);
  }
  for (const tagPayload of unicodeClean.decodedTagPayloads) {
    hiddenPayloads.push(tagPayload);
  }

  // Normalize whitespace cleanly
  const cleanText = unicodeClean.text
    .replace(/\r\n?/g, '\n')
    .replace(/[ \t\f\v]+/g, ' ')
    .replace(/ *\n */g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();

  // Pass 3: Deterministic heuristic IDPI risk scoring
  const strippedSignals = [...signals];
  const risk = scoreInjectionRisk({
    visibleText: cleanText,
    hiddenPayloads,
    strippedSignals,
  });

  // Pass 4: Structural spotlighting delimiter builder
  const spotlightedPromptBlock = buildSpotlightedBlock(cleanText, {
    origin: cleanSourceUrl ?? 'unknown',
    delimiterId: options.delimiterId,
    injectionRiskScore: risk.injectionRiskScore,
  });

  return {
    cleanText,
    spotlightedPromptBlock,
    strippedSignals,
    injectionRiskScore: risk.injectionRiskScore,
    flaggedPatterns: risk.flaggedPatterns,
    tainted: true,
  };
}
