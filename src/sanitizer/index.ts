export {
  sanitizeUntrustedContent,
  isCssStyleHidden,
  inspectAndStripHashJack,
  type SanitizeOptions,
} from './html-sanitizer.js';
export {
  sanitizeUnicode,
  type UnicodeSanitizationResult,
} from './unicode-sanitizer.js';
export {
  scoreInjectionRisk,
  type RiskAssessmentInput,
  type RiskAssessmentResult,
  type RiskPatternRule,
} from './risk-scorer.js';
export {
  buildSpotlightedBlock,
  escapeSpotlightBoundaries,
  type SpotlightingOptions,
} from './spotlighting.js';
