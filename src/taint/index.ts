export {
  TaintTracker,
  createTaintedValue,
  deriveTaintedValue,
  concatTainted,
  isTaintedValue,
  unwrapTainted,
  type TaintSourceKind,
  type TaintProvenance,
  type TaintedValue,
  type SensitiveSinkKind,
  type TaintFlowReport,
  type CreateProvenanceInput,
} from './taint-tracker.js';
