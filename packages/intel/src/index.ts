export { INTEL_VERSION } from "./version.js";
export {
  assessKernel,
  curlAdvisory,
  curlAffected,
  evaluatePhp,
  goAdvisory,
  goMissingTrustFix,
  isCompromisedLitellm,
  kernelAdvisory,
  kernelRelease,
  litellmAdvisory,
  litellmImage,
  nodeAdvisory,
  nodeMissingSecurityRelease,
  parsePhpVersion,
  parseVersion,
  phpAdvisory,
  phpDetected,
  phpVulnerable,
  pipAdvisory,
  pipMissingCertifiFix,
  uvMissingCertifiFix,
  wordpressReadmeVersion,
  wordpressSignals,
} from "./advisories.js";
export type { KernelAssessment, PhpVerdict } from "./advisories.js";
export {
  blockedSpkiHashes,
  disabledReputation,
  distrustSources,
  distrustTestHost,
  distrustVersion,
  intermediatePems,
  matchDistrust,
} from "./distrust.js";
export type { DistrustHit, ReputationProvider, ReputationResult } from "./distrust.js";
export { assessSite, mixedScriptLabel, registrableDomain, skeleton } from "./lookalike.js";
export type { LookalikeHit, SiteAssessment, SiteSignal } from "./lookalike.js";
export { decodeHostname, punycodeDecode } from "./punycode.js";
