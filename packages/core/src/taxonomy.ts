import catalog from "../data/rule-catalog.json" with { type: "json" };
import {
  TAXONOMY_DOMAIN_IDS,
  type Finding,
  type FindingTaxonomy,
  type NistCsfFunction,
  type TaxonomyDomainId,
} from "./types.js";

interface CatalogCis {
  control: number;
  safeguard?: string;
  safeguardTitle?: string;
}

interface CatalogRule {
  domain: TaxonomyDomainId;
  nist: string;
  cis: CatalogCis | null;
}

const data = catalog as {
  version: string;
  frameworks: { nistCsf: string; cis: string };
  domains: { id: TaxonomyDomainId; label: string; scope: string }[];
  nistFunctions: { id: NistCsfFunction; label: string }[];
  nistCategories: Record<string, string>;
  cisControls: { control: number; title: string }[];
  rules: Record<string, CatalogRule>;
};

const domainById = new Map(data.domains.map((domain) => [domain.id, domain]));
const functionById = new Map(data.nistFunctions.map((entry) => [entry.id, entry]));
const cisByControl = new Map(data.cisControls.map((entry) => [entry.control, entry]));

export function taxonomyDomains(): { id: TaxonomyDomainId; label: string; scope: string }[] {
  return TAXONOMY_DOMAIN_IDS.map((id) => {
    const domain = domainById.get(id);
    if (!domain) throw new Error(`Taxonomy domain ${id} is missing from the rule catalog`);
    return domain;
  });
}

export function catalogVersion(): string {
  return data.version;
}

export function catalogRuleIds(): string[] {
  return Object.keys(data.rules);
}

export function taxonomyFor(ruleId: string): FindingTaxonomy {
  const rule = data.rules[ruleId];
  if (!rule) throw new Error(`Rule ${ruleId} has no taxonomy entry in the rule catalog`);
  const domain = domainById.get(rule.domain);
  if (!domain) throw new Error(`Rule ${ruleId} uses unknown domain ${rule.domain}`);
  const categoryLabel = data.nistCategories[rule.nist];
  if (!categoryLabel) throw new Error(`Rule ${ruleId} uses unknown NIST category ${rule.nist}`);
  const functionId = rule.nist.slice(0, 2) as NistCsfFunction;
  const nistFunction = functionById.get(functionId);
  if (!nistFunction) throw new Error(`Rule ${ruleId} uses unknown NIST function ${functionId}`);
  let cis: FindingTaxonomy["cis"] = null;
  if (rule.cis) {
    const control = cisByControl.get(rule.cis.control);
    if (!control) throw new Error(`Rule ${ruleId} uses unknown CIS control ${rule.cis.control}`);
    cis = {
      version: "8.1",
      control: control.control,
      controlTitle: control.title,
      ...(rule.cis.safeguard ? { safeguard: rule.cis.safeguard } : {}),
      ...(rule.cis.safeguardTitle ? { safeguardTitle: rule.cis.safeguardTitle } : {}),
    };
  }
  return {
    domain: domain.id,
    domainLabel: domain.label,
    nistCsf: {
      function: nistFunction.id,
      functionLabel: nistFunction.label,
      category: rule.nist,
      categoryLabel,
    },
    cis,
  };
}

export function createFinding(
  input: Omit<Finding, "taxonomy" | "occurrenceId"> & { occurrenceId?: string },
): Finding {
  return {
    ...input,
    occurrenceId: input.occurrenceId ?? `${input.id}:${input.file}:${input.line}`,
    taxonomy: taxonomyFor(input.id),
  };
}

export function emptyDomainCounts(): { id: TaxonomyDomainId; label: string; critical: number; high: number; medium: number; low: number; informational: number; total: number }[] {
  return taxonomyDomains().map((domain) => ({
    id: domain.id,
    label: domain.label,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    informational: 0,
    total: 0,
  }));
}
