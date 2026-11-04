/**
 * Shared vendor-matching helper for the MX, SPF, DKIM CNAME and DKIM
 * selector tables. Each analyzer keeps its own table because the inputs
 * differ (exchange hosts, include targets, CNAME targets, selector names),
 * but the lookup loop and the display names are shared so one vendor is
 * reported under one name across the whole email report.
 */

export type ProviderTable = ReadonlyArray<readonly [RegExp, string]>;

/** First table entry whose pattern matches the lower-cased, dot-trimmed value. */
export function matchProvider(table: ProviderTable, value: string | null | undefined): string | null {
  if (!value) return null;
  const normalized = value.toLowerCase().replace(/\.$/, "");
  for (const [pattern, provider] of table) {
    if (pattern.test(normalized)) return provider;
  }
  return null;
}
