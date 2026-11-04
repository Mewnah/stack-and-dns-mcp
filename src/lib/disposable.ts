/**
 * Disposable / throwaway email domain detection backed by a curated list
 * of well-known temporary-inbox providers.
 */

import disposableDomains from "../data/disposable-domains.json" with { type: "json" };

const DISPOSABLE_SET: ReadonlySet<string> = new Set((disposableDomains as string[]).map((d) => d.toLowerCase()));

export const DISPOSABLE_DOMAIN_COUNT = DISPOSABLE_SET.size;

export interface DisposableCheck {
  disposable: boolean;
  matchedDomain: string | null;
}

/**
 * Matches the exact domain and every parent suffix, so mail.mailinator.com
 * is flagged because mailinator.com is on the list.
 */
export function checkDisposableDomain(domain: string): DisposableCheck {
  const labels = domain.toLowerCase().split(".");
  for (let i = 0; i < labels.length - 1; i++) {
    const candidate = labels.slice(i).join(".");
    if (DISPOSABLE_SET.has(candidate)) return { disposable: true, matchedDomain: candidate };
  }
  return { disposable: false, matchedDomain: null };
}
