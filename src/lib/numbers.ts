/**
 * Bounded numeric parsing for values that come from remote DNS records and
 * HTTP headers. Number("9".repeat(400)) is Infinity, which the output schemas
 * reject, so every remote integer is parsed through here.
 */

const MAX_DIGITS = 15;

/** Parses a non-negative decimal integer, returning null when absent, malformed or beyond the safe-integer range. */
export function parseSafeInteger(value: string | undefined | null): number | null {
  if (typeof value !== "string") return null;
  const raw = value.trim();
  if (raw.length === 0 || !/^\d+$/.test(raw)) return null;
  // Leading zeros are legal in max-age / max_age values and carry no magnitude.
  const digits = raw.replace(/^0+(?=\d)/, "");
  if (digits.length > MAX_DIGITS) return null;
  const n = Number(digits);
  return Number.isSafeInteger(n) ? n : null;
}
