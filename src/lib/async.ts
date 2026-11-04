/**
 * Small concurrency primitives shared by the inspectors.
 */

export class TimeoutError extends Error {
  readonly code = "ETIMEOUT";
  constructor(label: string, ms: number) {
    super(`${label} timed out after ${ms}ms`);
    this.name = "TimeoutError";
  }
}

export class AbortError extends Error {
  readonly code = "ABORT_ERR";
  constructor(message = "The operation was aborted") {
    super(message);
    this.name = "AbortError";
  }
}

/** The error a fired signal should surface as: its reason when that is an Error, else an AbortError carrying a string reason. */
export function abortReason(signal: AbortSignal): Error {
  if (signal.reason instanceof Error) return signal.reason;
  return new AbortError(typeof signal.reason === "string" && signal.reason.length > 0 ? signal.reason : undefined);
}

/** Throws the signal's reason (or an AbortError) once the signal has fired. */
export function throwIfAborted(signal: AbortSignal | undefined): void {
  if (!signal?.aborted) return;
  throw abortReason(signal);
}

/**
 * Settles with the promise, or rejects as soon as the signal fires. The
 * losing promise is still observed, so a late rejection is never unhandled.
 */
export function untilAborted<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) {
    promise.catch(() => undefined);
    return Promise.reject(abortReason(signal));
  }
  let onAbort = (): void => undefined;
  const aborted = new Promise<never>((_, reject) => {
    onAbort = () => reject(abortReason(signal));
    signal.addEventListener("abort", onAbort, { once: true });
  });
  return Promise.race([promise, aborted]).finally(() => signal.removeEventListener("abort", onAbort)) as Promise<T>;
}

export function withTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new TimeoutError(label, ms)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => {
    if (timer) clearTimeout(timer);
  }) as Promise<T>;
}

/**
 * Runs fn over items with bounded parallelism. When a signal is supplied no
 * new item is started after it fires, so a cancelled or timed-out tool call
 * stops fanning out DNS and HTTP work instead of running it to completion
 * in the background.
 */
export async function mapConcurrent<T, R>(items: readonly T[], concurrency: number, fn: (item: T, index: number) => Promise<R>, signal?: AbortSignal): Promise<R[]> {
  throwIfAborted(signal);
  const results: R[] = new Array(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.max(1, Math.min(concurrency, items.length)) }, async () => {
    while (next < items.length) {
      throwIfAborted(signal);
      const index = next++;
      const item = items[index] as T;
      results[index] = await fn(item, index);
    }
  });
  await Promise.all(workers);
  return results;
}

export type Settled<T> = { ok: true; value: T } | { ok: false; error: unknown };

export async function settle<T>(promise: Promise<T>): Promise<Settled<T>> {
  try {
    return { ok: true, value: await promise };
  } catch (error) {
    return { ok: false, error };
  }
}

/** Combines a deadline with an optional caller signal so either one aborts the operation. */
export function deadlineSignal(timeoutMs: number, signal?: AbortSignal): AbortSignal {
  const timeout = AbortSignal.timeout(timeoutMs);
  return signal ? AbortSignal.any([timeout, signal]) : timeout;
}
