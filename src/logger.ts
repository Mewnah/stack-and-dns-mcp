/**
 * Structured JSON logger that writes exclusively to stderr.
 *
 * The stdio MCP transport owns stdout for protocol frames, so every log line
 * (in both transports) goes to stderr to guarantee the protocol stream is
 * never corrupted.
 */

export type LogLevel = "debug" | "info" | "warn" | "error" | "silent";

const LEVEL_WEIGHT: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
  silent: 100
};

const SECRET_KEY_PATTERN = /(secret|token|password|api[-_]?key|authorization|credential|client_secret)/i;

let activeLevel: LogLevel = "info";

export function setLogLevel(level: LogLevel): void {
  activeLevel = level;
}

export function getLogLevel(): LogLevel {
  return activeLevel;
}

function redact(value: unknown, depth = 0): unknown {
  if (depth > 4) return "[depth]";
  if (value instanceof Error) {
    return { name: value.name, message: value.message, code: (value as NodeJS.ErrnoException).code };
  }
  if (Array.isArray(value)) return value.slice(0, 50).map((v) => redact(v, depth + 1));
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = SECRET_KEY_PATTERN.test(k) && typeof v === "string" ? "[redacted]" : redact(v, depth + 1);
    }
    return out;
  }
  if (typeof value === "string" && value.length > 2000) {
    return value.slice(0, 2000) + "...[+" + String(value.length - 2000) + " chars]";
  }
  return value;
}

function emit(level: Exclude<LogLevel, "silent">, msg: string, meta?: Record<string, unknown>): void {
  if (LEVEL_WEIGHT[level] < LEVEL_WEIGHT[activeLevel]) return;
  const record: Record<string, unknown> = { ts: new Date().toISOString(), level, msg };
  let line: string;
  try {
    // Redaction enumerates caller-supplied objects, so a throwing getter or a
    // revoked proxy must be contained here: a logger that throws from inside
    // a catch handler would turn an error report into a hung request.
    if (meta) Object.assign(record, redact(meta) as Record<string, unknown>);
    line = JSON.stringify(record);
  } catch {
    line = JSON.stringify({ ts: record.ts, level, msg, meta: "[unserializable]" });
  }
  process.stderr.write(line + "\n");
}

export const logger = {
  debug: (msg: string, meta?: Record<string, unknown>) => emit("debug", msg, meta),
  info: (msg: string, meta?: Record<string, unknown>) => emit("info", msg, meta),
  warn: (msg: string, meta?: Record<string, unknown>) => emit("warn", msg, meta),
  error: (msg: string, meta?: Record<string, unknown>) => emit("error", msg, meta)
};

export type Logger = typeof logger;
