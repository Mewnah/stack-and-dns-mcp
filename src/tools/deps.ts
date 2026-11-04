/**
 * Dependencies shared by every tool handler. Built once per process by the
 * registration layer and threaded into each handler call.
 */

import type { AppConfig } from "../config.js";
import type { DnsClient } from "../lib/dns.js";

export interface ToolDeps {
  config: AppConfig;
  dns: DnsClient;
  /**
   * DKIM selectors already known to hold a key for a domain (from stored
   * scans). Every email scan probes them, so a scan is always comparable
   * with the stored posture however it was started.
   */
  knownDkimSelectors?: (domain: string) => string[];
}
