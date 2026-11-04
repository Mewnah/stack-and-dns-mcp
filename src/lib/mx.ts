/**
 * MX record analysis: provider identification, null-MX detection, dangling
 * exchange detection and implicit-A fallback reporting.
 */

import { isIP } from "node:net";
import { mapConcurrent, throwIfAborted } from "./async.js";
import type { DnsClient, DnsErrorInfo } from "./dns.js";
import type { Finding } from "./findings.js";
import { isPrivateAddress } from "./net.js";
import { matchProvider, type ProviderTable } from "./providers.js";

export interface MxExchange {
  exchange: string;
  priority: number;
  addresses: string[];
  resolvable: boolean;
  /** The A/AAAA lookups failed (SERVFAIL, timeout), so whether the exchange resolves is unknown, not "no". */
  lookupFailed: boolean;
  provider: string | null;
}

export interface MxEvaluation {
  found: boolean;
  nullMx: boolean;
  records: MxExchange[];
  provider: string | null;
  providers: string[];
  usesImplicitA: boolean;
  fallbackAddresses: string[];
  dnsError: DnsErrorInfo | null;
  findings: Finding[];
}

const MX_PROVIDERS: ProviderTable = [
  [/\.(google|googlemail)\.com$/i, "Google Workspace"],
  [/\.mail\.protection\.outlook\.com$/i, "Microsoft 365"],
  [/\.mail\.eo\.outlook\.com$|\.protection\.outlook\.com$/i, "Microsoft 365"],
  [/\.pphosted\.com$|\.ppe-hosted\.com$/i, "Proofpoint"],
  [/\.mimecast\.com$|\.mimecast-offshore\.com$/i, "Mimecast"],
  [/\.zoho\.(com|eu|in|com\.au)$|\.zohomail\.(com|eu|in)$/i, "Zoho Mail"],
  [/\.barracudanetworks\.com$/i, "Barracuda"],
  [/\.messagelabs\.com$/i, "Broadcom (Symantec) Email Security"],
  [/\.secureserver\.net$/i, "GoDaddy"],
  [/\.mailgun\.org$/i, "Mailgun"],
  [/inbound-smtp\.[a-z0-9-]+\.amazonaws\.com$/i, "Amazon SES Inbound"],
  [/\.amazonaws\.com$/i, "Amazon Web Services"],
  [/\.protonmail\.ch$|\.proton\.me$/i, "Proton Mail"],
  [/\.messagingengine\.com$|\.fastmail\.com$/i, "Fastmail"],
  [/\.emailsrvr\.com$/i, "Rackspace Email"],
  [/\.yandex\.(net|ru)$/i, "Yandex"],
  [/\.icloud\.com$|\.me\.com$/i, "iCloud Mail"],
  [/\.titan\.email$/i, "Titan"],
  [/\.hostinger\.com$/i, "Hostinger"],
  [/\.ovh\.net$/i, "OVH"],
  [/\.ionos\.(com|de|co\.uk)$|\.1and1\.(com|co\.uk)$|\.kundenserver\.de$|\.perfora\.net$/i, "IONOS"],
  [/\.mx\.cloudflare\.net$/i, "Cloudflare Email Routing"],
  [/\.improvmx\.com$/i, "ImprovMX"],
  [/\.forwardemail\.net$/i, "Forward Email"],
  [/\.hey\.com$/i, "HEY"],
  [/\.sophos\.com$/i, "Sophos Email"],
  [/\.trendmicro\.(com|eu)$/i, "Trend Micro Email Security"],
  [/\.fireeyecloud\.com$|\.fireeye\.com$/i, "Trellix Email Security"],
  [/\.iphmx\.com$/i, "Cisco Secure Email"],
  [/\.hornetsecurity\.com$|\.antispameurope\.com$/i, "Hornetsecurity"],
  [/\.mailanyone\.net$/i, "MailAnyone"],
  [/\.spamtitan\.com$|\.titanhq\.com$/i, "TitanHQ SpamTitan"],
  [/\.emailarray\.com$/i, "EmailArray"],
  [/\.mxroute\.com$|\.mxrouting\.net$/i, "MXroute"],
  [/\.migadu\.com$/i, "Migadu"],
  [/\.mailbox\.org$/i, "mailbox.org"],
  [/\.posteo\.de$/i, "Posteo"],
  [/\.tutanota\.de$|\.tuta\.com$/i, "Tuta"],
  [/\.mail\.ru$/i, "Mail.ru"],
  [/\.qq\.com$/i, "Tencent Exmail"],
  [/\.aliyun\.com$|\.mxhichina\.com$/i, "Alibaba Mail"],
  [/\.163\.com$|\.netease\.com$/i, "NetEase"],
  [/\.naver\.com$/i, "Naver Works"],
  [/\.hostedemail\.com$/i, "OpenSRS Hosted Email"],
  [/\.emailsecurity\.hosted\.blackberry\.com$/i, "BlackBerry"],
  [/\.mailcontrol\.com$/i, "Forcepoint Email Security"],
  [/\.zix\.com$|\.zixmail\.net$|\.appriver\.com$/i, "Zix / AppRiver"],
  [/\.securence\.com$/i, "Securence"],
  [/\.mailprotector\.net$|\.mailprotector\.com$/i, "Mailprotector"],
  [/\.mail-filter\.net$|\.spambrella\.com$/i, "Spambrella"],
  [/\.mxlogic\.net$/i, "McAfee SaaS Email Protection"],
  [/\.frontbridge\.com$/i, "Microsoft Exchange Online Protection"],
  [/\.dreamhost\.com$/i, "DreamHost"],
  [/\.bluehost\.com$/i, "Bluehost"],
  [/\.hostgator\.com$/i, "HostGator"],
  [/\.siteground\.(com|net|eu|biz)$|\.sgvps\.net$/i, "SiteGround"],
  [/\.wpengine\.com$/i, "WP Engine"],
  [/\.namecheap\.com$|\.privateemail\.com$|\.registrar-servers\.com$/i, "Namecheap Private Email"],
  [/\.web\.com$|\.networksolutions\.com$/i, "Network Solutions"],
  [/\.hover\.com$|\.tucows\.com$/i, "Hover"],
  [/\.gandi\.net$/i, "Gandi"],
  [/\.infomaniak\.(ch|com)$/i, "Infomaniak"],
  [/\.one\.com$/i, "one.com"],
  [/\.strato\.de$|\.rzone\.de$/i, "STRATO"],
  [/\.hetzner\.(de|com)$|\.your-server\.de$/i, "Hetzner"],
  [/\.hosting\.com$|\.a2hosting\.com$/i, "A2 Hosting"],
  [/\.inmotionhosting\.com$/i, "InMotion Hosting"],
  [/\.liquidweb\.com$/i, "Liquid Web"],
  [/\.mailhostbox\.com$/i, "MailHostBox"],
  [/\.mailsystem\.(com|net)$/i, "Mail System"]
];

export function identifyMailProvider(exchange: string): string | null {
  return matchProvider(MX_PROVIDERS, exchange);
}

export async function evaluateMx(domain: string, dns: DnsClient, signal?: AbortSignal): Promise<MxEvaluation> {
  throwIfAborted(signal);
  const findings: Finding[] = [];
  const mx = await dns.mx(domain);
  const evaluation: MxEvaluation = {
    found: false,
    nullMx: false,
    records: [],
    provider: null,
    providers: [],
    usesImplicitA: false,
    fallbackAddresses: [],
    dnsError: mx.error,
    findings
  };

  if (mx.error) {
    findings.push({
      severity: "high",
      code: "MX_DNS_ERROR",
      message: `MX lookup for ${domain} failed (${mx.error.code}).`,
      recommendation: "Verify the authoritative nameservers respond correctly and retry."
    });
  }

  const sorted = [...mx.records].sort((a, b) => a.priority - b.priority || a.exchange.localeCompare(b.exchange));
  const nullMx = sorted.length === 1 && sorted[0] !== undefined && (sorted[0].exchange === "" || sorted[0].exchange === ".") && sorted[0].priority === 0;
  if (nullMx) {
    evaluation.nullMx = true;
    findings.push({
      severity: "info",
      code: "MX_NULL",
      message: "A Null MX record (RFC 7505) is published: this domain explicitly does not accept email.",
      recommendation: "No action needed if the domain is not meant to receive mail."
    });
    return evaluation;
  }

  if (sorted.length === 0) {
    if (mx.error) {
      // A failed query is not an empty answer: whether MX records exist is unknown.
      findings.push({
        severity: "medium",
        code: "MX_MISSING",
        message: `No MX records were returned for ${domain}, but the MX lookup failed (${mx.error.code}), so their absence is unconfirmed.`,
        recommendation: "Retry once the nameservers answer."
      });
      return evaluation;
    }
    const fallback = await dns.addresses(domain);
    evaluation.fallbackAddresses = [...fallback.v4, ...fallback.v6];
    if (evaluation.fallbackAddresses.length === 0 && fallback.errors.length > 0) {
      const codes = [...new Set(fallback.errors.map((e) => e.code))].join(", ");
      findings.push({
        severity: "medium",
        code: "MX_HOST_DNS_ERROR",
        message: `${domain} publishes no MX records and the A/AAAA lookup for the implicit fallback failed (${codes}), so whether it can receive mail is unknown.`,
        recommendation: "Verify the authoritative nameservers respond correctly and retry."
      });
      return evaluation;
    }
    if (evaluation.fallbackAddresses.length > 0) {
      evaluation.usesImplicitA = true;
      findings.push({
        severity: "medium",
        code: "MX_MISSING_IMPLICIT_A",
        message: "No MX records exist; receivers will fall back to the domain's A/AAAA record, which rarely runs a mail server.",
        recommendation: 'Publish MX records for your mail provider, or a Null MX ("0 .") if the domain never receives mail.'
      });
    } else {
      findings.push({
        severity: "high",
        code: "MX_MISSING",
        message: "No MX records and no A/AAAA fallback: this domain cannot receive email.",
        recommendation: "Publish MX records for your mail provider."
      });
    }
    return evaluation;
  }

  evaluation.found = true;
  const resolved = await mapConcurrent(
    sorted.slice(0, 10),
    5,
    async (record) => {
      const exchange = record.exchange.toLowerCase().replace(/\.$/, "");
      const addresses = await dns.addresses(exchange);
      const all = [...addresses.v4, ...addresses.v6];
      return {
        exchange,
        priority: record.priority,
        addresses: all,
        resolvable: all.length > 0,
        lookupFailed: all.length === 0 && addresses.errors.length > 0,
        provider: identifyMailProvider(exchange),
        errorCodes: addresses.errors.map((e) => e.code)
      };
    },
    signal
  );
  evaluation.records = resolved.map(({ errorCodes: _codes, ...record }) => record);

  const providers = [...new Set(resolved.map((r) => r.provider).filter((p): p is string => p !== null))];
  evaluation.providers = providers;
  evaluation.provider = resolved[0]?.provider ?? providers[0] ?? null;

  // An exchange whose address lookup failed is unknown, not dangling.
  const unknown = resolved.filter((r) => r.lookupFailed);
  if (unknown.length > 0) {
    const codes = [...new Set(unknown.flatMap((r) => r.errorCodes))].join(", ");
    findings.push({
      severity: "medium",
      code: "MX_HOST_DNS_ERROR",
      message: `Address lookups for ${unknown.length} MX exchange(s) failed (${codes}): ${unknown.map((r) => r.exchange).join(", ")}. Whether they resolve could not be confirmed.`,
      recommendation: "Verify the exchanges' nameservers respond correctly and retry."
    });
  }
  const dangling = resolved.filter((r) => !r.resolvable && !r.lookupFailed);
  if (dangling.length > 0 && dangling.length === resolved.length) {
    findings.push({
      severity: "critical",
      code: "MX_ALL_UNRESOLVABLE",
      message: `None of the ${resolved.length} MX exchanges resolve to an IP address; inbound mail will bounce.`,
      recommendation: "Fix or replace the MX hostnames."
    });
  } else if (dangling.length > 0) {
    findings.push({
      severity: "medium",
      code: "MX_DANGLING",
      message: `${dangling.length} MX exchange(s) do not resolve: ${dangling.map((d) => d.exchange).join(", ")}.`,
      recommendation: "Remove stale MX entries to avoid delivery delays."
    });
  }
  const privateExchanges = resolved.filter((r) => r.addresses.some((a) => isPrivateAddress(a)));
  if (privateExchanges.length > 0) {
    findings.push({
      severity: "medium",
      code: "MX_PRIVATE_ADDRESS",
      message: `MX exchange(s) resolve to private or reserved IP space: ${privateExchanges.map((d) => d.exchange).join(", ")}.`,
      recommendation: "MX hosts must resolve to publicly routable addresses."
    });
  }
  // Checked over every published exchange, not only the ten that were
  // resolved, and including the RFC 5321 tagged literal form [IPv6:...].
  if (sorted.some((r) => isIP(r.exchange.replace(/\.$/, "").replace(/^\[(?:ipv6:)?|\]$/gi, "")) !== 0)) {
    findings.push({
      severity: "medium",
      code: "MX_IP_LITERAL",
      message: "An MX record points directly at an IP address, which violates RFC 5321 and is rejected by many receivers.",
      recommendation: "Point MX records at hostnames with A/AAAA records."
    });
  }
  if (resolved.length === 1) {
    findings.push({
      severity: "info",
      code: "MX_SINGLE",
      message: "Only one MX exchange is published; there is no backup for inbound mail.",
      recommendation: "Most providers publish multiple MX hosts. Confirm the provider's recommended configuration."
    });
  }
  return evaluation;
}
