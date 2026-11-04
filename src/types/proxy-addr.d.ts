/**
 * Minimal typings for proxy-addr (the parser Express uses for "trust proxy").
 * Only the surface used by src/config.ts is declared.
 */
declare module "proxy-addr" {
  import type { IncomingMessage } from "node:http";

  type TrustFunction = (addr: string, hopIndex: number) => boolean;

  function proxyaddr(req: IncomingMessage, trust: string | string[] | number | boolean | TrustFunction): string;

  namespace proxyaddr {
    function all(req: IncomingMessage, trust?: string | string[] | number | boolean | TrustFunction): string[];
    function compile(val: string | string[]): TrustFunction;
  }

  export = proxyaddr;
}
