/**
 * Local stdio transport for Cursor, Claude Desktop, Claude Code and any
 * other MCP client that spawns the server as a subprocess.
 */

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { logger } from "../logger.js";
import { createMcpServer, type ServerDeps } from "../server.js";

/** Connects the server to stdin/stdout; onClose runs the process shutdown when the client goes away. */
export async function startStdio(deps: ServerDeps, onClose: () => void): Promise<void> {
  const server = createMcpServer(deps);
  const transport = new StdioServerTransport();
  transport.onerror = (err: Error) => logger.error("stdio transport error", { error: err });
  transport.onclose = () => {
    logger.info("stdio transport closed; shutting down");
    onClose();
  };
  await server.connect(transport);
  // The SDK transport never listens for stdin EOF. A client that disconnects
  // by closing stdin would otherwise let the process simply exit, skipping
  // the shutdown that flushes usage, releases the worker lease and closes the
  // database. transport.close() fires onclose; shutdown is idempotent.
  const onStdinGone = (): void => {
    void transport.close();
  };
  process.stdin.once("end", onStdinGone);
  process.stdin.once("close", onStdinGone);
  process.stdout.once("error", onStdinGone);
  logger.info("stack-and-dns-mcp ready on stdio", {
    version: deps.config.version,
    principal: deps.localPrincipal.id,
    plan: deps.localPrincipal.plan,
    requireAuth: deps.config.auth.requireAuth
  });
}
