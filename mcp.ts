// MCP (Model Context Protocol) surface: JSON-RPC 2.0 streamable HTTP on POST /mcp.
// Modern era only (server/discover, revision 2026-07-28) plus a minimal legacy `initialize`
// fallback. Every tool is a thin adapter over the verified REST handlers — the MCP layer
// builds a synthetic RestContext whose reply closure captures the result, so MCP and REST
// read and write the same store through the same code path (one store, one id allocator).
//
// Wire facts (program/env/src/mcp-client.ts, checks-mcp.ts; see phase1/checks-graphql-mcp.md):
// - Per-request timeout 3 s (mcp-client.ts:61): every handler must answer fast; all six
//   tools are synchronous store operations, so this is trivially met.
// - server/discover returns {supportedVersions: ["2026-07-28"], serverInfo, capabilities:
//   {tools: {}}}; serverInfo is read from result._meta["io.modelcontextprotocol/serverInfo"]
//   first, else result.serverInfo.
// - tools/list must be byte-identical across calls: the tool table is a frozen constant.
// - Unknown tool -> JSON-RPC -32601 (HTTP 200, never 500). Missing required args -> a tool
//   result with isError: true (or -32602); never create a partial object.
// - Malformed JSON body -> HTTP 400 + JSON-RPC -32700 (id null). This needs the RAW body,
//   so app.ts routes /mcp here without pre-parsing it as JSON.
// - Auth is enforced per request by app.ts's gate (401 before this handler runs).
// - JSON-RPC ids are echoed exactly as received (string ids stay strings).
// - Determinism: no Date.now()/Math.random()/randomUUID() anywhere in this file.

import type { ServerResponse } from 'node:http';
import { handleRest, type RestContext } from './rest.ts';
import type { Store } from './store.ts';

const SERVER_NAME = 'github-core-clone';
const SERVER_VERSION = '0.1.0';
const PREFERRED_REVISION = '2026-07-28';

/* ------------------------------------------------------------------ JSON-RPC */

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isRevision(value: unknown): value is string {
  return typeof value === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(value);
}

type JsonRpcId = string | number | null;

function rpcResult(id: JsonRpcId, result: unknown): Record<string, unknown> {
  return { jsonrpc: '2.0', id, result };
}

function rpcError(id: JsonRpcId, code: number, message: string): Record<string, unknown> {
  return { jsonrpc: '2.0', id, error: { code, message } };
}

/** Write one MCP HTTP response (JSON body, or an empty body when body is null). */
function sendMcp(res: ServerResponse, requestId: string, status: number, body: unknown): void {
  if (body === null) {
    res.writeHead(status, { 'x-github-request-id': requestId });
    res.end();
    return;
  }
  const text = `${JSON.stringify(body)}\n`;
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(text),
    'x-github-request-id': requestId,
  });
  res.end(text);
}

/* ------------------------------------------------------------------ tool table */

// The six required tools (checks-mcp.ts:70). A frozen constant: tools/list returns this
// same object on every call, so the list is byte-identical (mcp.tools-list-idempotent).
interface McpToolDef {
  name: string;
  description: string;
  inputSchema: {
    type: 'object';
    properties: Record<string, { type: string; description?: string }>;
    required: string[];
  };
}

const TOOLS: McpToolDef[] = [
  {
    name: 'create_repo',
    description: 'Create a new repository for the authenticated user.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Repository name.' },
        description: { type: 'string', description: 'Repository description.' },
        private: { type: 'boolean', description: 'Whether the repository is private.' },
        owner: { type: 'string', description: 'Owner login (ignored; the token owner is used).' },
      },
      required: ['name'],
    },
  },
  {
    name: 'get_repo',
    description: 'Get a repository by owner and name.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Owner login.' },
        repo: { type: 'string', description: 'Repository name.' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Owner login.' },
        repo: { type: 'string', description: 'Repository name.' },
        title: { type: 'string', description: 'Issue title.' },
        body: { type: 'string', description: 'Issue body.' },
      },
      required: ['owner', 'repo', 'title'],
    },
  },
  {
    name: 'list_issues',
    description: 'List issues in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Owner login.' },
        repo: { type: 'string', description: 'Repository name.' },
        state: { type: 'string', description: 'Issue state: open, closed, or all.' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_pull_request',
    description: 'Create a pull request.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Owner login.' },
        repo: { type: 'string', description: 'Repository name.' },
        title: { type: 'string', description: 'Pull request title.' },
        body: { type: 'string', description: 'Pull request body.' },
        head: { type: 'string', description: 'Head branch name.' },
        base: { type: 'string', description: 'Base branch name.' },
      },
      required: ['owner', 'repo', 'title', 'head', 'base'],
    },
  },
  {
    name: 'merge_pull_request',
    description: 'Merge a pull request (squash).',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Owner login.' },
        repo: { type: 'string', description: 'Repository name.' },
        pull_number: { type: 'integer', description: 'Pull request number.' },
      },
      required: ['owner', 'repo', 'pull_number'],
    },
  },
];

function deepFreeze<T>(value: T): T {
  if (typeof value === 'object' && value !== null) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}
deepFreeze(TOOLS);

/* ------------------------------------------------------------------ arguments */

// Argument synonyms (checks-mcp.ts:185-205). The suite maps its semantic args to the
// property names of the tool's inputSchema, so with canonical schema names it sends
// canonical names; the synonym lookup below is insurance for any alias it may pass.
const ARG_SYNONYMS: Record<string, string[]> = {
  owner: ['owner', 'owner_login', 'org', 'organization', 'organisation', 'user', 'user_login', 'login', 'account', 'namespace', 'owner_name'],
  repo: ['repo', 'repository', 'repository_name', 'repo_name', 'repo_slug', 'project', 'project_name'],
  title: ['title', 'issue_title', 'pr_title', 'pull_request_title', 'subject'],
  body: ['body', 'issue_body', 'description', 'content', 'text', 'comment'],
  head: ['head', 'head_ref', 'head_branch', 'pull_request_head', 'pr_head', 'source', 'source_ref', 'source_branch', 'from', 'from_branch', 'branch'],
  base: ['base', 'base_ref', 'base_branch', 'pull_request_base', 'pr_base', 'target', 'target_ref', 'target_branch', 'into', 'into_branch'],
  pull_number: ['pull_number', 'pull_request_number', 'pr_number', 'number', 'issue_number', 'index'],
  name: ['name', 'repo', 'repository', 'repository_name', 'repo_name'],
  description: ['description', 'about', 'summary', 'body'],
  private: ['private', 'is_private'],
  state: ['state', 'status'],
};

/** First value found for a semantic argument, canonical name first, then synonyms. */
function argValue(args: Record<string, unknown>, canonical: string): unknown {
  for (const name of ARG_SYNONYMS[canonical] ?? [canonical]) {
    if (args[name] !== undefined) return args[name];
  }
  return undefined;
}

/** A required non-empty string argument, or undefined when absent/invalid. */
function argString(args: Record<string, unknown>, canonical: string): string | undefined {
  const value = argValue(args, canonical);
  return typeof value === 'string' && value !== '' ? value : undefined;
}

/** A required integer argument (a JSON number, or a digit string), or undefined. */
function argInt(args: Record<string, unknown>, canonical: string): number | undefined {
  const value = argValue(args, canonical);
  if (typeof value === 'number' && Number.isInteger(value) && value >= 1) return value;
  if (typeof value === 'string' && /^\d+$/.test(value)) return Number.parseInt(value, 10);
  return undefined;
}

/** Owner + repo for a repo-scoped tool; falls back to splitting a "owner/repo" full_name. */
function repoArgs(args: Record<string, unknown>): { owner: string; repo: string } | null {
  let owner = argString(args, 'owner');
  let repo = argString(args, 'repo');
  if ((owner === undefined || repo === undefined) && typeof args['full_name'] === 'string') {
    const parts = (args['full_name'] as string).split('/');
    if (parts.length === 2 && parts[0] !== '' && parts[1] !== '') {
      owner ??= parts[0];
      repo ??= parts[1];
    }
  }
  if (owner === undefined || repo === undefined) return null;
  return { owner, repo };
}

/* ------------------------------------------------------------------ tool results */

interface ToolResult {
  content: Array<{ type: 'text'; text: string }>;
  structuredContent?: unknown;
  isError?: boolean;
}

/** A successful tool result: the data as a JSON text block and as structuredContent. */
function toolOk(data: unknown): ToolResult {
  const text = typeof data === 'string' ? data : JSON.stringify(data);
  return { content: [{ type: 'text', text }], structuredContent: data };
}

/** A failed tool call: a well-formed tool result with isError: true (never a 500). */
function toolErr(message: string): ToolResult {
  return { content: [{ type: 'text', text: message }], isError: true };
}

/* ------------------------------------------------------------------ REST bridge */

// Call a verified REST route with a synthetic context and capture its reply. This is how
// every tool touches the store: the same validation, number/id allocation, conflict check
// and squash merge the REST surface uses, so MCP and REST can never diverge.
async function callRest(
  store: Store,
  method: string,
  path: string,
  query: URLSearchParams,
  body: unknown,
): Promise<{ status: number; body: unknown } | null> {
  let captured: { status: number; body: unknown } | null = null;
  const ctx: RestContext = {
    method,
    path,
    query,
    body,
    requestId: 'mcp',
    host: '127.0.0.1',
    store,
    reply: (status, replyBody) => {
      captured = { status, body: replyBody };
    },
  };
  const handled = await handleRest(ctx);
  return handled ? captured : null;
}

function restMessage(body: unknown): string {
  if (isRecord(body) && typeof body.message === 'string') return body.message;
  return 'Request failed';
}

/* ------------------------------------------------------------------ tool handlers */

async function toolCreateRepo(store: Store, args: Record<string, unknown>): Promise<ToolResult> {
  const name = argString(args, 'name');
  if (name === undefined) return toolErr('missing required argument: name');
  const description = argString(args, 'description');
  const priv = argValue(args, 'private');
  const res = await callRest(store, 'POST', '/api/v3/user/repos', new URLSearchParams(), {
    name,
    ...(description !== undefined ? { description } : {}),
    ...(priv === true ? { private: true } : {}),
  });
  if (res === null) return toolErr('create_repo is not available');
  if (res.status === 201) return toolOk(res.body);
  return toolErr(restMessage(res.body));
}

async function toolGetRepo(store: Store, args: Record<string, unknown>): Promise<ToolResult> {
  const target = repoArgs(args);
  if (target === null) return toolErr('missing required argument: owner or repo');
  const res = await callRest(
    store,
    'GET',
    `/api/v3/repos/${encodeURIComponent(target.owner)}/${encodeURIComponent(target.repo)}`,
    new URLSearchParams(),
    undefined,
  );
  if (res === null) return toolErr('get_repo is not available');
  if (res.status === 200) return toolOk(res.body);
  return toolErr(restMessage(res.body));
}

async function toolCreateIssue(store: Store, args: Record<string, unknown>): Promise<ToolResult> {
  const target = repoArgs(args);
  if (target === null) return toolErr('missing required argument: owner or repo');
  const title = argString(args, 'title');
  if (title === undefined) return toolErr('missing required argument: title');
  const body = argString(args, 'body');
  const res = await callRest(
    store,
    'POST',
    `/api/v3/repos/${encodeURIComponent(target.owner)}/${encodeURIComponent(target.repo)}/issues`,
    new URLSearchParams(),
    { title, ...(body !== undefined ? { body } : {}) },
  );
  if (res === null) return toolErr('create_issue is not available');
  if (res.status === 201) return toolOk(res.body);
  return toolErr(restMessage(res.body));
}

async function toolListIssues(store: Store, args: Record<string, unknown>): Promise<ToolResult> {
  const target = repoArgs(args);
  if (target === null) return toolErr('missing required argument: owner or repo');
  const state = (argString(args, 'state') ?? 'open').toLowerCase();
  const query = new URLSearchParams({ state, per_page: '100' });
  const res = await callRest(
    store,
    'GET',
    `/api/v3/repos/${encodeURIComponent(target.owner)}/${encodeURIComponent(target.repo)}/issues`,
    query,
    undefined,
  );
  if (res === null) return toolErr('list_issues is not available');
  if (res.status === 200) return toolOk(res.body);
  return toolErr(restMessage(res.body));
}

async function toolCreatePullRequest(store: Store, args: Record<string, unknown>): Promise<ToolResult> {
  const target = repoArgs(args);
  if (target === null) return toolErr('missing required argument: owner or repo');
  const title = argString(args, 'title');
  const head = argString(args, 'head');
  const base = argString(args, 'base');
  if (title === undefined) return toolErr('missing required argument: title');
  if (head === undefined) return toolErr('missing required argument: head');
  if (base === undefined) return toolErr('missing required argument: base');
  const body = argString(args, 'body');
  const res = await callRest(
    store,
    'POST',
    `/api/v3/repos/${encodeURIComponent(target.owner)}/${encodeURIComponent(target.repo)}/pulls`,
    new URLSearchParams(),
    { title, head, base, ...(body !== undefined ? { body } : {}) },
  );
  if (res === null) return toolErr('create_pull_request is not available');
  if (res.status === 201) return toolOk(res.body);
  return toolErr(restMessage(res.body));
}

async function toolMergePullRequest(store: Store, args: Record<string, unknown>): Promise<ToolResult> {
  const target = repoArgs(args);
  if (target === null) return toolErr('missing required argument: owner or repo');
  const pullNumber = argInt(args, 'pull_number');
  if (pullNumber === undefined) return toolErr('missing required argument: pull_number');
  const res = await callRest(
    store,
    'PUT',
    `/api/v3/repos/${encodeURIComponent(target.owner)}/${encodeURIComponent(target.repo)}/pulls/${pullNumber}/merge`,
    new URLSearchParams(),
    undefined,
  );
  if (res === null) return toolErr('merge_pull_request is not available');
  if (res.status === 200) return toolOk(res.body);
  return toolErr(restMessage(res.body));
}

const TOOL_HANDLERS: Record<string, (store: Store, args: Record<string, unknown>) => Promise<ToolResult>> = {
  create_repo: toolCreateRepo,
  get_repo: toolGetRepo,
  create_issue: toolCreateIssue,
  list_issues: toolListIssues,
  create_pull_request: toolCreatePullRequest,
  merge_pull_request: toolMergePullRequest,
};

/* ------------------------------------------------------------------ dispatcher */

export interface McpContext {
  store: Store;
  method: string;
  path: string;
  rawBody: Buffer;
  res: ServerResponse;
  requestId: string;
}

const SERVER_INFO = { name: SERVER_NAME, version: SERVER_VERSION };

/**
 * Handle an MCP request. Returns true when the path is an MCP path (the response has
 * been written); false when it is not an MCP path at all. Never throws out of a request:
 * a malformed request is answered with the matching JSON-RPC error, never a 500.
 */
export function handleMcp(ctx: McpContext): boolean {
  if (ctx.path !== '/mcp' && !ctx.path.startsWith('/mcp/')) return false;
  try {
    // Session close (best-effort DELETE): nothing to tear down, answer 200 empty.
    if (ctx.method === 'DELETE') {
      sendMcp(ctx.res, ctx.requestId, 200, null);
      return true;
    }
    if (ctx.method !== 'POST') {
      sendMcp(ctx.res, ctx.requestId, 405, { message: 'Method Not Allowed' });
      return true;
    }
    // Parse the raw body as JSON. Unparseable -> HTTP 400 + JSON-RPC -32700 (id null).
    let parsed: unknown;
    try {
      parsed = ctx.rawBody.length === 0 ? undefined : JSON.parse(ctx.rawBody.toString('utf8'));
    } catch {
      sendMcp(ctx.res, ctx.requestId, 400, rpcError(null, -32700, 'Parse error'));
      return true;
    }
    if (!isRecord(parsed) || typeof parsed.method !== 'string') {
      const id: JsonRpcId =
        isRecord(parsed) && (typeof parsed.id === 'string' || typeof parsed.id === 'number') ? parsed.id : null;
      sendMcp(ctx.res, ctx.requestId, 200, rpcError(id, -32600, 'Invalid Request'));
      return true;
    }
    // A notification carries no id: answer with an empty 202 and no JSON-RPC body.
    if (!('id' in parsed) || parsed.id === undefined) {
      sendMcp(ctx.res, ctx.requestId, 202, null);
      return true;
    }
    const id: JsonRpcId =
      typeof parsed.id === 'string' || typeof parsed.id === 'number' ? parsed.id : null;
    const method = parsed.method;
    const params = isRecord(parsed.params) ? parsed.params : {};

    // Modern era: server/discover.
    if (method === 'server/discover') {
      sendMcp(
        ctx.res,
        ctx.requestId,
        200,
        rpcResult(id, {
          supportedVersions: [PREFERRED_REVISION],
          serverInfo: SERVER_INFO,
          capabilities: { tools: {} },
          _meta: { 'io.modelcontextprotocol/serverInfo': SERVER_INFO },
        }),
      );
      return true;
    }

    // Legacy era: initialize (only reached when discover fails; kept as a safety net).
    if (method === 'initialize') {
      const offered = isRecord(params) ? params['protocolVersion'] : undefined;
      sendMcp(
        ctx.res,
        ctx.requestId,
        200,
        rpcResult(id, {
          protocolVersion: isRevision(offered) ? offered : PREFERRED_REVISION,
          capabilities: { tools: {} },
          serverInfo: SERVER_INFO,
        }),
      );
      return true;
    }

    if (method === 'ping') {
      sendMcp(ctx.res, ctx.requestId, 200, rpcResult(id, {}));
      return true;
    }

    if (method === 'tools/list') {
      sendMcp(ctx.res, ctx.requestId, 200, rpcResult(id, { tools: TOOLS }));
      return true;
    }

    if (method === 'tools/call') {
      const name = isRecord(params) && typeof params['name'] === 'string' ? params['name'] : '';
      const handler = TOOL_HANDLERS[name];
      if (handler === undefined) {
        sendMcp(ctx.res, ctx.requestId, 200, rpcError(id, -32601, `Method not found: ${name}`));
        return true;
      }
      const args = isRecord(params['arguments']) ? (params['arguments'] as Record<string, unknown>) : {};
      void handler(ctx.store, args)
        .then((result) => {
          sendMcp(ctx.res, ctx.requestId, 200, rpcResult(id, result));
        })
        .catch((err: unknown) => {
          // A tool handler must never become a 500: report it as a tool error.
          sendMcp(ctx.res, ctx.requestId, 200, rpcResult(id, toolErr((err as Error).message)));
        });
      return true;
    }

    // Any other method: JSON-RPC method not found.
    sendMcp(ctx.res, ctx.requestId, 200, rpcError(id, -32601, `Method not found: ${method}`));
    return true;
  } catch {
    try {
      if (!ctx.res.headersSent) sendMcp(ctx.res, ctx.requestId, 200, rpcError(null, -32603, 'Internal error'));
      else ctx.res.end();
    } catch {
      /* the response is already gone; nothing more to do */
    }
    return true;
  }
}
