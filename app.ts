// The forge's HTTP surface: one protocol wrapper for every route the entry serves.
// main.ts (the entry <-> env lifecycle) is untouched; this file is the server it grows.
//
// Wrapper guarantees, from the suite source (program/env/src):
// - Every response is JSON and carries a non-empty X-GitHub-Request-Id, including 401/404/400/500
//   (checks-rest.ts:53, :240, :1235 assert it on all paths, so it is set in one place: sendJson).
// - No token -> 401 with a JSON {message}; a wrong token is the same 401 (checks-rest.ts:13).
// - A malformed JSON body on a JSON route -> 400 with a JSON {message}; git smart-HTTP bodies are
//   binary pkt-lines and are never JSON-parsed (they get the raw buffer instead).
// - Unknown route -> GitHub's JSON 404 {message: 'Not Found'} (the starter's behaviour, kept).
// - The handler never throws out of a request: an unexpected error is a JSON 500 and the process
//   stays up (one crash would zero every column: checks-git.ts repo-survives-errors).
// - Determinism: the request id is a monotonic counter only. No Date.now(), no Math.random(),
//   no randomUUID() anywhere in this file; request-time state never enters the export.
//
// Auth model: the only credential is the bearer token the env sets as MAKEFUN_SHOP_TOKEN
// (wire.ts:81-82). A request is authenticated when its Authorization header carries exactly that
// value ("Bearer <token>" or "token <token>"). /healthz and the API root answer without auth, as
// the starter did; every other /api/v3, /api/graphql, /mcp and *.git path requires it.

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { createStore, type Store } from './store.ts';
import { handleGit } from './git.ts';
import { handleMcp } from './mcp.ts';
import { handleRest, type RestContext } from './rest.ts';

const JSON_TYPE = 'application/json; charset=utf-8';
/** Largest request body accepted; anything bigger is a 413 (trial packs are far below this). */
const MAX_BODY_BYTES = 16 * 1024 * 1024;

/** Monotonic request counter: the only source of request ids (deterministic, no clock/random). */
let requestSeq = 0;

/** Answer one request with a JSON body; the request id rides on every response. */
function sendJson(
  res: ServerResponse,
  requestId: string,
  status: number,
  body: unknown,
  headers: Readonly<Record<string, string>> = {},
): void {
  const text = `${JSON.stringify(body)}\n`;
  res.writeHead(status, {
    'content-type': JSON_TYPE,
    'content-length': Buffer.byteLength(text),
    'x-github-request-id': requestId,
    ...headers,
  });
  res.end(text);
}

/** The path and query of a request URL (never a throw from a request). */
function parseRequestUrl(req: IncomingMessage): { path: string; query: URLSearchParams } {
  try {
    const url = new URL(req.url ?? '/', 'http://entry');
    return { path: url.pathname, query: url.searchParams };
  } catch {
    return { path: '/', query: new URLSearchParams() };
  }
}

/** The bearer token a request carries, or null when the header is absent or malformed. */
function bearerToken(req: IncomingMessage): string | null {
  const header = req.headers.authorization;
  if (typeof header !== 'string') return null;
  const match = /^(?:Bearer|token)\s+(\S+)$/i.exec(header.trim());
  return match === null ? null : match[1];
}

/** True when the request carries exactly the env's token (the suite's only credential). */
function isAuthenticated(req: IncomingMessage): boolean {
  const expected = process.env.MAKEFUN_SHOP_TOKEN ?? '';
  if (expected === '') return false;
  const presented = bearerToken(req);
  return presented !== null && presented === expected;
}

/** Read the whole request body as bytes; rejects when it passes MAX_BODY_BYTES. */
function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise<Buffer>((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on('data', (chunk: Buffer) => {
      total += chunk.length;
      if (total > MAX_BODY_BYTES) {
        reject(new Error('request body too large'));
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

/**
 * Parse a JSON body. Empty body -> { ok: true, value: undefined } (routes validate the fields
 * they need). Non-empty but unparseable -> { ok: false } and the caller answers 400.
 */
function parseJsonBody(raw: Buffer): { ok: true; value: unknown } | { ok: false } {
  if (raw.length === 0) return { ok: true, value: undefined };
  try {
    return { ok: true, value: JSON.parse(raw.toString('utf8')) as unknown };
  } catch {
    return { ok: false };
  }
}

/** Whether a path needs authentication (everything except the health probe and the API root). */
function needsAuth(path: string): boolean {
  if (path === '/healthz') return false;
  if (path === '/api/v3' || path === '/api/v3/') return false;
  return (
    path.startsWith('/api/v3/') ||
    path.startsWith('/api/graphql') ||
    path.startsWith('/mcp') ||
    path.includes('/.git/') ||
    path.endsWith('/.git') ||
    path.endsWith('/info/refs') ||
    path.endsWith('/git-upload-pack') ||
    path.endsWith('/git-receive-pack')
  );
}

/** Whether a path carries a JSON body (REST/GraphQL). MCP parses its own raw body (it must
 *  answer malformed JSON with JSON-RPC -32700, not the generic 400); git paths are binary. */
function isJsonRoute(path: string): boolean {
  return path.startsWith('/api/v3/') || path.startsWith('/api/graphql');
}

/** Build the server. It binds nothing until the caller listens; the entry listens on an ephemeral port. */
export function createApp(): Server {
  // One store per server: the trial's whole state lives here and nowhere else.
  const store: Store = createStore();
  return createServer((req: IncomingMessage, res: ServerResponse) => {
    const requestId = `req-${(requestSeq += 1)}`;
    void (async () => {
      try {
        const { path, query } = parseRequestUrl(req);
        const method = req.method ?? 'GET';

        // The env's boot check calls this twice: 200 {"ok":true}.
        if (method === 'GET' && path === '/healthz') {
          sendJson(res, requestId, 200, { ok: true });
          return;
        }

        // The GitHub API root: a 200 with the token's scopes, as api.github.com answers GET /.
        if (method === 'GET' && (path === '/api/v3' || path === '/api/v3/')) {
          sendJson(
            res,
            requestId,
            200,
            { current_user_url: '/api/v3/user', rate_limit_url: '/api/v3/rate_limit' },
            { 'x-oauth-scopes': 'repo, read:org' },
          );
          return;
        }

        // Auth gate: no token (or a wrong one) is a JSON 401 on every protected path.
        if (needsAuth(path) && !isAuthenticated(req)) {
          sendJson(res, requestId, 401, { message: 'Requires authentication' });
          return;
        }

        // Read the body for requests that may carry one. JSON routes get a parsed value and
        // answer 400 on malformed JSON; git routes keep the raw buffer for the git layer.
        let body: unknown;
        let rawBody: Buffer | undefined;
        if (method === 'POST' || method === 'PUT' || method === 'PATCH') {
          try {
            rawBody = await readBody(req);
          } catch {
            sendJson(res, requestId, 413, { message: 'Request body too large' });
            return;
          }
          if (isJsonRoute(path)) {
            const parsed = parseJsonBody(rawBody);
            if (!parsed.ok) {
              sendJson(res, requestId, 400, { message: 'Problems parsing JSON' });
              return;
            }
            body = parsed.value;
          }
        }
        // Git smart HTTP (Tahap 2): binary pkt-line protocol; it writes its own response
        // (binary or JSON) and returns true when the path is a git path.
        if (
          handleGit({
            store,
            method,
            path,
            query,
            headers: req.headers,
            rawBody: rawBody ?? Buffer.alloc(0),
            res,
            requestId,
          })
        ) {
          return;
        }

        // MCP (Tahap 4): JSON-RPC 2.0 on POST /mcp; it parses its own raw body (malformed
        // JSON must answer -32700) and writes its own response. Returns true on /mcp paths.
        if (
          handleMcp({
            store,
            method,
            path,
            rawBody: rawBody ?? Buffer.alloc(0),
            res,
            requestId,
          })
        ) {
          return;
        }

        // REST v3 dispatch: repos, refs, contents, labels, issues.
        const handled = await handleRest({
          method,
          path,
          query,
          body,
          requestId,
          host: typeof req.headers.host === 'string' ? req.headers.host : '127.0.0.1',
          store,
          reply: (status: number, replyBody: unknown, headers: Record<string, string> = {}) => {
            if (replyBody === null) {
              res.writeHead(status, { 'x-github-request-id': requestId, ...headers });
              res.end();
              return;
            }
            sendJson(res, requestId, status, replyBody, headers);
          },
        } satisfies RestContext);
        if (handled) return;

        // No route implemented for this path: GitHub's JSON 404.
        sendJson(res, requestId, 404, { message: 'Not Found' });
      } catch {
        // Never let one bad request kill the process: answer 500 and keep serving.
        if (!res.headersSent) {
          sendJson(res, requestId, 500, { message: 'Internal Server Error' });
        } else {
          res.end();
        }
      }
    })();
  });
}
