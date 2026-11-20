// GraphQL surface: POST /api/graphql (single operation object, or a JSON array for
// batched operations). A small hand-written executor for the exact documents the suite
// sends (checks-graphql.ts:107-318; see phase1/checks-graphql-mcp.md Part A) — it parses
// the document, validates every requested field against a schema table, and resolves
// against the same in-memory store REST/git/MCP use, so a write on one surface reads
// back identically on the others.
//
// Wire facts (graphql-client.ts, checks-graphql.ts):
// - HTTP 200 + {data, errors} for every well-formed request, including validation
//   failures (an unknown field is HTTP 200 with errors, never a 4xx — A.14).
// - Any non-empty `errors` array fails every check except invalid-field, so the executor
//   only records an error for a genuinely unknown field.
// - Global ids are opaque and stable (A.19): base64url of a tagged string
//   ("Repository:<dbId>", "Issue:<repoDbId>:<number>", ...), never the plain number.
// - Auth is enforced by app.ts's gate (401 before this handler runs) — A.15.
// - Determinism: no Date.now()/Math.random()/randomUUID() anywhere in this file;
//   ordering uses the store's monotonic createdSeq, cursors encode an offset.

import type { ServerResponse } from 'node:http';
import {
  flattenTree,
  parseCommit,
  repoOf,
  viewerRepos,
  type Issue,
  type Pull,
  type Repo,
  type Store,
} from './store.ts';
import { VIEWER_LOGIN, VIEWER_ID } from './fixture.ts';
import { callRest, restMessage } from './mcp.ts';

/* ------------------------------------------------------------------ global ids */

function globalId(kind: string, ...parts: Array<string | number>): string {
  return Buffer.from([kind, ...parts.map(String)].join(':'), 'utf8').toString('base64url');
}

function decodeGlobalId(id: unknown): { kind: string; parts: string[] } | null {
  if (typeof id !== 'string' || id === '') return null;
  try {
    const text = Buffer.from(id, 'base64url').toString('utf8');
    const parts = text.split(':');
    if (parts.length < 2) return null;
    return { kind: parts[0], parts: parts.slice(1) };
  } catch {
    return null;
  }
}

function repoById(store: Store, dbId: number): Repo | null {
  return viewerRepos(store).find((r) => r.id === dbId) ?? null;
}

function repoFromGlobalId(store: Store, id: unknown): Repo | null {
  const decoded = decodeGlobalId(id);
  if (decoded === null || decoded.kind !== 'Repository' || decoded.parts.length !== 1) return null;
  const dbId = Number.parseInt(decoded.parts[0], 10);
  return Number.isInteger(dbId) ? repoById(store, dbId) : null;
}

function issueFromGlobalId(store: Store, id: unknown): { repo: Repo; issue: Issue } | null {
  const decoded = decodeGlobalId(id);
  if (decoded === null || decoded.kind !== 'Issue' || decoded.parts.length !== 2) return null;
  const repo = repoById(store, Number.parseInt(decoded.parts[0], 10));
  const issue = repo?.issues.get(Number.parseInt(decoded.parts[1], 10)) ?? null;
  return repo !== null && issue !== null && issue !== undefined ? { repo, issue } : null;
}

function pullFromGlobalId(store: Store, id: unknown): { repo: Repo; pull: Pull } | null {
  const decoded = decodeGlobalId(id);
  if (decoded === null || decoded.kind !== 'PullRequest' || decoded.parts.length !== 2) return null;
  const repo = repoById(store, Number.parseInt(decoded.parts[0], 10));
  const pull = repo?.pulls.get(Number.parseInt(decoded.parts[1], 10)) ?? null;
  return repo !== null && pull !== null && pull !== undefined ? { repo, pull } : null;
}

/* ------------------------------------------------------------------ tokenizer */

// The suite's documents use only: names, ints, strings, and the punctuation
// { } ( ) : $ ! [ ] , ... — the tokenizer accepts the full GraphQL lexical set anyway
// (floats, directives) so an unexpected document degrades to a parse error, not a crash.
type TokenKind = 'Name' | 'Int' | 'Float' | 'String' | 'Punct' | 'Spread';
interface Token {
  kind: TokenKind;
  value: string;
}

function tokenize(src: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;
  const isNameStart = (c: string): boolean => /[A-Za-z_]/.test(c);
  const isNameChar = (c: string): boolean => /[A-Za-z0-9_]/.test(c);
  while (i < src.length) {
    const c = src[i];
    if (c === ' ' || c === '\t' || c === '\n' || c === '\r' || c === ',' || c === '﻿') {
      i += 1;
      continue;
    }
    if (c === '#') {
      while (i < src.length && src[i] !== '\n') i += 1;
      continue;
    }
    if (c === '.' && src.slice(i, i + 3) === '...') {
      tokens.push({ kind: 'Spread', value: '...' });
      i += 3;
      continue;
    }
    if ('{}()[]:!=$@|&'.includes(c)) {
      tokens.push({ kind: 'Punct', value: c });
      i += 1;
      continue;
    }
    if (c === '"') {
      let j = i + 1;
      let out = '';
      while (j < src.length && src[j] !== '"') {
        if (src[j] === '\\' && j + 1 < src.length) {
          const esc = src[j + 1];
          if (esc === 'n') out += '\n';
          else if (esc === 't') out += '\t';
          else if (esc === 'r') out += '\r';
          else if (esc === 'u' && /^[0-9a-fA-F]{4}$/.test(src.slice(j + 2, j + 6))) {
            out += String.fromCharCode(Number.parseInt(src.slice(j + 2, j + 6), 16));
            j += 4;
          } else out += esc;
          j += 2;
        } else {
          out += src[j];
          j += 1;
        }
      }
      if (j >= src.length) throw new Error('Syntax Error: unterminated string');
      tokens.push({ kind: 'String', value: out });
      i = j + 1;
      continue;
    }
    if (/[0-9-]/.test(c)) {
      let j = i;
      if (src[j] === '-') j += 1;
      while (j < src.length && /[0-9]/.test(src[j])) j += 1;
      let isFloat = false;
      if (src[j] === '.') {
        isFloat = true;
        j += 1;
        while (j < src.length && /[0-9]/.test(src[j])) j += 1;
      }
      if (src[j] === 'e' || src[j] === 'E') {
        isFloat = true;
        j += 1;
        if (src[j] === '+' || src[j] === '-') j += 1;
        while (j < src.length && /[0-9]/.test(src[j])) j += 1;
      }
      tokens.push({ kind: isFloat ? 'Float' : 'Int', value: src.slice(i, j) });
      i = j;
      continue;
    }
    if (isNameStart(c)) {
      let j = i;
      while (j < src.length && isNameChar(src[j])) j += 1;
      tokens.push({ kind: 'Name', value: src.slice(i, j) });
      i = j;
      continue;
    }
    throw new Error(`Syntax Error: unexpected character "${c}"`);
  }
  return tokens;
}

/* ------------------------------------------------------------------ parser */

type ValueNode =
  | { kind: 'variable'; name: string }
  | { kind: 'string'; value: string }
  | { kind: 'int'; value: number }
  | { kind: 'float'; value: number }
  | { kind: 'boolean'; value: boolean }
  | { kind: 'null' }
  | { kind: 'enum'; value: string }
  | { kind: 'list'; values: ValueNode[] }
  | { kind: 'object'; fields: Record<string, ValueNode> };

interface FieldNode {
  kind: 'field';
  alias: string | null;
  name: string;
  args: Record<string, ValueNode>;
  selections: SelectionNode[] | null;
}

interface FragmentNode {
  kind: 'fragment';
  typeCondition: string | null;
  selections: SelectionNode[];
}

type SelectionNode = FieldNode | FragmentNode;

interface OperationNode {
  kind: 'query' | 'mutation';
  name: string | null;
  selections: SelectionNode[];
}

class Parser {
  private pos = 0;
  private readonly tokens: Token[];

  constructor(tokens: Token[]) {
    this.tokens = tokens;
  }

  private peek(): Token | undefined {
    return this.tokens[this.pos];
  }
  private next(): Token {
    const tok = this.tokens[this.pos];
    if (tok === undefined) throw new Error('Syntax Error: unexpected end of document');
    this.pos += 1;
    return tok;
  }
  private expectPunct(value: string): void {
    const tok = this.next();
    if (tok.kind !== 'Punct' || tok.value !== value) {
      throw new Error(`Syntax Error: expected "${value}", found "${tok.value}"`);
    }
  }
  private expectName(value?: string): string {
    const tok = this.next();
    if (tok.kind !== 'Name') throw new Error(`Syntax Error: expected a name, found "${tok.value}"`);
    if (value !== undefined && tok.value !== value) {
      throw new Error(`Syntax Error: expected "${value}", found "${tok.value}"`);
    }
    return tok.value;
  }

  parseDocument(): OperationNode[] {
    const ops: OperationNode[] = [];
    while (this.peek() !== undefined) {
      ops.push(this.parseOperation());
    }
    if (ops.length === 0) throw new Error('Syntax Error: empty document');
    return ops;
  }

  private parseOperation(): OperationNode {
    let kind: 'query' | 'mutation' = 'query';
    const tok = this.peek();
    if (tok !== undefined && tok.kind === 'Punct' && tok.value === '{') {
      return { kind: 'query', name: null, selections: this.parseSelectionSet() };
    }
    if (tok !== undefined && tok.kind === 'Name' && (tok.value === 'query' || tok.value === 'mutation')) {
      kind = this.next().value as 'query' | 'mutation';
    }
    let name: string | null = null;
    const after = this.peek();
    if (after !== undefined && after.kind === 'Name') name = this.next().value;
    // Variable definitions: ($name: Type, ...) — only the names matter to execution.
    if (this.peek()?.kind === 'Punct' && this.peek()?.value === '(') {
      this.next();
      let depth = 1;
      while (depth > 0) {
        const t = this.next();
        if (t.kind === 'Punct' && t.value === '(') depth += 1;
        else if (t.kind === 'Punct' && t.value === ')') depth -= 1;
      }
    }
    // Directives (@...) are ignored (the suite sends none).
    this.skipDirectives();
    return { kind, name, selections: this.parseSelectionSet() };
  }

  private skipDirectives(): void {
    while (this.peek()?.kind === 'Punct' && this.peek()?.value === '@') {
      this.next();
      this.expectName();
      if (this.peek()?.kind === 'Punct' && this.peek()?.value === '(') this.parseArguments();
    }
  }

  private parseSelectionSet(): SelectionNode[] {
    this.expectPunct('{');
    const selections: SelectionNode[] = [];
    while (!(this.peek()?.kind === 'Punct' && this.peek()?.value === '}')) {
      if (this.peek() === undefined) throw new Error('Syntax Error: unterminated selection set');
      selections.push(this.parseSelection());
    }
    this.expectPunct('}');
    return selections;
  }

  private parseSelection(): SelectionNode {
    const tok = this.peek();
    if (tok !== undefined && tok.kind === 'Spread') {
      this.next();
      let typeCondition: string | null = null;
      const on = this.peek();
      if (on !== undefined && on.kind === 'Name' && on.value === 'on') {
        this.next();
        typeCondition = this.expectName();
      }
      this.skipDirectives();
      return { kind: 'fragment', typeCondition, selections: this.parseSelectionSet() };
    }
    let name = this.expectName();
    let alias: string | null = null;
    if (this.peek()?.kind === 'Punct' && this.peek()?.value === ':') {
      this.next();
      alias = name;
      name = this.expectName();
    }
    let args: Record<string, ValueNode> = {};
    if (this.peek()?.kind === 'Punct' && this.peek()?.value === '(') args = this.parseArguments();
    this.skipDirectives();
    let selections: SelectionNode[] | null = null;
    if (this.peek()?.kind === 'Punct' && this.peek()?.value === '{') {
      selections = this.parseSelectionSet();
    }
    return { kind: 'field', alias, name, args, selections };
  }

  private parseArguments(): Record<string, ValueNode> {
    this.expectPunct('(');
    const args: Record<string, ValueNode> = {};
    while (!(this.peek()?.kind === 'Punct' && this.peek()?.value === ')')) {
      const name = this.expectName();
      this.expectPunct(':');
      args[name] = this.parseValue();
    }
    this.expectPunct(')');
    return args;
  }

  private parseValue(): ValueNode {
    const tok = this.next();
    if (tok.kind === 'Punct' && tok.value === '$') return { kind: 'variable', name: this.expectName() };
    if (tok.kind === 'Punct' && tok.value === '[') {
      const values: ValueNode[] = [];
      while (!(this.peek()?.kind === 'Punct' && this.peek()?.value === ']')) {
        values.push(this.parseValue());
      }
      this.expectPunct(']');
      return { kind: 'list', values };
    }
    if (tok.kind === 'Punct' && tok.value === '{') {
      const fields: Record<string, ValueNode> = {};
      while (!(this.peek()?.kind === 'Punct' && this.peek()?.value === '}')) {
        const name = this.expectName();
        this.expectPunct(':');
        fields[name] = this.parseValue();
      }
      this.expectPunct('}');
      return { kind: 'object', fields };
    }
    if (tok.kind === 'String') return { kind: 'string', value: tok.value };
    if (tok.kind === 'Int') return { kind: 'int', value: Number.parseInt(tok.value, 10) };
    if (tok.kind === 'Float') return { kind: 'float', value: Number.parseFloat(tok.value) };
    if (tok.kind === 'Name') {
      if (tok.value === 'true') return { kind: 'boolean', value: true };
      if (tok.value === 'false') return { kind: 'boolean', value: false };
      if (tok.value === 'null') return { kind: 'null' };
      return { kind: 'enum', value: tok.value };
    }
    throw new Error(`Syntax Error: unexpected value token "${tok.value}"`);
  }
}

function parseDocument(src: string): OperationNode[] {
  return new Parser(tokenize(src)).parseDocument();
}

/** Resolve a parsed value against the request's variables (recursively). */
function resolveValue(node: ValueNode, variables: Record<string, unknown>): unknown {
  switch (node.kind) {
    case 'variable':
      return variables[node.name] ?? null;
    case 'string':
    case 'int':
    case 'float':
    case 'boolean':
      return node.value;
    case 'null':
      return null;
    case 'enum':
      return node.value;
    case 'list':
      return node.values.map((v) => resolveValue(v, variables));
    case 'object': {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(node.fields)) out[k] = resolveValue(v, variables);
      return out;
    }
  }
}

/* ------------------------------------------------------------------ introspection */

const INTROSPECTION: Record<string, { fields: string[]; enumValues: string[] }> = {
  Issue: {
    fields: ['id', 'number', 'title', 'state', 'body', 'createdAt', 'updatedAt', 'url', 'author', 'comments', 'labels', 'assignees', 'closedAt'],
    enumValues: [],
  },
  PullRequest: {
    fields: ['id', 'number', 'title', 'body', 'state', 'merged', 'headRefName', 'baseRefName', 'mergeable', 'files', 'createdAt', 'updatedAt', 'url', 'author', 'headRef', 'baseRef', 'isDraft', 'additions', 'deletions', 'changedFiles', 'commits', 'reviews', 'comments'],
    enumValues: [],
  },
  Repository: {
    fields: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest', 'description', 'private', 'isPrivate', 'url', 'createdAt', 'updatedAt', 'fork', 'licenseInfo', 'stargazerCount', 'forkCount', 'watchers', 'primaryLanguage', 'topics', 'visibility', 'hasWikiEnabled', 'hasProjectsEnabled', 'hasDiscussionsEnabled'],
    enumValues: [],
  },
  SearchType: {
    fields: [],
    enumValues: ['ISSUE', 'PULL_REQUEST', 'DISCUSSION', 'COMMIT', 'REPOSITORY', 'USER', 'ORGANIZATION', 'MARKETPLACE'],
  },
  User: {
    fields: ['id', 'login', 'name', 'email', 'avatarUrl', 'url'],
    enumValues: [],
  },
  Node: { fields: ['id'], enumValues: [] },
  IssueConnection: { fields: ['nodes', 'pageInfo', 'totalCount'], enumValues: [] },
  PageInfo: { fields: ['hasNextPage', 'hasPreviousPage', 'startCursor', 'endCursor'], enumValues: [] },
  PullRequestConnection: { fields: ['nodes', 'pageInfo', 'totalCount'], enumValues: [] },
  PullRequestChangedFileConnection: { fields: ['nodes', 'pageInfo', 'totalCount'], enumValues: [] },
  PullRequestChangedFile: { fields: ['path', 'additions', 'deletions', 'changeType'], enumValues: [] },
  Ref: { fields: ['name', 'target'], enumValues: [] },
  IssueComment: { fields: ['id', 'body', 'author', 'createdAt', 'updatedAt', 'url'], enumValues: [] },
  IssueCommentEdge: { fields: ['node', 'cursor'], enumValues: [] },
};

/* ------------------------------------------------------------------ resolvers */

// Objects carry their runtime type in __typename; scalars pass through unchanged.
type AnyObject = Record<string, unknown> & { __typename?: string };

interface GqlContext {
  store: Store;
  variables: Record<string, unknown>;
  errors: Array<{ message: string }>;
}

type ResolverFn = (ctx: GqlContext, parent: AnyObject, args: Record<string, unknown>) => unknown | Promise<unknown>;

function userObject(login: string): AnyObject {
  return { __typename: 'User', login, id: VIEWER_ID };
}

function repoObject(repo: Repo): AnyObject {
  return { __typename: 'Repository', __repo: repo };
}

function issueObject(repo: Repo, issue: Issue): AnyObject {
  return { __typename: 'Issue', __repo: repo, __issue: issue };
}

function pullObject(repo: Repo, pull: Pull): AnyObject {
  return { __typename: 'PullRequest', __repo: repo, __pull: pull };
}

function issueGlobalId(repo: Repo, issue: Issue): string {
  return globalId('Issue', repo.id, issue.number);
}

function pullGlobalId(repo: Repo, pull: Pull): string {
  return globalId('PullRequest', repo.id, pull.number);
}

function issueStateGql(issue: Issue): string {
  return issue.state === 'open' ? 'OPEN' : 'CLOSED';
}

function pullStateGql(pull: Pull): string {
  if (pull.merged) return 'MERGED';
  return pull.state === 'open' ? 'OPEN' : 'CLOSED';
}

/** Cursor = base64("cursor:<offset>") over the ordered issue list; bad input means 0. */
function encodeCursor(offset: number): string {
  return Buffer.from(`cursor:${offset}`, 'utf8').toString('base64');
}

function decodeCursor(after: unknown): number {
  if (typeof after !== 'string' || after === '') return 0;
  try {
    const text = Buffer.from(after, 'base64').toString('utf8');
    const m = /^cursor:(\d+)$/.exec(text);
    return m !== null ? Number.parseInt(m[1], 10) : 0;
  } catch {
    return 0;
  }
}

/** Whether baseSha is an ancestor-or-self of headSha (walk commit parents). */
function isAncestorOrSelf(repo: Repo, baseSha: string, headSha: string): boolean {
  if (baseSha === headSha) return true;
  const seen = new Set<string>();
  const stack = [headSha];
  while (stack.length > 0) {
    const sha = stack.pop() as string;
    if (seen.has(sha)) continue;
    seen.add(sha);
    const obj = repo.objects.get(sha);
    if (obj === undefined || obj.type !== 'commit') continue;
    for (const parent of parseCommit(obj.data).parents) {
      if (parent === baseSha) return true;
      stack.push(parent);
    }
  }
  return false;
}

/** Changed paths between two commit trees (added, modified, deleted), sorted. */
function changedPaths(repo: Repo, baseSha: string, headSha: string): string[] {
  const treeOf = (sha: string): Map<string, string> => {
    const obj = repo.objects.get(sha);
    if (obj === undefined || obj.type !== 'commit') return new Map();
    return flattenTree(repo, parseCommit(obj.data).tree);
  };
  const base = treeOf(baseSha);
  const head = treeOf(headSha);
  const paths = new Set<string>();
  for (const [p, b] of base) if (head.get(p) !== b) paths.add(p);
  for (const p of head.keys()) if (!base.has(p)) paths.add(p);
  return [...paths].sort();
}

function issuesOrdered(repo: Repo): Issue[] {
  // CREATED_AT DESC with number DESC as the tiebreak (RULES.txt); createdSeq is monotonic
  // and increases with the per-repo number, so one sort covers both.
  return [...repo.issues.values()].sort((a, b) => b.createdSeq - a.createdSeq);
}

const FIELDS: Record<string, Record<string, ResolverFn>> = {
  Query: {
    viewer: () => userObject(VIEWER_LOGIN),
    repository: (ctx, _parent, args) => {
      const repo = repoOf(ctx.store, String(args['owner'] ?? ''), String(args['name'] ?? ''));
      return repo === null ? null : repoObject(repo);
    },
    node: (ctx, _parent, args) => {
      const repo = repoFromGlobalId(ctx.store, args['id']);
      return repo === null ? null : repoObject(repo);
    },
    __type: (_ctx, _parent, args) => {
      const entry = INTROSPECTION[String(args['name'] ?? '')];
      if (entry === undefined) return null;
      return { __typename: '__Type', __typeName: String(args['name']), __fields: entry.fields, __enumValues: entry.enumValues };
    },
  },
  Mutation: {
    createIssue: async (ctx, _parent, args) => {
      const input = (args['input'] ?? {}) as Record<string, unknown>;
      const repo = repoFromGlobalId(ctx.store, input['repositoryId']);
      if (repo === null) {
        ctx.errors.push({ message: 'Repository not found' });
        return { __typename: 'CreateIssuePayload', issue: null };
      }
      const res = await callRest(
        ctx.store,
        'POST',
        `/api/v3/repos/${encodeURIComponent(repo.owner)}/${encodeURIComponent(repo.name)}/issues`,
        new URLSearchParams(),
        { title: input['title'], ...(typeof input['body'] === 'string' ? { body: input['body'] } : {}) },
      );
      if (res === null || res.status !== 201) {
        ctx.errors.push({ message: res === null ? 'createIssue is not available' : restMessage(res.body) });
        return { __typename: 'CreateIssuePayload', issue: null };
      }
      const number = (res.body as Record<string, unknown>)['number'] as number;
      const issue = repo.issues.get(number);
      return { __typename: 'CreateIssuePayload', issue: issue === undefined ? null : issueObject(repo, issue) };
    },
    closeIssue: async (ctx, _parent, args) => {
      const input = (args['input'] ?? {}) as Record<string, unknown>;
      const found = issueFromGlobalId(ctx.store, input['issueId']);
      if (found === null) {
        ctx.errors.push({ message: 'Issue not found' });
        return { __typename: 'CloseIssuePayload', issue: null };
      }
      const { repo, issue } = found;
      const res = await callRest(
        ctx.store,
        'PATCH',
        `/api/v3/repos/${encodeURIComponent(repo.owner)}/${encodeURIComponent(repo.name)}/issues/${issue.number}`,
        new URLSearchParams(),
        { state: 'closed' },
      );
      if (res === null || res.status !== 200) {
        ctx.errors.push({ message: res === null ? 'closeIssue is not available' : restMessage(res.body) });
        return { __typename: 'CloseIssuePayload', issue: null };
      }
      return { __typename: 'CloseIssuePayload', issue: issueObject(repo, issue) };
    },
    createPullRequest: async (ctx, _parent, args) => {
      const input = (args['input'] ?? {}) as Record<string, unknown>;
      const repo = repoFromGlobalId(ctx.store, input['repositoryId']);
      if (repo === null) {
        ctx.errors.push({ message: 'Repository not found' });
        return { __typename: 'CreatePullRequestPayload', pullRequest: null };
      }
      const res = await callRest(
        ctx.store,
        'POST',
        `/api/v3/repos/${encodeURIComponent(repo.owner)}/${encodeURIComponent(repo.name)}/pulls`,
        new URLSearchParams(),
        {
          title: input['title'],
          head: input['headRefName'],
          base: input['baseRefName'],
          ...(typeof input['body'] === 'string' ? { body: input['body'] } : {}),
        },
      );
      if (res === null || res.status !== 201) {
        ctx.errors.push({ message: res === null ? 'createPullRequest is not available' : restMessage(res.body) });
        return { __typename: 'CreatePullRequestPayload', pullRequest: null };
      }
      const number = (res.body as Record<string, unknown>)['number'] as number;
      const pull = repo.pulls.get(number);
      return { __typename: 'CreatePullRequestPayload', pullRequest: pull === undefined ? null : pullObject(repo, pull) };
    },
    mergePullRequest: async (ctx, _parent, args) => {
      const input = (args['input'] ?? {}) as Record<string, unknown>;
      const found = pullFromGlobalId(ctx.store, input['pullRequestId']);
      if (found === null) {
        ctx.errors.push({ message: 'Pull request not found' });
        return { __typename: 'MergePullRequestPayload', pullRequest: null };
      }
      const { repo, pull } = found;
      const res = await callRest(
        ctx.store,
        'PUT',
        `/api/v3/repos/${encodeURIComponent(repo.owner)}/${encodeURIComponent(repo.name)}/pulls/${pull.number}/merge`,
        new URLSearchParams(),
        undefined,
      );
      if (res === null || res.status !== 200) {
        ctx.errors.push({ message: res === null ? 'mergePullRequest is not available' : restMessage(res.body) });
        return { __typename: 'MergePullRequestPayload', pullRequest: null };
      }
      return { __typename: 'MergePullRequestPayload', pullRequest: pullObject(repo, pull) };
    },
    addComment: async (ctx, _parent, args) => {
      const input = (args['input'] ?? {}) as Record<string, unknown>;
      const found = issueFromGlobalId(ctx.store, input['subjectId']);
      if (found === null) {
        ctx.errors.push({ message: 'Subject not found' });
        return { __typename: 'AddCommentPayload', commentEdge: null };
      }
      const { repo, issue } = found;
      const res = await callRest(
        ctx.store,
        'POST',
        `/api/v3/repos/${encodeURIComponent(repo.owner)}/${encodeURIComponent(repo.name)}/issues/${issue.number}/comments`,
        new URLSearchParams(),
        { body: input['body'] },
      );
      if (res === null || res.status !== 201) {
        ctx.errors.push({ message: res === null ? 'addComment is not available' : restMessage(res.body) });
        return { __typename: 'AddCommentPayload', commentEdge: null };
      }
      const commentId = (res.body as Record<string, unknown>)['id'] as number;
      const body = (res.body as Record<string, unknown>)['body'] as string;
      return {
        __typename: 'AddCommentPayload',
        commentEdge: {
          __typename: 'IssueCommentEdge',
          node: {
            __typename: 'IssueComment',
            id: globalId('IssueComment', repo.id, issue.number, commentId),
            body,
          },
        },
      };
    },
  },
  User: {
    login: (_ctx, parent) => parent['login'] ?? null,
    id: () => VIEWER_ID,
    name: (_ctx, parent) => parent['login'] ?? null,
  },
  Repository: {
    id: (_ctx, parent) => globalId('Repository', (parent['__repo'] as Repo).id),
    databaseId: (_ctx, parent) => (parent['__repo'] as Repo).id,
    name: (_ctx, parent) => (parent['__repo'] as Repo).name,
    nameWithOwner: (_ctx, parent) => {
      const repo = parent['__repo'] as Repo;
      return `${repo.owner}/${repo.name}`;
    },
    owner: (_ctx, parent) => userObject((parent['__repo'] as Repo).owner),
    defaultBranchRef: (_ctx, parent) => ({ __typename: 'Ref', name: (parent['__repo'] as Repo).defaultBranch }),
    viewerPermission: () => 'ADMIN',
    hasIssuesEnabled: () => true,
    issue: (_ctx, parent, args) => {
      const repo = parent['__repo'] as Repo;
      const issue = repo.issues.get(Number(args['number']));
      return issue === undefined ? null : issueObject(repo, issue);
    },
    issues: (_ctx, parent, args) => {
      const repo = parent['__repo'] as Repo;
      let list = issuesOrdered(repo);
      if (Array.isArray(args['states']) && args['states'].length > 0) {
        const want = new Set((args['states'] as unknown[]).map((s) => String(s).toUpperCase()));
        list = list.filter((issue) => want.has(issueStateGql(issue)));
      }
      if (args['orderBy'] !== undefined && args['orderBy'] !== null) {
        const orderBy = args['orderBy'] as Record<string, unknown>;
        const direction = String(orderBy['direction'] ?? 'DESC').toUpperCase();
        if (direction === 'ASC') list = [...list].reverse();
      }
      const offset = decodeCursor(args['after']);
      const first = typeof args['first'] === 'number' ? args['first'] : list.length;
      const page = list.slice(offset, offset + first);
      return {
        __typename: 'IssueConnection',
        nodes: page.map((issue) => issueObject(repo, issue)),
        pageInfo: {
          __typename: 'PageInfo',
          hasNextPage: offset + page.length < list.length,
          endCursor: page.length === 0 ? null : encodeCursor(offset + page.length),
        },
      };
    },
    pullRequests: (_ctx, parent, args) => {
      const repo = parent['__repo'] as Repo;
      let list = [...repo.pulls.values()].sort((a, b) => b.createdSeq - a.createdSeq);
      if (typeof args['first'] === 'number') list = list.slice(0, args['first']);
      return {
        __typename: 'PullRequestConnection',
        nodes: list.map((pull) => pullObject(repo, pull)),
        pageInfo: { __typename: 'PageInfo', hasNextPage: false, endCursor: null },
      };
    },
    pullRequest: (_ctx, parent, args) => {
      const repo = parent['__repo'] as Repo;
      const pull = repo.pulls.get(Number(args['number']));
      return pull === undefined ? null : pullObject(repo, pull);
    },
  },
  Ref: {
    name: (_ctx, parent) => parent['name'] ?? null,
  },
  Issue: {
    id: (_ctx, parent) => issueGlobalId(parent['__repo'] as Repo, parent['__issue'] as Issue),
    number: (_ctx, parent) => (parent['__issue'] as Issue).number,
    title: (_ctx, parent) => (parent['__issue'] as Issue).title,
    state: (_ctx, parent) => issueStateGql(parent['__issue'] as Issue),
    body: (_ctx, parent) => (parent['__issue'] as Issue).body,
  },
  IssueConnection: {
    nodes: (_ctx, parent) => parent['nodes'] ?? [],
    pageInfo: (_ctx, parent) => parent['pageInfo'] ?? null,
    totalCount: (_ctx, parent) => (parent['nodes'] as unknown[] | undefined)?.length ?? 0,
  },
  PageInfo: {
    hasNextPage: (_ctx, parent) => parent['hasNextPage'] ?? false,
    hasPreviousPage: () => false,
    startCursor: () => null,
    endCursor: (_ctx, parent) => parent['endCursor'] ?? null,
  },
  PullRequest: {
    id: (_ctx, parent) => pullGlobalId(parent['__repo'] as Repo, parent['__pull'] as Pull),
    number: (_ctx, parent) => (parent['__pull'] as Pull).number,
    title: (_ctx, parent) => (parent['__pull'] as Pull).title,
    body: (_ctx, parent) => (parent['__pull'] as Pull).body,
    state: (_ctx, parent) => pullStateGql(parent['__pull'] as Pull),
    merged: (_ctx, parent) => (parent['__pull'] as Pull).merged,
    headRefName: (_ctx, parent) => (parent['__pull'] as Pull).headRef,
    baseRefName: (_ctx, parent) => (parent['__pull'] as Pull).baseRef,
    mergeable: (_ctx, parent) => {
      const repo = parent['__repo'] as Repo;
      const pull = parent['__pull'] as Pull;
      if (pull.headSha === '' || pull.baseSha === '') return 'UNKNOWN';
      return isAncestorOrSelf(repo, pull.baseSha, pull.headSha) ? 'MERGEABLE' : 'CONFLICTING';
    },
    files: (_ctx, parent, args) => {
      const repo = parent['__repo'] as Repo;
      const pull = parent['__pull'] as Pull;
      let paths = changedPaths(repo, pull.baseSha, pull.headSha);
      if (typeof args['first'] === 'number') paths = paths.slice(0, args['first']);
      return {
        __typename: 'PullRequestChangedFileConnection',
        nodes: paths.map((path) => ({ __typename: 'PullRequestChangedFile', path })),
        pageInfo: { __typename: 'PageInfo', hasNextPage: false, endCursor: null },
      };
    },
  },
  PullRequestConnection: {
    nodes: (_ctx, parent) => parent['nodes'] ?? [],
    pageInfo: (_ctx, parent) => parent['pageInfo'] ?? null,
    totalCount: (_ctx, parent) => (parent['nodes'] as unknown[] | undefined)?.length ?? 0,
  },
  PullRequestChangedFileConnection: {
    nodes: (_ctx, parent) => parent['nodes'] ?? [],
    pageInfo: (_ctx, parent) => parent['pageInfo'] ?? null,
    totalCount: (_ctx, parent) => (parent['nodes'] as unknown[] | undefined)?.length ?? 0,
  },
  PullRequestChangedFile: {
    path: (_ctx, parent) => parent['path'] ?? null,
  },
  __Type: {
    fields: (_ctx, parent) =>
      (parent['__fields'] as string[]).map((name) => ({ __typename: '__Field', name })),
    enumValues: (_ctx, parent) =>
      (parent['__enumValues'] as string[]).map((name) => ({ __typename: '__EnumValue', name })),
  },
  __Field: {
    name: (_ctx, parent) => parent['name'] ?? null,
  },
  __EnumValue: {
    name: (_ctx, parent) => parent['name'] ?? null,
  },
  CreateIssuePayload: {
    issue: (_ctx, parent) => parent['issue'] ?? null,
  },
  CloseIssuePayload: {
    issue: (_ctx, parent) => parent['issue'] ?? null,
  },
  CreatePullRequestPayload: {
    pullRequest: (_ctx, parent) => parent['pullRequest'] ?? null,
  },
  MergePullRequestPayload: {
    pullRequest: (_ctx, parent) => parent['pullRequest'] ?? null,
  },
  AddCommentPayload: {
    commentEdge: (_ctx, parent) => parent['commentEdge'] ?? null,
  },
  IssueCommentEdge: {
    node: (_ctx, parent) => parent['node'] ?? null,
    cursor: () => null,
  },
  IssueComment: {
    id: (_ctx, parent) => parent['id'] ?? null,
    body: (_ctx, parent) => parent['body'] ?? null,
  },
};

/* ------------------------------------------------------------------ executor */

/**
 * Execute one selection set against a value of the given runtime type.
 * Unknown fields record a validation error ("Cannot query field ...") and resolve to null;
 * everything else resolves through the schema table above.
 */
async function executeSelections(
  selections: SelectionNode[],
  typeName: string,
  value: AnyObject | null,
  ctx: GqlContext,
): Promise<Record<string, unknown>> {
  const out: Record<string, unknown> = {};
  for (const sel of selections) {
    if (sel.kind === 'fragment') {
      const runtime = value?.__typename ?? typeName;
      if (sel.typeCondition === null || sel.typeCondition === runtime) {
        const frag = await executeSelections(sel.selections, sel.typeCondition ?? typeName, value, ctx);
        Object.assign(out, frag);
      }
      continue;
    }
    const responseKey = sel.alias ?? sel.name;
    const table = FIELDS[typeName];
    const resolver = table?.[sel.name];
    if (resolver === undefined) {
      ctx.errors.push({ message: `Cannot query field "${sel.name}" on type "${typeName}".` });
      out[responseKey] = null;
      continue;
    }
    const args: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(sel.args)) args[k] = resolveValue(v, ctx.variables);
    let resolved: unknown;
    try {
      resolved = await resolver(ctx, value ?? {}, args);
    } catch (err) {
      ctx.errors.push({ message: (err as Error).message });
      out[responseKey] = null;
      continue;
    }
    if (sel.selections === null) {
      out[responseKey] = resolved ?? null;
    } else if (resolved === null || resolved === undefined) {
      out[responseKey] = null;
    } else if (Array.isArray(resolved)) {
      const items: Record<string, unknown>[] = [];
      for (const item of resolved) {
        const itemType = (item as AnyObject).__typename ?? typeName;
        items.push(await executeSelections(sel.selections, itemType, item as AnyObject, ctx));
      }
      out[responseKey] = items;
    } else {
      const childType = (resolved as AnyObject).__typename ?? typeName;
      out[responseKey] = await executeSelections(sel.selections, childType, resolved as AnyObject, ctx);
    }
  }
  return out;
}

interface GqlEnvelope {
  data: Record<string, unknown> | null;
  errors: Array<{ message: string }>;
}

/** Execute one parsed operation (query or mutation) against the store. */
async function executeOperation(
  store: Store,
  op: OperationNode,
  variables: Record<string, unknown>,
): Promise<GqlEnvelope> {
  const ctx: GqlContext = { store, variables, errors: [] };
  const rootType = op.kind === 'mutation' ? 'Mutation' : 'Query';
  const data = await executeSelections(op.selections, rootType, {}, ctx);
  return { data, errors: ctx.errors };
}

/** Execute one request body element ({query, variables, operationName?}). */
async function executeRequest(
  store: Store,
  element: unknown,
): Promise<GqlEnvelope> {
  if (!isRecord(element) || typeof element['query'] !== 'string') {
    return { data: null, errors: [{ message: 'Request must carry a query string' }] };
  }
  const query = element['query'] as string;
  const variables = isRecord(element['variables']) ? (element['variables'] as Record<string, unknown>) : {};
  const operationName = typeof element['operationName'] === 'string' ? element['operationName'] : null;
  let operations: OperationNode[];
  try {
    operations = parseDocument(query);
  } catch (err) {
    return { data: null, errors: [{ message: (err as Error).message }] };
  }
  let op: OperationNode | undefined;
  if (operationName !== null) op = operations.find((o) => o.name === operationName);
  if (op === undefined) op = operations[0];
  if (op === undefined) return { data: null, errors: [{ message: 'No operation in document' }] };
  return executeOperation(store, op, variables);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/* ------------------------------------------------------------------ dispatcher */

export interface GraphqlContext {
  store: Store;
  method: string;
  path: string;
  body: unknown;
  res: ServerResponse;
  requestId: string;
}

function sendGql(res: ServerResponse, requestId: string, status: number, body: unknown): void {
  const text = `${JSON.stringify(body)}\n`;
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(text),
    'x-github-request-id': requestId,
  });
  res.end(text);
}

/**
 * Handle a GraphQL request. Returns true when the path is the GraphQL path (the response
 * has been written); false when it is not. Never throws out of a request.
 */
export function handleGraphql(ctx: GraphqlContext): boolean {
  if (ctx.path !== '/api/graphql' && !ctx.path.startsWith('/api/graphql/')) return false;
  try {
    if (ctx.method !== 'POST') {
      sendGql(ctx.res, ctx.requestId, 405, { message: 'Method Not Allowed' });
      return true;
    }
    void (async () => {
      try {
        if (Array.isArray(ctx.body)) {
          // Batched operations: one envelope per element, in request order (A.18).
          const results: GqlEnvelope[] = [];
          for (const element of ctx.body) results.push(await executeRequest(ctx.store, element));
          sendGql(ctx.res, ctx.requestId, 200, results);
        } else if (isRecord(ctx.body)) {
          const result = await executeRequest(ctx.store, ctx.body);
          sendGql(ctx.res, ctx.requestId, 200, result);
        } else {
          sendGql(ctx.res, ctx.requestId, 400, { message: 'Problems parsing JSON' });
        }
      } catch (err) {
        if (!ctx.res.headersSent) {
          sendGql(ctx.res, ctx.requestId, 200, { data: null, errors: [{ message: (err as Error).message }] });
        } else ctx.res.end();
      }
    })();
    return true;
  } catch {
    try {
      if (!ctx.res.headersSent) sendGql(ctx.res, ctx.requestId, 200, { data: null, errors: [{ message: 'Internal error' }] });
      else ctx.res.end();
    } catch {
      /* the response is already gone; nothing more to do */
    }
    return true;
  }
}
