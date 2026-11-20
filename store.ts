// The one shared in-memory store for REST, git smart HTTP, GraphQL and MCP.
// Everything the suite can observe is created through this store, so a repo/issue/PR/commit
// made on one surface reads back identically on the others (checks-rest.ts:57-70).
//
// Determinism (export.ts:10-20): no wall clock, no randomness in stored state.
// - All timestamps are the trial's fixed now (MAKEFUN_TRIAL_NOW) or the scenario epoch
//   2025-01-01T00:00:00Z (wire.ts:757, SCENARIO_EPOCH_SEC = 1735689600) when unset.
// - Ordering uses monotonic counters (createdSeq), never wall-clock time, because two issues
//   created back-to-back would tie on a millisecond clock (checks-rest.ts:847-858).
// - Git commit timestamps are epoch + a monotonic counter, so every commit object is
//   byte-deterministic across replay runs.
// - No request log is kept in RAM: only the objects the suite can read back are stored.

import { createHash } from 'node:crypto';
import { VIEWER_LOGIN, VIEWER_ID } from './fixture.ts';

/** The trial's fixed "now" for every timestamp the entry emits. */
export function trialNowISO(): string {
  const v = process.env.MAKEFUN_TRIAL_NOW ?? '';
  return v !== '' ? v : '2025-01-01T00:00:00Z';
}

/** Scenario epoch seconds (wire.ts:757), the base for git commit timestamps. */
export const SCENARIO_EPOCH_SEC = 1735689600;

export function sha1Hex(data: Buffer): string {
  return createHash('sha1').update(data).digest('hex');
}

/** The git blob id for raw file bytes: sha1("blob <len>\0" + bytes). */
export function gitBlobSha(content: Buffer): string {
  return sha1Hex(Buffer.concat([Buffer.from(`blob ${content.length}\0`, 'utf8'), content]));
}

export type GitObjectType = 'blob' | 'tree' | 'commit' | 'tag';

export interface GitObject {
  type: GitObjectType;
  data: Buffer;
}

export interface Label {
  name: string;
  color: string;
}

export interface IssueComment {
  id: number;
  body: string;
  createdSeq: number;
}

export interface Issue {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: Label[];
  createdSeq: number;
  comments: IssueComment[];
}

export interface Pull {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  merged: boolean;
  mergedAt: string | null;
  mergeCommitSha: string | null;
  headRef: string;
  headSha: string;
  baseRef: string;
  baseSha: string;
  createdSeq: number;
}

export interface Repo {
  id: number;
  name: string;
  owner: string;
  private: boolean;
  description: string | null;
  defaultBranch: string;
  createdSeq: number;
  /** Branch name -> tip commit sha (null = unborn, no commit yet). */
  refs: Map<string, string | null>;
  /** Tag name -> tag-object sha (refs/tags/*). */
  tags: Map<string, string>;
  /** Commit sha -> parent shas (memo for git ancestor walks). */
  parents: Map<string, string[]>;
  /** Git objects by lowercase hex sha (blobs, trees, commits). */
  objects: Map<string, GitObject>;
  labels: Map<string, Label>;
  issues: Map<number, Issue>;
  nextIssueNumber: number;
  pulls: Map<number, Pull>;
  nextPullNumber: number;
}

export interface Store {
  repos: Map<string, Repo>;
  nextRepoId: number;
  nextIssueId: number;
  nextPullId: number;
  nextCommentId: number;
  /** Global monotonic counter: creation order and git commit timestamps. */
  seq: number;
}

export function createStore(): Store {
  return {
    repos: new Map(),
    nextRepoId: 1,
    nextIssueId: 1,
    nextPullId: 1,
    nextCommentId: 1,
    seq: 0,
  };
}

/** The store key for a repo: owner/name. */
export function repoKey(owner: string, name: string): string {
  return `${owner}/${name}`;
}

/** Look a repo up by owner + name. Any owner other than the token's owner is foreign: null. */
export function repoOf(store: Store, owner: string, name: string): Repo | null {
  if (owner !== VIEWER_LOGIN) return null;
  return store.repos.get(repoKey(owner, name)) ?? null;
}

/** Create a repo owned by the token's viewer. Returns null when the name already exists. */
export function createRepo(
  store: Store,
  name: string,
  opts: { private: boolean; description: string | null },
): Repo | null {
  const key = repoKey(VIEWER_LOGIN, name);
  if (store.repos.has(key)) return null;
  const repo: Repo = {
    id: store.nextRepoId,
    name,
    owner: VIEWER_LOGIN,
    private: opts.private,
    description: opts.description,
    defaultBranch: 'main',
    createdSeq: (store.seq += 1),
    refs: new Map([['main', null]]),
    tags: new Map(),
    parents: new Map(),
    objects: new Map(),
    labels: new Map(),
    issues: new Map(),
    nextIssueNumber: 1,
    pulls: new Map(),
    nextPullNumber: 1,
  };
  store.nextRepoId += 1;
  store.repos.set(key, repo);
  return repo;
}

/** Delete a repo and everything in it. Returns false when it did not exist. */
export function deleteRepo(store: Store, owner: string, name: string): boolean {
  if (owner !== VIEWER_LOGIN) return false;
  return store.repos.delete(repoKey(owner, name));
}

/** All repos owned by the token's viewer, in creation order. */
export function viewerRepos(store: Store): Repo[] {
  return [...store.repos.values()].sort((a, b) => a.createdSeq - b.createdSeq);
}

// ---------------------------------------------------------------------------
// Git objects: trees and commits built from the flat file map of a branch tip.
// ---------------------------------------------------------------------------

/** One entry of a git tree object: mode, name, and the object it points at. */
interface TreeEntry {
  mode: string;
  name: string;
  sha: string;
}

/**
 * Strip a loose-object header (`<type> <len>\0`) when one is present at the start of the
 * buffer; otherwise return the buffer unchanged. A raw git tree's first NUL terminates its
 * first entry (`100644 name\0...`), whose prefix never matches `<type> <len>`, so raw
 * content is never misdetected as a header. A raw commit has no NUL before its message
 * text in practice, and a message NUL would not match the pattern either.
 */
function stripLooseHeader(data: Buffer): Buffer {
  const nul = data.indexOf(0);
  if (nul < 0) return data;
  const prefix = data.subarray(0, nul).toString('utf8');
  return /^(blob|tree|commit|tag) \d+$/.test(prefix) ? data.subarray(nul + 1) : data;
}

/** Serialise tree entries the way git does (sorted by name, "<mode> <name>\0" + raw sha).
 * Returns the RAW tree content (entries only, no loose-object header): that is what a pack
 * carries and what hashObject hashes after prepending `tree <len>\0`. */
export function treeBytes(entries: TreeEntry[]): Buffer {
  const sorted = [...entries].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  const parts: Buffer[] = [];
  for (const entry of sorted) {
    parts.push(Buffer.from(`${entry.mode} ${entry.name}\0`, 'utf8'));
    parts.push(Buffer.from(entry.sha, 'hex'));
  }
  return Buffer.concat(parts);
}

/**
 * Build (and store) the tree objects for a flat path -> blob-sha map, bottom-up.
 * Returns the root tree sha. Empty map -> the empty tree.
 */
export function buildTree(repo: Repo, files: Map<string, string>): string {
  interface Node {
    files: Map<string, string>;
    dirs: Map<string, Node>;
  }
  const root: Node = { files: new Map(), dirs: new Map() };
  for (const [path, blobSha] of files) {
    const parts = path.split('/').filter((p) => p !== '');
    let node = root;
    for (let i = 0; i < parts.length - 1; i += 1) {
      const part = parts[i];
      let child = node.dirs.get(part);
      if (child === undefined) {
        child = { files: new Map(), dirs: new Map() };
        node.dirs.set(part, child);
      }
      node = child;
    }
    node.files.set(parts[parts.length - 1], blobSha);
  }
  const build = (node: Node): string => {
    const entries: TreeEntry[] = [];
    for (const [name, blobSha] of node.files) entries.push({ mode: '100644', name, sha: blobSha });
    for (const [name, child] of node.dirs) entries.push({ mode: '40000', name, sha: build(child) });
    const bytes = treeBytes(entries);
    const sha = sha1Hex(Buffer.concat([Buffer.from(`tree ${bytes.length}\0`, 'utf8'), bytes]));
    repo.objects.set(sha, { type: 'tree', data: bytes });
    return sha;
  };
  return build(root);
}

/** Parse a stored tree object back into its entries. Stored trees hold raw git content
 * (entries only); a loose-object header is stripped if one is present (stripLooseHeader). */
export function parseTree(data: Buffer): TreeEntry[] {
  const body = stripLooseHeader(data);
  const entries: TreeEntry[] = [];
  let i = 0;
  while (i < body.length) {
    const space = body.indexOf(0x20, i);
    const zero = body.indexOf(0, space + 1);
    const mode = body.subarray(i, space).toString('utf8');
    const name = body.subarray(space + 1, zero).toString('utf8');
    const sha = body.subarray(zero + 1, zero + 21).toString('hex');
    entries.push({ mode, name, sha });
    i = zero + 21;
  }
  return entries;
}

/** Flatten a stored tree into path -> blob-sha (recursive, directory prefixes included). */
export function flattenTree(repo: Repo, treeSha: string, prefix = ''): Map<string, string> {
  const out = new Map<string, string>();
  const obj = repo.objects.get(treeSha);
  if (obj === undefined || obj.type !== 'tree') return out;
  for (const entry of parseTree(obj.data)) {
    const path = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
    if (entry.mode === '40000') {
      for (const [p, s] of flattenTree(repo, entry.sha, path)) out.set(p, s);
    } else {
      out.set(path, entry.sha);
    }
  }
  return out;
}

/** Parse a stored commit object: tree, parents, message (author/committer lines ignored). */
export function parseCommit(data: Buffer): { tree: string; parents: string[]; message: string } {
  // Stored commits hold raw git content; a loose-object header (`commit <len>\0`) is
  // stripped if one is present (see stripLooseHeader).
  const text = stripLooseHeader(data).toString('utf8');
  const headEnd = text.indexOf('\n\n');
  const head = headEnd === -1 ? text : text.slice(0, headEnd);
  const message = headEnd === -1 ? '' : text.slice(headEnd + 2).replace(/\n$/, '');
  let tree = '';
  const parents: string[] = [];
  for (const line of head.split('\n')) {
    if (line.startsWith('tree ')) tree = line.slice(5).trim();
    else if (line.startsWith('parent ')) parents.push(line.slice(7).trim());
  }
  return { tree, parents, message };
}

/**
 * Create (and store) a commit object. Timestamp is epoch + the store's monotonic counter,
 * so the object bytes are deterministic across replay runs.
 */
export function createCommit(
  store: Store,
  repo: Repo,
  opts: { tree: string; parent: string | null; message: string },
): string {
  const stamp = SCENARIO_EPOCH_SEC + (store.seq += 1);
  const author = `ada iversen <adaiversen@example.invalid> ${stamp} +0000`;
  const lines = [`tree ${opts.tree}`];
  if (opts.parent !== null) lines.push(`parent ${opts.parent}`);
  lines.push(`author ${author}`, `committer ${author}`, '', opts.message);
  const body = Buffer.from(lines.join('\n') + '\n', 'utf8');
  const sha = sha1Hex(Buffer.concat([Buffer.from(`commit ${body.length}\0`, 'utf8'), body]));
  repo.objects.set(sha, { type: 'commit', data: body });
  return sha;
}

/** Walk a commit chain from a tip (first-parent only; this store never makes merges yet). */
export function commitChain(repo: Repo, tip: string | null): string[] {
  const out: string[] = [];
  let current = tip;
  const seen = new Set<string>();
  while (current !== null && !seen.has(current)) {
    seen.add(current);
    const obj = repo.objects.get(current);
    if (obj === undefined || obj.type !== 'commit') break;
    out.push(current);
    current = parseCommit(obj.data).parents[0] ?? null;
  }
  return out;
}

/** The flat file map of a branch tip (empty map when the branch is unborn). */
export function branchFiles(repo: Repo, branch: string): Map<string, string> {
  const tip = repo.refs.get(branch) ?? null;
  if (tip === null) return new Map();
  const obj = repo.objects.get(tip);
  if (obj === undefined || obj.type !== 'commit') return new Map();
  return flattenTree(repo, parseCommit(obj.data).tree);
}

export { VIEWER_ID };
