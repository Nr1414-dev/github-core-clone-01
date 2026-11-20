// REST v3 routes: repos, refs/branches/commits, contents, labels, issues.
// Every assertion below is quoted from program/env/src/checks-rest.ts via the Phase 1
// mapping (phase1/checks-rest.md); the shape checker requires listed props but allows
// extras (rest-client.ts:258-318), so serializers return GitHub's full object where cheap.
//
// Owner rule (checks-rest.ts:55-58, :734-744): repos are namespaced by owner; any owner
// other than the token's viewer is a 404, never a 403, on every sub-route.

import {
  type Issue,
  type Label,
  type Repo,
  type Store,
  branchFiles,
  buildTree,
  commitChain,
  createCommit,
  createRepo,
  deleteRepo,
  flattenTree,
  gitBlobSha,
  parseCommit,
  parseTree,
  repoOf,
  trialNowISO,
  viewerRepos,
} from './store.ts';
import { VIEWER_ID, VIEWER_LOGIN } from './fixture.ts';

export interface RestContext {
  method: string;
  path: string;
  query: URLSearchParams;
  body: unknown;
  requestId: string;
  host: string;
  store: Store;
  /** Send a JSON reply; body null sends an empty body (for 204). */
  reply: (status: number, body: unknown, headers?: Record<string, string>) => void;
}

const SHA40 = /^[0-9a-f]{40}$/i;

function msg(message: string): { message: string } {
  return { message };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function segmentsOf(path: string): string[] {
  return path
    .split('/')
    .filter((part) => part !== '')
    .map((part) => {
      try {
        return decodeURIComponent(part);
      } catch {
        return part;
      }
    });
}

function pageParams(query: URLSearchParams): { page: number; perPage: number } {
  const page = Math.max(1, Number.parseInt(query.get('page') ?? '1', 10) || 1);
  const rawPerPage = Number.parseInt(query.get('per_page') ?? '30', 10);
  const perPage = Math.min(100, Math.max(1, Number.isNaN(rawPerPage) ? 30 : rawPerPage));
  return { page, perPage };
}

function paginate<T>(items: readonly T[], page: number, perPage: number): T[] {
  return items.slice((page - 1) * perPage, page * perPage);
}

/** Absolute same-origin URL for a Link header (the client refuses off-origin next links). */
function pageUrl(host: string, path: string, query: URLSearchParams, page: number, perPage: number): string {
  const next = new URLSearchParams(query);
  next.set('page', String(page));
  next.set('per_page', String(perPage));
  return `http://${host}${path}?${next.toString()}`;
}

function linkHeader(host: string, path: string, query: URLSearchParams, page: number, perPage: number, total: number): string | null {
  const lastPage = Math.max(1, Math.ceil(total / perPage));
  const parts: string[] = [];
  if (page < lastPage) {
    parts.push(`<${pageUrl(host, path, query, page + 1, perPage)}>; rel="next"`);
    parts.push(`<${pageUrl(host, path, query, lastPage, perPage)}>; rel="last"`);
  }
  if (page > 1) {
    parts.push(`<${pageUrl(host, path, query, 1, perPage)}>; rel="first"`);
    parts.push(`<${pageUrl(host, path, query, page - 1, perPage)}>; rel="prev"`);
  }
  return parts.length === 0 ? null : parts.join(', ');
}

// ---------------------------------------------------------------------------
// Serializers (one per resource, used by create/get/list alike).
// ---------------------------------------------------------------------------

function userJson(): { login: string; id: number; type: string } {
  return { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' };
}

function repoJson(repo: Repo): Record<string, unknown> {
  return {
    id: repo.id,
    name: repo.name,
    full_name: `${repo.owner}/${repo.name}`,
    owner: userJson(),
    private: repo.private,
    description: repo.description,
    default_branch: repo.defaultBranch,
    html_url: `https://github.com/${repo.owner}/${repo.name}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}`,
    created_at: trialNowISO(),
    updated_at: trialNowISO(),
    fork: false,
    archived: false,
    disabled: false,
    visibility: repo.private ? 'private' : 'public',
  };
}

function labelJson(repo: Repo, label: Label): Record<string, unknown> {
  return {
    name: label.name,
    color: label.color,
    description: '',
    default: false,
    url: `/api/v3/repos/${repo.owner}/${repo.name}/labels/${encodeURIComponent(label.name)}`,
  };
}

function issueJson(repo: Repo, issue: Issue): Record<string, unknown> {
  return {
    id: issue.id,
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    labels: issue.labels.map((label) => labelJson(repo, label)),
    user: userJson(),
    assignee: null,
    assignees: [],
    created_at: trialNowISO(),
    updated_at: trialNowISO(),
    comments: issue.comments.length,
    html_url: `https://github.com/${repo.owner}/${repo.name}/issues/${issue.number}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/${issue.number}`,
  };
}

function commentJson(repo: Repo, issue: Issue, comment: { id: number; body: string }): Record<string, unknown> {
  return {
    id: comment.id,
    body: comment.body,
    user: userJson(),
    created_at: trialNowISO(),
    updated_at: trialNowISO(),
    html_url: `https://github.com/${repo.owner}/${repo.name}/issues/${issue.number}#issuecomment-${comment.id}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/comments/${comment.id}`,
  };
}

// ---------------------------------------------------------------------------
// Contents helpers: resolve a ref to a tree, read/write the flat file map.
// ---------------------------------------------------------------------------

/** Resolve ?ref= (branch name or commit sha) to a tree sha, or null when unresolvable. */
function resolveRefTree(repo: Repo, ref: string | null): string | null {
  if (ref === null || ref === '') {
    const tip = repo.refs.get(repo.defaultBranch) ?? null;
    if (tip === null) return null;
    const obj = repo.objects.get(tip);
    return obj !== undefined && obj.type === 'commit' ? parseCommit(obj.data).tree : null;
  }
  const branchTip = repo.refs.get(ref) ?? null;
  if (branchTip !== null) {
    const obj = repo.objects.get(branchTip);
    return obj !== undefined && obj.type === 'commit' ? parseCommit(obj.data).tree : null;
  }
  if (SHA40.test(ref)) {
    const obj = repo.objects.get(ref.toLowerCase());
    return obj !== undefined && obj.type === 'commit' ? parseCommit(obj.data).tree : null;
  }
  return null;
}

/** Author/committer line of a stored commit, for the commits list. */
function commitAuthor(data: Buffer): { name: string; email: string; date: string } {
  const nul = data.indexOf(0);
  const text = data.subarray(nul + 1).toString('utf8');
  const line = text.split('\n').find((l) => l.startsWith('author ')) ?? '';
  const match = /^author (.*) <(.*)> (\d+) ([+-]\d{4})$/.exec(line);
  if (match === null) return { name: VIEWER_LOGIN, email: '', date: trialNowISO() };
  return {
    name: match[1],
    email: match[2],
    date: new Date(Number(match[3]) * 1000).toISOString(),
  };
}

// ---------------------------------------------------------------------------
// Route handlers. Each returns true when it answered the request.
// ---------------------------------------------------------------------------

export async function handleRest(ctx: RestContext): Promise<boolean> {
  const { method, path, query, body, store } = ctx;
  const seg = segmentsOf(path);
  // All routes here live under /api/v3.
  if (seg.length < 2 || seg[0] !== 'api' || seg[1] !== 'v3') return false;

  // GET /api/v3/meta -> 200 {installed_version} (checks-rest.ts:600-603).
  if (method === 'GET' && seg.length === 3 && seg[2] === 'meta') {
    ctx.reply(200, { installed_version: '1.0.0' });
    return true;
  }

  // POST /api/v3/user/repos -> 201; duplicate name -> 422 (checks-rest.ts:605-624, :653-661).
  if (method === 'POST' && seg.length === 4 && seg[2] === 'user' && seg[3] === 'repos') {
    if (!isRecord(body) || typeof body.name !== 'string' || body.name === '') {
      ctx.reply(422, msg('name is required'));
      return true;
    }
    const repo = createRepo(store, body.name, {
      private: body.private === true,
      description: typeof body.description === 'string' ? body.description : null,
    });
    if (repo === null) {
      ctx.reply(422, msg('Repository already exists'));
      return true;
    }
    ctx.reply(201, repoJson(repo));
    return true;
  }

  // GET /api/v3/user/repos -> 200 + Link rel="next" (checks-rest.ts:649-685).
  if (method === 'GET' && seg.length === 4 && seg[2] === 'user' && seg[3] === 'repos') {
    const { page, perPage } = pageParams(query);
    const all = viewerRepos(store);
    const items = paginate(all, page, perPage);
    const headers: Record<string, string> = {};
    const link = linkHeader(ctx.host, path, query, page, perPage, all.length);
    if (link !== null) headers.link = link;
    ctx.reply(200, items.map(repoJson), headers);
    return true;
  }

  // /api/v3/repos/{owner}/{repo}[/...]
  if (seg.length >= 4 && seg[2] === 'repos') {
    const owner = seg[3];
    const name = seg[4] === undefined ? '' : seg[4];
    const repo = name === '' ? null : repoOf(store, owner, name);
    const rest = seg.slice(5);

    // GET /repos/{o}/{r} -> 200 or 404 (checks-rest.ts:605-624, :626-631, :734-744).
    if (method === 'GET' && rest.length === 0) {
      if (repo === null) {
        ctx.reply(404, msg('Not Found'));
        return true;
      }
      ctx.reply(200, repoJson(repo));
      return true;
    }

    // PATCH /repos/{o}/{r} -> 200 (checks-rest.ts:633-639).
    if (method === 'PATCH' && rest.length === 0) {
      if (repo === null) {
        ctx.reply(404, msg('Not Found'));
        return true;
      }
      if (isRecord(body)) {
        if (typeof body.description === 'string' || body.description === null) repo.description = body.description;
        if (typeof body.private === 'boolean') repo.private = body.private;
      }
      ctx.reply(200, repoJson(repo));
      return true;
    }

    // DELETE /repos/{o}/{r} -> 204, later GET is 404 (checks-rest.ts:641-647).
    if (method === 'DELETE' && rest.length === 0) {
      if (repo === null) {
        ctx.reply(404, msg('Not Found'));
        return true;
      }
      deleteRepo(store, owner, name);
      ctx.reply(204, null);
      return true;
    }

    if (repo === null) {
      // Every sub-route under a missing/foreign repo is the same JSON 404.
      ctx.reply(404, msg('Not Found'));
      return true;
    }

    // GET /repos/{o}/{r}/branches (checks-rest.ts:687-701).
    if (method === 'GET' && rest.length === 1 && rest[0] === 'branches') {
      const out: Record<string, unknown>[] = [];
      for (const [branch, tip] of repo.refs) {
        if (tip === null) continue;
        out.push({
          name: branch,
          commit: { sha: tip, url: `/api/v3/repos/${owner}/${name}/commits/${tip}` },
          protected: false,
        });
      }
      ctx.reply(200, out);
      return true;
    }

    // GET /repos/{o}/{r}/commits[?sha=] (checks-rest.ts:703-726).
    if (method === 'GET' && rest.length === 1 && rest[0] === 'commits') {
      const shaParam = query.get('sha');
      let tip: string | null = null;
      if (shaParam === null || shaParam === '') {
        tip = repo.refs.get(repo.defaultBranch) ?? null;
      } else if (repo.refs.has(shaParam)) {
        tip = repo.refs.get(shaParam) ?? null;
      } else if (SHA40.test(shaParam) && repo.objects.get(shaParam.toLowerCase())?.type === 'commit') {
        tip = shaParam.toLowerCase();
      } else {
        ctx.reply(404, msg('Not Found'));
        return true;
      }
      const { page, perPage } = pageParams(query);
      const chain = paginate(commitChain(repo, tip), page, perPage);
      ctx.reply(
        200,
        chain.map((sha) => {
          const obj = repo.objects.get(sha);
          const parsed = obj === undefined ? { message: '' } : parseCommit(obj.data);
          const author = obj === undefined ? { name: '', email: '', date: trialNowISO() } : commitAuthor(obj.data);
          return {
            sha,
            commit: { message: parsed.message, author, committer: author },
            parents: (parsed as { parents?: string[] }).parents?.map((p) => ({ sha: p })) ?? [],
            url: `/api/v3/repos/${owner}/${name}/commits/${sha}`,
            html_url: `https://github.com/${owner}/${name}/commit/${sha}`,
          };
        }),
      );
      return true;
    }

    // POST /repos/{o}/{r}/git/refs (checks-rest.ts:461-473).
    if (method === 'POST' && rest.length === 2 && rest[0] === 'git' && rest[1] === 'refs') {
      if (!isRecord(body) || typeof body.ref !== 'string' || typeof body.sha !== 'string') {
        ctx.reply(422, msg('ref and sha are required'));
        return true;
      }
      const ref = body.ref;
      if (!ref.startsWith('refs/heads/') || ref.length <= 'refs/heads/'.length) {
        ctx.reply(422, msg('ref must be refs/heads/<branch>'));
        return true;
      }
      const branch = ref.slice('refs/heads/'.length);
      const sha = body.sha.toLowerCase();
      if (!SHA40.test(sha) || repo.objects.get(sha)?.type !== 'commit') {
        ctx.reply(422, msg('sha is not a known commit'));
        return true;
      }
      if (repo.refs.has(branch)) {
        ctx.reply(422, msg('Reference already exists'));
        return true;
      }
      repo.refs.set(branch, sha);
      ctx.reply(201, {
        ref,
        url: `/api/v3/repos/${owner}/${name}/git/refs/heads/${encodeURIComponent(branch)}`,
        object: { sha, type: 'commit', url: `/api/v3/repos/${owner}/${name}/git/commits/${sha}` },
      });
      return true;
    }

    // Contents: PUT/GET/DELETE /repos/{o}/{r}/contents[/path...] (checks-rest.ts:746-795).
    if (rest.length >= 1 && rest[0] === 'contents') {
      const contentPath = rest.slice(1).join('/');
      return handleContents(ctx, repo, contentPath);
    }

    // Labels: GET/POST /repos/{o}/{r}/labels (checks-rest.ts:552-558).
    if (rest.length === 1 && rest[0] === 'labels') {
      if (method === 'GET') {
        ctx.reply(200, [...repo.labels.values()].map((label) => labelJson(repo, label)));
        return true;
      }
      if (method === 'POST') {
        if (!isRecord(body) || typeof body.name !== 'string' || body.name === '') {
          ctx.reply(422, msg('name is required'));
          return true;
        }
        if (repo.labels.has(body.name)) {
          ctx.reply(422, msg('Label already exists'));
          return true;
        }
        const label: Label = {
          name: body.name,
          color: typeof body.color === 'string' ? body.color : 'ededed',
        };
        repo.labels.set(label.name, label);
        ctx.reply(201, labelJson(repo, label));
        return true;
      }
    }

    // Issues: POST/GET /repos/{o}/{r}/issues[/{n}[/comments]] (checks-rest.ts:800-961).
    if (rest.length >= 1 && rest[0] === 'issues') {
      return handleIssues(ctx, repo, rest.slice(1));
    }
  }

  return false;
}

// ---------------------------------------------------------------------------
// Contents
// ---------------------------------------------------------------------------

function handleContents(ctx: RestContext, repo: Repo, contentPath: string): boolean {
  const { method, query, body, store } = ctx;
  const branch = isRecord(body) && typeof body.branch === 'string' ? body.branch : repo.defaultBranch;

  if (method === 'GET') {
    const treeSha = resolveRefTree(repo, query.get('ref'));
    if (treeSha === null) {
      ctx.reply(404, msg('Not Found'));
      return true;
    }
    if (contentPath === '') {
      // Root directory listing.
      ctx.reply(200, dirEntries(repo, treeSha, ''));
      return true;
    }
    const files = flattenTree(repo, treeSha);
    const blobSha = files.get(contentPath);
    if (blobSha !== undefined) {
      const obj = repo.objects.get(blobSha);
      const bytes = obj === undefined ? Buffer.alloc(0) : obj.data;
      ctx.reply(200, {
        type: 'file',
        name: contentPath.split('/').pop() ?? contentPath,
        path: contentPath,
        sha: blobSha,
        size: bytes.length,
        encoding: 'base64',
        content: bytes.toString('base64'),
        url: `/api/v3/repos/${repo.owner}/${repo.name}/contents/${contentPath}`,
        html_url: `https://github.com/${repo.owner}/${repo.name}/blob/${repo.defaultBranch}/${contentPath}`,
        download_url: null,
      });
      return true;
    }
    // Directory? Look for entries directly under this path in the flat map.
    const prefix = `${contentPath}/`;
    const children = new Map<string, { name: string; path: string; sha: string; dir: boolean }>();
    for (const [p, s] of files) {
      if (!p.startsWith(prefix)) continue;
      const rest = p.slice(prefix.length);
      const slash = rest.indexOf('/');
      if (slash === -1) {
        children.set(rest, { name: rest, path: p, sha: s, dir: false });
      } else {
        const dirName = rest.slice(0, slash);
        if (!children.has(dirName)) {
          children.set(dirName, { name: dirName, path: `${contentPath}/${dirName}`, sha: '', dir: true });
        }
      }
    }
    if (children.size === 0) {
      ctx.reply(404, msg('Not Found'));
      return true;
    }
    // Directory entries need the tree sha for dirs: resolve from the tree object.
    const entries = dirEntries(repo, treeSha, contentPath);
    void children;
    ctx.reply(200, entries);
    return true;
  }

  if (method === 'PUT') {
    if (!isRecord(body) || typeof body.content !== 'string') {
      ctx.reply(422, msg('content is required'));
      return true;
    }
    if (!repo.refs.has(branch)) {
      ctx.reply(422, msg('Branch does not exist'));
      return true;
    }
    const bytes = Buffer.from(body.content.replace(/\s/g, ''), 'base64');
    const blobSha = gitBlobSha(bytes);
    const files = branchFiles(repo, branch);
    const existing = files.get(contentPath);
    const isUpdate = existing !== undefined;
    if (isUpdate && typeof body.sha === 'string' && body.sha.toLowerCase() !== existing.toLowerCase()) {
      ctx.reply(409, msg('sha does not match the current blob'));
      return true;
    }
    repo.objects.set(blobSha, { type: 'blob', data: bytes });
    files.set(contentPath, blobSha);
    const treeSha = buildTree(repo, files);
    const parent = repo.refs.get(branch) ?? null;
    const message = typeof body.message === 'string' ? body.message : '';
    const commitSha = createCommit(store, repo, { tree: treeSha, parent, message });
    repo.refs.set(branch, commitSha);
    ctx.reply(isUpdate ? 200 : 201, {
      content: {
        name: contentPath.split('/').pop() ?? contentPath,
        path: contentPath,
        sha: blobSha,
        size: bytes.length,
        type: 'file',
        encoding: 'base64',
      },
      commit: { sha: commitSha },
    });
    return true;
  }

  if (method === 'DELETE') {
    if (!repo.refs.has(branch)) {
      ctx.reply(422, msg('Branch does not exist'));
      return true;
    }
    const files = branchFiles(repo, branch);
    const existing = files.get(contentPath);
    if (existing === undefined) {
      ctx.reply(404, msg('Not Found'));
      return true;
    }
    if (isRecord(body) && typeof body.sha === 'string' && body.sha.toLowerCase() !== existing.toLowerCase()) {
      ctx.reply(409, msg('sha does not match the current blob'));
      return true;
    }
    files.delete(contentPath);
    const treeSha = buildTree(repo, files);
    const parent = repo.refs.get(branch) ?? null;
    const message = isRecord(body) && typeof body.message === 'string' ? body.message : '';
    const commitSha = createCommit(store, repo, { tree: treeSha, parent, message });
    repo.refs.set(branch, commitSha);
    ctx.reply(200, { commit: { sha: commitSha } });
    return true;
  }

  return false;
}

/** Direct children of a directory inside a tree, as GitHub lists them. */
function dirEntries(repo: Repo, treeSha: string, dirPath: string): Record<string, unknown>[] {
  const obj = repo.objects.get(treeSha);
  if (obj === undefined || obj.type !== 'tree') return [];
  let current = treeSha;
  if (dirPath !== '') {
    for (const part of dirPath.split('/')) {
      const parent = repo.objects.get(current);
      if (parent === undefined || parent.type !== 'tree') return [];
      const entry = parseTree(parent.data).find((e) => e.name === part && e.mode === '40000');
      if (entry === undefined) return [];
      current = entry.sha;
    }
  }
  const node = repo.objects.get(current);
  if (node === undefined || node.type !== 'tree') return [];
  return parseTree(node.data).map((entry) => ({
    type: entry.mode === '40000' ? 'dir' : 'file',
    name: entry.name,
    path: dirPath === '' ? entry.name : `${dirPath}/${entry.name}`,
    sha: entry.sha,
    size: entry.mode === '40000' ? 0 : (repo.objects.get(entry.sha)?.data.length ?? 0),
    url: `/api/v3/repos/${repo.owner}/${repo.name}/contents/${dirPath === '' ? entry.name : `${dirPath}/${entry.name}`}`,
  }));
}

// ---------------------------------------------------------------------------
// Issues
// ---------------------------------------------------------------------------

function handleIssues(ctx: RestContext, repo: Repo, rest: string[]): boolean {
  const { method, query, body, store } = ctx;

  // POST /issues, GET /issues
  if (rest.length === 0) {
    if (method === 'POST') {
      if (!isRecord(body) || typeof body.title !== 'string') {
        ctx.reply(422, msg('title is required'));
        return true;
      }
      if (body.body !== undefined && typeof body.body !== 'string') {
        ctx.reply(422, msg('body must be a string'));
        return true;
      }
      // Validate every requested label BEFORE allocating a number (checks-rest.ts:957-961).
      const requested: string[] = [];
      if (Array.isArray(body.labels)) {
        for (const item of body.labels) {
          if (typeof item === 'string') requested.push(item);
          else if (isRecord(item) && typeof item.name === 'string') requested.push(item.name);
        }
      }
      const resolved: Label[] = [];
      for (const name of requested) {
        const label = repo.labels.get(name);
        if (label === undefined) {
          ctx.reply(422, msg(`Label does not exist: ${name}`));
          return true;
        }
        resolved.push(label);
      }
      const issue: Issue = {
        id: store.nextIssueId,
        number: repo.nextIssueNumber,
        title: body.title,
        body: typeof body.body === 'string' ? body.body : '',
        state: 'open',
        labels: resolved,
        createdSeq: (store.seq += 1),
        comments: [],
      };
      store.nextIssueId += 1;
      repo.nextIssueNumber += 1;
      repo.issues.set(issue.number, issue);
      ctx.reply(201, issueJson(repo, issue));
      return true;
    }
    if (method === 'GET') {
      const state = query.get('state') ?? 'open';
      const direction = query.get('direction') ?? 'desc';
      const { page, perPage } = pageParams(query);
      let items = [...repo.issues.values()];
      if (state === 'open') items = items.filter((i) => i.state === 'open');
      else if (state === 'closed') items = items.filter((i) => i.state === 'closed');
      // state=all (or anything else) keeps every issue.
      items.sort((a, b) => (direction === 'asc' ? a.createdSeq - b.createdSeq : b.createdSeq - a.createdSeq));
      ctx.reply(200, paginate(items, page, perPage).map((issue) => issueJson(repo, issue)));
      return true;
    }
    return false;
  }

  // /issues/{n}[/comments]
  const num = Number.parseInt(rest[0], 10);
  if (!/^\d+$/.test(rest[0]) || Number.isNaN(num)) return false;
  const issue = repo.issues.get(num) ?? null;

  if (rest.length === 1) {
    if (issue === null) {
      ctx.reply(404, msg('Not Found'));
      return true;
    }
    if (method === 'GET') {
      ctx.reply(200, issueJson(repo, issue));
      return true;
    }
    if (method === 'PATCH') {
      if (!isRecord(body)) {
        ctx.reply(422, msg('Invalid body'));
        return true;
      }
      if (body.state !== undefined) {
        if (body.state !== 'open' && body.state !== 'closed') {
          ctx.reply(422, msg('state must be open or closed'));
          return true;
        }
        issue.state = body.state;
      }
      if (typeof body.title === 'string') issue.title = body.title;
      if (typeof body.body === 'string') issue.body = body.body;
      if (Array.isArray(body.labels)) {
        const requested: string[] = [];
        for (const item of body.labels) {
          if (typeof item === 'string') requested.push(item);
          else if (isRecord(item) && typeof item.name === 'string') requested.push(item.name);
        }
        const resolved: Label[] = [];
        for (const name of requested) {
          const label = repo.labels.get(name);
          if (label === undefined) {
            ctx.reply(422, msg(`Label does not exist: ${name}`));
            return true;
          }
          resolved.push(label);
        }
        issue.labels = resolved;
      }
      ctx.reply(200, issueJson(repo, issue));
      return true;
    }
    return false;
  }

  if (rest.length === 2 && rest[1] === 'comments') {
    if (issue === null) {
      ctx.reply(404, msg('Not Found'));
      return true;
    }
    if (method === 'POST') {
      if (!isRecord(body) || typeof body.body !== 'string') {
        ctx.reply(422, msg('body is required'));
        return true;
      }
      const comment = { id: store.nextCommentId, body: body.body, createdSeq: (store.seq += 1) };
      store.nextCommentId += 1;
      issue.comments.push(comment);
      ctx.reply(201, commentJson(repo, issue, comment));
      return true;
    }
    if (method === 'GET') {
      ctx.reply(200, issue.comments.map((c) => commentJson(repo, issue, c)));
      return true;
    }
    return false;
  }

  return false;
}
