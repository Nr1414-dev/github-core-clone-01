// git.ts — Git smart-HTTP protocol (v0 + v2) for the make.fun git forge entry.
//
// Wire contract (VERIFIED from the kit's own client, program/env/src/git-client.ts):
// - Endpoints: GET /<owner>/<repo>.git/info/refs?service=git-upload-pack|git-receive-pack,
//   POST /<owner>/<repo>.git/git-upload-pack, POST .../git-receive-pack.
// - v2 is keyed by the `Git-Protocol: version=2` header, sent ONLY for upload-pack info/refs
//   (git-client.ts:1331, :1394); receive-pack is v0-only.
// - pkt-line: 4 lowercase-hex length incl. header; max 65520; 0000 flush, 0001 delim, 0002 end.
// - v2 advertisement: `version 2\n` + caps `fetch=shallow filter`, `ls-refs=unborn`,
//   `object-format=sha1` (object-format other than sha1 makes the client throw, :1067).
// - v0 advertisement: `# service=...\n`, flush, ref lines; the FIRST ref line carries the
//   capabilities after NUL; empty repo = `000...0 capabilities^{}\0<caps>`.
// - Receive-pack caps: report-status, report-status-v2, side-band-64k, delete-refs, ofs-delta,
//   symref=HEAD:refs/heads/main (checks-git.ts:410). Upload-pack v0 caps: side-band-64k (the
//   client throws without it, :1729), shallow, thin-pack, ofs-delta, multi_ack_detailed, symref.
// - v2 fetch response sections, in order, each flush-terminated: acknowledgments (NAK),
//   shallow-info (only when there are lines), packfile (sideband packets only; >= 1 packet even
//   for an empty pack, else parseV2Fetch throws, :1614). `packfile-uris` is NEVER sent.
// - v0 fetch response: plain pkt-lines `NAK` / `shallow <oid>` / `unshallow <oid>` interleaved
//   with sideband packets (band 1 = pack data), then flush.
// - Push report: `unpack ok\n` + one `ok <ref>\n` / `ng <ref> <reason>\n` per command, in order.
//   The `ng` reason for a refused update is exactly `non-fast-forward` (checks-git.ts:865).
//   A refused push MUST still unpack: objects are stored before refs are evaluated (:865).
//   When side-band-64k is negotiated the report stream is pkt-lined INSIDE band-1 packets.
// - Packs: plain objects only, no deltas (pack-deltas passes with deltaCount 0, checks-git.ts:1003),
//   version 2, trailer = SHA-1 of all preceding bytes, each oid at most once.
// - HEAD is hidden whenever a ref-prefix is given in ls-refs (the ls-refs-prefix trap, :508).
// - Robustness: any malformed git request is answered 400 without touching the store and
//   without throwing out of the handler (repo-survives-errors, checks-git.ts:1089).

import { createHash } from 'node:crypto';
import type { ServerResponse } from 'node:http';
import { deflateSync, inflateSync } from 'node:zlib';
import { parseCommit, parseTree, repoOf, sha1Hex, type GitObject, type Repo, type Store } from './store.ts';

export const ZERO_OID = '0'.repeat(40);
const PKT_LINE_MAX = 65520;
/** Data bytes per sideband packet: well under the 65516 payload limit (checks-git.ts:1025). */
const SIDEBAND_CHUNK = 32768;

const TYPE_CODE: Record<string, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const CODE_TYPE: Record<number, string> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

/* ------------------------------------------------------------------ pkt-line */

function pktLine(payload: Buffer | string): Buffer {
  const body = Buffer.isBuffer(payload) ? payload : Buffer.from(payload, 'utf8');
  if (body.length + 4 > PKT_LINE_MAX) throw new Error('pkt-line too long');
  return Buffer.concat([
    Buffer.from((body.length + 4).toString(16).padStart(4, '0'), 'ascii'),
    body,
  ]);
}

const pktFlush = (): Buffer => Buffer.from('0000', 'ascii');

interface PktPacket {
  kind: 'data' | 'flush' | 'delim' | 'response-end';
  payload: Buffer;
}

/** Decode a whole buffer of pkt-lines. Throws on any malformed framing. */
function decodePktLines(buf: Buffer): PktPacket[] {
  const packets: PktPacket[] = [];
  let off = 0;
  while (off < buf.length) {
    if (off + 4 > buf.length) throw new Error('truncated pkt-line header');
    const hex = buf.subarray(off, off + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(hex)) throw new Error('bad pkt-line length');
    const len = parseInt(hex, 16);
    if (len === 0) {
      packets.push({ kind: 'flush', payload: Buffer.alloc(0) });
      off += 4;
      continue;
    }
    if (len === 1) {
      packets.push({ kind: 'delim', payload: Buffer.alloc(0) });
      off += 4;
      continue;
    }
    if (len === 2) {
      packets.push({ kind: 'response-end', payload: Buffer.alloc(0) });
      off += 4;
      continue;
    }
    if (len < 4 || len > PKT_LINE_MAX) throw new Error('bad pkt-line length');
    if (off + len > buf.length) throw new Error('truncated pkt-line');
    packets.push({ kind: 'data', payload: buf.subarray(off + 4, off + len) });
    off += len;
  }
  return packets;
}

/* ------------------------------------------------------------------ packs */

/** Git object-header varint: type in bits 4-6 of the first byte, size little-endian base-128. */
function encodeObjectHeader(typeCode: number, size: number): Buffer {
  const out: number[] = [];
  let b = (typeCode << 4) | (size & 0x0f);
  size >>= 4;
  while (size !== 0) {
    out.push(b | 0x80);
    b = size & 0x7f;
    size >>= 7;
  }
  out.push(b);
  return Buffer.from(out);
}

function readVarint(buf: Buffer, off: number): { size: number; typeCode: number; next: number } {
  if (off >= buf.length) throw new Error('truncated object header');
  let byte = buf[off++];
  const typeCode = (byte >> 4) & 0x07;
  let size = byte & 0x0f;
  let shift = 4;
  while (byte & 0x80) {
    if (off >= buf.length) throw new Error('truncated object header');
    byte = buf[off++];
    size += (byte & 0x7f) * 2 ** shift;
    shift += 7;
  }
  return { size, typeCode, next: off };
}

/** Build a pack of plain objects (no deltas), entries sorted by oid for determinism. */
function buildPack(objects: Map<string, GitObject>): Buffer {
  const header = Buffer.alloc(12);
  header.write('PACK', 0, 'ascii');
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(objects.size, 8);
  const parts: Buffer[] = [header];
  for (const oid of [...objects.keys()].sort()) {
    const obj = objects.get(oid)!;
    parts.push(encodeObjectHeader(TYPE_CODE[obj.type], obj.data.length));
    parts.push(deflateSync(obj.data));
  }
  const body = Buffer.concat(parts);
  return Buffer.concat([body, createHash('sha1').update(body).digest()]);
}

/**
 * Parse + verify a pushed pack. Throws on any defect (bad header, bad trailer, delta entry,
 * size mismatch, stray bytes, conflicting duplicate). Mirrors the client's readPack
 * (git-client.ts:707) and inflateAt (:615, inflateSync with {info:true} + bytesWritten).
 */
function parsePack(buf: Buffer): Map<string, GitObject> {
  if (buf.length < 32) throw new Error('pack too short');
  if (buf.subarray(0, 4).toString('ascii') !== 'PACK') throw new Error('bad pack header');
  const version = buf.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error('unsupported pack version');
  const count = buf.readUInt32BE(8);
  const trailerStart = buf.length - 20;
  const trailer = buf.subarray(trailerStart).toString('hex');
  if (createHash('sha1').update(buf.subarray(0, trailerStart)).digest('hex') !== trailer) {
    throw new Error('pack trailer checksum mismatch');
  }
  const out = new Map<string, GitObject>();
  let off = 12;
  for (let i = 0; i < count; i++) {
    const h = readVarint(buf, off);
    off = h.next;
    const type = CODE_TYPE[h.typeCode];
    if (!type) throw new Error(`unknown pack object type ${h.typeCode}`);
    // Delta entries (type 6/7) have no CODE_TYPE entry, so they are rejected above.
    const inflated = inflateSync(buf.subarray(off, trailerStart), { info: true }) as unknown as {
      buffer: Buffer;
      engine: { bytesWritten: number };
    };
    const data: Buffer = inflated.buffer;
    const consumed: number = inflated.engine.bytesWritten;
    if (!consumed || consumed <= 0) throw new Error('zlib stream consumed no bytes');
    if (data.length !== h.size) throw new Error('object size mismatch');
    off += consumed;
    const oid = sha1Hex(Buffer.concat([Buffer.from(`${type} ${data.length}\0`, 'utf8'), data]));
    const prev = out.get(oid);
    if (prev && !prev.data.equals(data)) throw new Error('conflicting duplicate object');
    out.set(oid, { type: type as GitObject['type'], data });
  }
  if (off !== trailerStart) throw new Error('pack has stray bytes');
  return out;
}

/* ------------------------------------------------------- reachability helpers */

/** Parse a tag object: {target, targetType, name} or null when the bytes are not a tag. */
function parseTag(data: Buffer): { target: string; targetType: string; name: string } | null {
  const text = data.toString('utf8');
  const obj = /^object ([0-9a-f]{40})\n/.exec(text);
  const typ = /^type (\w+)\n/m.exec(text);
  const tag = /^tag ([^\n]*)\n/m.exec(text);
  if (!obj || !typ) return null;
  return { target: obj[1], targetType: typ[1], name: tag ? tag[1] : '' };
}

/** Commit parents, memoised in repo.parents (built once per object, never re-parsed). */
function commitParents(repo: Repo, oid: string): string[] {
  const memo = repo.parents.get(oid);
  if (memo !== undefined) return memo;
  const obj = repo.objects.get(oid);
  let parents: string[] = [];
  if (obj && obj.type === 'commit') {
    try {
      parents = parseCommit(obj.data).parents;
    } catch {
      parents = [];
    }
  }
  repo.parents.set(oid, parents);
  return parents;
}

/** Add a tree and everything reachable from it (subtrees + blobs) to `out`. */
function treeClosure(repo: Repo, treeSha: string, out: Set<string>): void {
  const stack = [treeSha];
  while (stack.length > 0) {
    const sha = stack.pop()!;
    if (out.has(sha)) continue;
    const obj = repo.objects.get(sha);
    if (!obj) continue;
    out.add(sha);
    if (obj.type !== 'tree') continue;
    let entries: Array<{ mode: string; name: string; sha: string }> = [];
    try {
      entries = parseTree(obj.data);
    } catch {
      continue;
    }
    for (const e of entries) {
      if (e.mode === '160000') continue; // gitlink: not stored, never sent
      if (e.mode === '40000') stack.push(e.sha);
      else out.add(e.sha);
    }
  }
}

/** Full closure of commits (parents + trees) and tag targets, no depth limit. */
function fullClosure(repo: Repo, seeds: string[]): Set<string> {
  const out = new Set<string>();
  const stack = [...seeds];
  while (stack.length > 0) {
    const oid = stack.pop()!;
    if (out.has(oid)) continue;
    const obj = repo.objects.get(oid);
    if (!obj) continue;
    out.add(oid);
    if (obj.type === 'commit') {
      try {
        const c = parseCommit(obj.data);
        if (c.tree) treeClosure(repo, c.tree, out);
        for (const p of c.parents) stack.push(p);
      } catch {
        /* corrupt commit bytes: treat as a leaf */
      }
    } else if (obj.type === 'tag') {
      const t = parseTag(obj.data);
      if (t) stack.push(t.target);
    }
  }
  return out;
}

interface FetchPlan {
  objects: Map<string, GitObject>;
  shallow: string[];
  unshallow: string[];
}

/**
 * The fetch set: closure(wants) with an optional commit-depth cutoff, minus closure(haves).
 * Depth counts commit generations: deepen 1 = the want commits only, deepen 2 = + parents.
 * A `have` that is also listed as `shallow` is a boundary the client already holds: its
 * commit + tree are excluded, but its parents are NOT (they are exactly what a deepen asks
 * for). Boundary commits (cut off by depth, with parents not sent) are reported as `shallow`;
 * old boundaries whose parents are now included are reported as `unshallow`.
 */
function computeFetch(
  repo: Repo,
  wants: string[],
  haves: string[],
  shallows: string[],
  deepen: number | null,
): FetchPlan {
  const shallowSet = new Set(shallows);
  // 1. Expand wants: tag objects are sent as-is and resolve to their target commit.
  const wantCommits: string[] = [];
  const extra = new Set<string>();
  const expandQueue = [...wants];
  const seenWant = new Set<string>();
  while (expandQueue.length > 0) {
    const w = expandQueue.pop()!;
    if (seenWant.has(w)) continue;
    seenWant.add(w);
    const obj = repo.objects.get(w);
    if (!obj) continue; // unknown want: the client only asks for advertised tips
    if (obj.type === 'tag') {
      extra.add(w);
      const t = parseTag(obj.data);
      if (t) {
        if (t.targetType === 'commit') wantCommits.push(t.target);
        else if (t.targetType === 'tag') expandQueue.push(t.target);
        else extra.add(t.target);
      }
    } else if (obj.type === 'commit') wantCommits.push(w);
    else extra.add(w);
  }
  // 2. Depth-limited commit walk (BFS, first visit = smallest level).
  const maxLevel = deepen === null ? Infinity : deepen - 1;
  const levels = new Map<string, number>();
  const boundary = new Set<string>();
  const queue: Array<{ oid: string; level: number }> = wantCommits.map((oid) => ({ oid, level: 0 }));
  while (queue.length > 0) {
    const { oid, level } = queue.shift()!;
    if (levels.has(oid)) continue;
    const obj = repo.objects.get(oid);
    if (!obj || obj.type !== 'commit') continue;
    levels.set(oid, level);
    for (const p of commitParents(repo, oid)) {
      if (level + 1 > maxLevel) boundary.add(oid);
      else queue.push({ oid: p, level: level + 1 });
    }
  }
  // 3. Included objects: wanted commits + their full tree closures + extra wants.
  const included = new Set<string>(extra);
  for (const oid of levels.keys()) {
    included.add(oid);
    const obj = repo.objects.get(oid);
    if (obj && obj.type === 'commit') {
      try {
        const tree = parseCommit(obj.data).tree;
        if (tree) treeClosure(repo, tree, included);
      } catch {
        /* corrupt commit bytes: nothing more to include */
      }
    }
  }
  // 4. Exclusion from haves.
  const excluded = new Set<string>();
  for (const h of haves) {
    const obj = repo.objects.get(h);
    if (!obj) continue;
    if (shallowSet.has(h)) {
      // Shallow have: the commit + its tree only, NOT its parents.
      excluded.add(h);
      if (obj.type === 'commit') {
        try {
          const tree = parseCommit(obj.data).tree;
          if (tree) treeClosure(repo, tree, excluded);
        } catch {
          /* ignore */
        }
      } else if (obj.type === 'tag') {
        const t = parseTag(obj.data);
        if (t && t.targetType === 'commit') {
          excluded.add(t.target);
          const target = repo.objects.get(t.target);
          if (target) {
            try {
              const tree = parseCommit(target.data).tree;
              if (tree) treeClosure(repo, tree, excluded);
            } catch {
              /* ignore */
            }
          }
        }
      }
    } else if (obj.type === 'commit') {
      for (const o of fullClosure(repo, [h])) excluded.add(o);
    } else if (obj.type === 'tag') {
      excluded.add(h);
      const t = parseTag(obj.data);
      if (t) {
        if (t.targetType === 'commit') for (const o of fullClosure(repo, [t.target])) excluded.add(o);
        else excluded.add(t.target);
      }
    } else {
      excluded.add(h);
    }
  }
  // 5. The send set.
  const send = new Map<string, GitObject>();
  for (const oid of included) {
    if (excluded.has(oid)) continue;
    const obj = repo.objects.get(oid);
    if (obj) send.set(oid, obj);
  }
  // 6. Shallow-info: boundaries that are actually sent; old boundaries now fully fetched.
  const shallow = [...boundary].filter((o) => send.has(o)).sort();
  const unshallow = shallows.filter((s) => levels.has(s) && !boundary.has(s)).sort();
  return { objects: send, shallow, unshallow };
}

/* ------------------------------------------------------------------ refs */

/** All refs, sorted by name: refs/heads/* from branches, refs/tags/* from tags. */
function allRefs(repo: Repo): Array<{ name: string; oid: string }> {
  const refs: Array<{ name: string; oid: string }> = [];
  for (const [branch, tip] of repo.refs) {
    if (tip) refs.push({ name: `refs/heads/${branch}`, oid: tip });
  }
  for (const [tag, oid] of repo.tags) {
    refs.push({ name: `refs/tags/${tag}`, oid });
  }
  return refs.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
}

/** Peel an annotated tag to its commit oid; null when the ref does not point at a tag. */
function peeledOid(repo: Repo, refOid: string): string | null {
  let cur = refOid;
  for (let i = 0; i < 10; i++) {
    const obj = repo.objects.get(cur);
    if (!obj || obj.type !== 'tag') return null;
    const t = parseTag(obj.data);
    if (!t) return null;
    if (t.targetType === 'commit') return t.target;
    if (t.targetType === 'tag') {
      cur = t.target;
      continue;
    }
    return null;
  }
  return null;
}

function refCurrent(repo: Repo, ref: string): string | null {
  if (ref.startsWith('refs/heads/')) return repo.refs.get(ref.slice('refs/heads/'.length)) ?? null;
  if (ref.startsWith('refs/tags/')) return repo.tags.get(ref.slice('refs/tags/'.length)) ?? null;
  return null;
}

function setRef(repo: Repo, ref: string, oid: string | null): void {
  if (ref.startsWith('refs/heads/')) {
    const branch = ref.slice('refs/heads/'.length);
    if (oid === null) repo.refs.delete(branch);
    else repo.refs.set(branch, oid);
  } else if (ref.startsWith('refs/tags/')) {
    const tag = ref.slice('refs/tags/'.length);
    if (oid === null) repo.tags.delete(tag);
    else repo.tags.set(tag, oid);
  }
}

/** True when oldOid is reachable from newOid by walking first-parent chains (any parent). */
function isAncestor(repo: Repo, oldOid: string, newOid: string): boolean {
  if (oldOid === newOid) return true;
  const seen = new Set<string>();
  const stack = [newOid];
  while (stack.length > 0) {
    const cur = stack.pop()!;
    if (cur === oldOid) return true;
    if (seen.has(cur)) continue;
    seen.add(cur);
    if (seen.size > 100000) return false; // cycle guard for corrupt parent chains
    for (const p of commitParents(repo, cur)) stack.push(p);
  }
  return false;
}

/* ------------------------------------------------------- advertisements */

const V0_UPLOAD_CAPS =
  'side-band-64k shallow thin-pack ofs-delta multi_ack_detailed symref=HEAD:refs/heads/main';
const V0_RECEIVE_CAPS =
  'report-status report-status-v2 side-band-64k delete-refs ofs-delta symref=HEAD:refs/heads/main';

function v0Advertisement(repo: Repo, service: 'git-upload-pack' | 'git-receive-pack'): Buffer {
  const caps = service === 'git-upload-pack' ? V0_UPLOAD_CAPS : V0_RECEIVE_CAPS;
  const chunks: Buffer[] = [pktLine(`# service=${service}\n`), pktFlush()];
  const refs = allRefs(repo);
  const mainTip = repo.refs.get('main') ?? null;
  if (refs.length === 0) {
    chunks.push(pktLine(`${ZERO_OID} capabilities^{}\0${caps}\n`));
  } else {
    chunks.push(pktLine(`${mainTip ?? ZERO_OID} HEAD\0${caps}\n`));
    for (const r of refs) {
      chunks.push(pktLine(`${r.oid} ${r.name}\n`));
      const peeled = peeledOid(repo, r.oid);
      if (peeled) chunks.push(pktLine(`${peeled} ${r.name}^{}\n`));
    }
  }
  chunks.push(pktFlush());
  return Buffer.concat(chunks);
}

function v2Advertisement(): Buffer {
  return Buffer.concat([
    pktLine('version 2\n'),
    pktLine('ls-refs=unborn\n'),
    pktLine('fetch=shallow filter\n'),
    pktLine('object-format=sha1\n'),
    pktFlush(),
  ]);
}

/* ------------------------------------------------------- ls-refs (v2) */

function handleLsRefs(repo: Repo, args: string[]): Buffer {
  const wantPeel = args.includes('peel');
  const wantSymrefs = args.includes('symrefs');
  const prefixes = args
    .filter((a) => a.startsWith('ref-prefix '))
    .map((a) => a.slice('ref-prefix '.length));
  const out: Buffer[] = [];
  const mainTip = repo.refs.get('main') ?? null;
  // HEAD is sent only when no ref-prefix is given (the ls-refs-prefix trap).
  if (prefixes.length === 0) {
    const sym = wantSymrefs ? ' symref-target:refs/heads/main' : '';
    out.push(pktLine(mainTip ? `${mainTip} HEAD${sym}\n` : `unborn HEAD${sym}\n`));
  }
  for (const r of allRefs(repo)) {
    if (prefixes.length > 0 && !prefixes.some((p) => r.name.startsWith(p))) continue;
    let line = `${r.oid} ${r.name}`;
    if (wantPeel) {
      const peeled = peeledOid(repo, r.oid);
      if (peeled) line += ` peeled:${peeled}`;
    }
    out.push(pktLine(`${line}\n`));
  }
  out.push(pktFlush());
  return Buffer.concat(out);
}

/* ------------------------------------------------------- fetch */

function parseFetchArgs(lines: string[]): {
  wants: string[];
  haves: string[];
  shallows: string[];
  deepen: number | null;
} {
  const wants: string[] = [];
  const haves: string[] = [];
  const shallows: string[] = [];
  let deepen: number | null = null;
  for (const raw of lines) {
    const line = raw.replace(/\n$/, '');
    if (line.startsWith('want ')) wants.push(line.slice(5, 45));
    else if (line.startsWith('have ')) haves.push(line.slice(5, 45));
    else if (line.startsWith('shallow ')) shallows.push(line.slice(8, 48));
    else if (line.startsWith('deepen ')) {
      const n = parseInt(line.slice(7), 10);
      if (Number.isFinite(n) && n > 0) deepen = n;
    }
    // thin-pack, no-progress, ofs-delta, filter, deepen-since, deepen-not, done:
    // accepted and ignored (the server always sends full plain objects).
  }
  return { wants, haves, shallows, deepen };
}

/** Split a v2 upload-pack body into the command block and the args after the delim. */
function parseV2UploadPack(body: Buffer): { command: string; args: string[] } {
  const packets = decodePktLines(body);
  let inArgs = false;
  const cmdLines: string[] = [];
  const args: string[] = [];
  for (const p of packets) {
    if (p.kind === 'flush') break;
    if (p.kind === 'delim') {
      inArgs = true;
      continue;
    }
    if (p.kind !== 'data') continue;
    // Strip the trailing newline once here so every arg comparison sees the bare token
    // ('symrefs', 'peel', 'ref-prefix refs/heads/'); parseFetchArgs strips it again harmlessly.
    const line = p.payload.toString('utf8').replace(/\n$/, '');
    if (!inArgs) cmdLines.push(line);
    else args.push(line);
  }
  const m = /^command=([a-z-]+)/.exec(cmdLines[0] ?? '');
  return { command: m ? m[1] : '', args };
}

/** Split a v0 fetch body into its two sections: wants/shallow/deepen, then haves/done. */
function parseV0Fetch(body: Buffer): {
  wants: string[];
  haves: string[];
  shallows: string[];
  deepen: number | null;
} {
  const packets = decodePktLines(body);
  const sections: string[][] = [[]];
  for (const p of packets) {
    if (p.kind === 'flush') {
      sections.push([]);
      continue;
    }
    if (p.kind === 'data') sections[sections.length - 1].push(p.payload.toString('utf8'));
  }
  const first = parseFetchArgs(sections[0] ?? []);
  const second = parseFetchArgs(sections[1] ?? []);
  return { wants: first.wants, haves: second.haves, shallows: first.shallows, deepen: first.deepen };
}

/** Chop a pack into band-1 sideband packets (never an empty packet). */
function sidebandChunks(pack: Buffer): Buffer[] {
  const out: Buffer[] = [];
  for (let off = 0; off < pack.length; off += SIDEBAND_CHUNK) {
    const data = pack.subarray(off, Math.min(off + SIDEBAND_CHUNK, pack.length));
    out.push(pktLine(Buffer.concat([Buffer.from([1]), data])));
  }
  return out;
}

function handleFetchV2(repo: Repo, args: string[]): Buffer {
  const req = parseFetchArgs(args);
  const plan = computeFetch(repo, req.wants, req.haves, req.shallows, req.deepen);
  const pack = buildPack(plan.objects);
  const chunks: Buffer[] = [pktLine('acknowledgments\n'), pktLine('NAK\n'), pktFlush()];
  if (plan.shallow.length > 0 || plan.unshallow.length > 0) {
    chunks.push(pktLine('shallow-info\n'));
    for (const s of plan.shallow) chunks.push(pktLine(`shallow ${s}\n`));
    for (const s of plan.unshallow) chunks.push(pktLine(`unshallow ${s}\n`));
    chunks.push(pktFlush());
  }
  chunks.push(pktLine('packfile\n'));
  chunks.push(...sidebandChunks(pack));
  chunks.push(pktFlush());
  return Buffer.concat(chunks);
}

function handleFetchV0(repo: Repo, body: Buffer): Buffer {
  const req = parseV0Fetch(body);
  const plan = computeFetch(repo, req.wants, req.haves, req.shallows, req.deepen);
  const pack = buildPack(plan.objects);
  const chunks: Buffer[] = [pktLine('NAK\n')];
  for (const s of plan.shallow) chunks.push(pktLine(`shallow ${s}\n`));
  for (const s of plan.unshallow) chunks.push(pktLine(`unshallow ${s}\n`));
  chunks.push(...sidebandChunks(pack));
  chunks.push(pktFlush());
  return Buffer.concat(chunks);
}

/* ------------------------------------------------------- receive-pack */

interface PushCommand {
  oldOid: string;
  newOid: string;
  ref: string;
}

function applyCommand(repo: Repo, cmd: PushCommand): { ok: boolean; reason: string } {
  const isKnownNs = cmd.ref.startsWith('refs/heads/') || cmd.ref.startsWith('refs/tags/');
  if (!isKnownNs) return { ok: false, reason: 'non-fast-forward' };
  const cur = refCurrent(repo, cmd.ref);
  if (cmd.newOid === ZERO_OID) {
    // Delete: the ref must exist and old must match its tip.
    if (cur === null || cur !== cmd.oldOid) return { ok: false, reason: 'non-fast-forward' };
    setRef(repo, cmd.ref, null);
    return { ok: true, reason: '' };
  }
  if (cmd.oldOid === ZERO_OID) {
    // Create: the ref must not exist and the new object must be stored.
    if (cur !== null) return { ok: false, reason: 'non-fast-forward' };
    if (!repo.objects.has(cmd.newOid)) return { ok: false, reason: 'non-fast-forward' };
    setRef(repo, cmd.ref, cmd.newOid);
    return { ok: true, reason: '' };
  }
  // Update: old must match the tip and be an ancestor of new.
  if (cur === null || cur !== cmd.oldOid) return { ok: false, reason: 'non-fast-forward' };
  if (!repo.objects.has(cmd.newOid)) return { ok: false, reason: 'non-fast-forward' };
  if (!isAncestor(repo, cmd.oldOid, cmd.newOid)) return { ok: false, reason: 'non-fast-forward' };
  setRef(repo, cmd.ref, cmd.newOid);
  return { ok: true, reason: '' };
}

function wrapPushReport(lines: string[], sideband: boolean): Buffer {
  const text = Buffer.concat(lines.map((l) => pktLine(l)));
  if (!sideband) return Buffer.concat([text, pktFlush()]);
  const chunks: Buffer[] = [];
  for (let off = 0; off < text.length; off += SIDEBAND_CHUNK) {
    chunks.push(
      pktLine(Buffer.concat([Buffer.from([1]), text.subarray(off, Math.min(off + SIDEBAND_CHUNK, text.length))])),
    );
  }
  chunks.push(pktFlush());
  return Buffer.concat(chunks);
}

function handleReceivePack(repo: Repo, body: Buffer): Buffer {
  // 1. Parse the command list up to the first flush; the rest of the body is the pack.
  const commands: PushCommand[] = [];
  let caps = '';
  let off = 0;
  let sawFlush = false;
  while (off < body.length) {
    if (off + 4 > body.length) throw new Error('truncated pkt-line header');
    const hex = body.subarray(off, off + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(hex)) throw new Error('bad pkt-line length');
    const len = parseInt(hex, 16);
    if (len === 0) {
      off += 4;
      sawFlush = true;
      break;
    }
    if (len < 4 || len > PKT_LINE_MAX || off + len > body.length) throw new Error('bad pkt-line');
    let line = body.subarray(off + 4, off + len).toString('utf8');
    off += len;
    const nul = line.indexOf('\0');
    if (nul >= 0) {
      if (!caps) caps = line.slice(nul + 1);
      line = line.slice(0, nul);
    }
    const m = /^([0-9a-f]{40}) ([0-9a-f]{40}) (refs\/\S+)\n?$/.exec(line.replace(/\n$/, ''));
    if (!m) throw new Error('bad push command');
    commands.push({ oldOid: m[1], newOid: m[2], ref: m[3] });
  }
  if (!sawFlush || commands.length === 0) throw new Error('no push commands');
  const packBytes = body.subarray(off);
  const sideband = caps.split(' ').includes('side-band-64k');

  // 2. Unpack FIRST (a refused push must still unpack: checks-git.ts:865).
  const needsPack = commands.some((c) => c.newOid !== ZERO_OID);
  let unpackError: string | null = null;
  if (needsPack) {
    if (packBytes.length === 0) {
      unpackError = 'missing pack';
    } else {
      try {
        const unpacked = parsePack(packBytes);
        for (const [oid, obj] of unpacked) {
          if (!repo.objects.has(oid)) repo.objects.set(oid, obj);
          if (obj.type === 'commit') commitParents(repo, oid);
        }
      } catch (err) {
        unpackError = (err as Error).message;
      }
    }
  }

  // 3. Evaluate each command independently (partial-apply, never all-or-nothing).
  const reportLines: string[] = [];
  if (unpackError !== null) {
    reportLines.push(`unpack ${unpackError}\n`);
  } else {
    reportLines.push('unpack ok\n');
    for (const cmd of commands) {
      const res = applyCommand(repo, cmd);
      reportLines.push(res.ok ? `ok ${cmd.ref}\n` : `ng ${cmd.ref} ${res.reason}\n`);
    }
  }
  return wrapPushReport(reportLines, sideband);
}

/* ------------------------------------------------------- dispatcher */

function sendGitJson(res: ServerResponse, status: number, obj: unknown, requestId: string): void {
  const text = `${JSON.stringify(obj)}\n`;
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(text),
    'x-github-request-id': requestId,
  });
  res.end(text);
}

export interface GitContext {
  store: Store;
  method: string;
  path: string;
  query: URLSearchParams;
  headers: NodeJS.Dict<string | string[] | undefined>;
  rawBody: Buffer;
  res: ServerResponse;
  requestId: string;
}

/**
 * Handle a git smart-HTTP request. Returns true when the path is a git path (the response
 * has been written, binary or JSON); false when it is not a git path at all.
 * Never throws out of a git path: malformed requests are answered 400 without touching state.
 */
export function handleGit(ctx: GitContext): boolean {
  const m = /^\/([^/]+)\/([^/]+)\.git\/(info\/refs|git-upload-pack|git-receive-pack)$/.exec(ctx.path);
  if (!m) return false;
  const [, owner, repoName, action] = m;
  try {
    const repo = repoOf(ctx.store, owner, repoName);
    if (!repo) {
      sendGitJson(ctx.res, 404, { message: 'Not Found' }, ctx.requestId);
      return true;
    }
    if (action === 'info/refs') {
      if (ctx.method !== 'GET') {
        sendGitJson(ctx.res, 405, { message: 'Method Not Allowed' }, ctx.requestId);
        return true;
      }
      const service = ctx.query.get('service');
      if (service !== 'git-upload-pack' && service !== 'git-receive-pack') {
        sendGitJson(ctx.res, 400, { message: 'Missing service' }, ctx.requestId);
        return true;
      }
      const isV2 =
        service === 'git-upload-pack' && ctx.headers['git-protocol'] === 'version=2';
      const body =
        service === 'git-receive-pack'
          ? v0Advertisement(repo, 'git-receive-pack')
          : isV2
            ? v2Advertisement()
            : v0Advertisement(repo, 'git-upload-pack');
      ctx.res.writeHead(200, {
        'content-type': `application/x-${service}-advertisement`,
        'x-github-request-id': ctx.requestId,
      });
      ctx.res.end(body);
      return true;
    }
    if (ctx.method !== 'POST') {
      sendGitJson(ctx.res, 405, { message: 'Method Not Allowed' }, ctx.requestId);
      return true;
    }
    if (action === 'git-upload-pack') {
      const isV2 = ctx.headers['git-protocol'] === 'version=2';
      let body: Buffer;
      if (isV2) {
        const { command, args } = parseV2UploadPack(ctx.rawBody);
        if (command === 'ls-refs') body = handleLsRefs(repo, args);
        else if (command === 'fetch') body = handleFetchV2(repo, args);
        else {
          sendGitJson(ctx.res, 400, { message: 'Unknown command' }, ctx.requestId);
          return true;
        }
      } else {
        body = handleFetchV0(repo, ctx.rawBody);
      }
      ctx.res.writeHead(200, {
        'content-type': 'application/x-git-upload-pack-result',
        'x-github-request-id': ctx.requestId,
      });
      ctx.res.end(body);
      return true;
    }
    // git-receive-pack
    const body = handleReceivePack(repo, ctx.rawBody);
    ctx.res.writeHead(200, {
      'content-type': 'application/x-git-receive-pack-result',
      'x-github-request-id': ctx.requestId,
    });
    ctx.res.end(body);
    return true;
  } catch {
    // Malformed git request: answer 400, keep the process and the store intact.
    try {
      if (!ctx.res.headersSent) sendGitJson(ctx.res, 400, { message: 'Bad git request' }, ctx.requestId);
      else ctx.res.end();
    } catch {
      /* the response is already gone; nothing more to do */
    }
    return true;
  }
}
