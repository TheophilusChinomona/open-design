// Phase 6 — `od workspace` dual-track CLI over better-auth organization endpoints.
// Stub-server + exec-the-real-cli, following cli-auth.test.ts.

import http from 'node:http';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve as pathResolve } from 'node:path';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DAEMON_ROOT = pathResolve(__dirname, '..');
const REPO_ROOT = pathResolve(__dirname, '../../..');
const CLI_SRC = pathResolve(__dirname, '../src/cli.ts');
const TSX_CLI = pathResolve(REPO_ROOT, 'node_modules/tsx/dist/cli.mjs');

interface Captured { method: string; url: string; auth: string | undefined; body: string }

async function startStub() {
  const requests: Captured[] = [];
  const server = http.createServer((req, res) => {
    let raw = '';
    req.on('data', (c) => (raw += c));
    req.on('end', () => {
      requests.push({ method: req.method ?? '', url: req.url ?? '', auth: req.headers.authorization, body: raw });
      res.setHeader('content-type', 'application/json');
      const url = req.url ?? '';
      if (url.startsWith('/api/auth/organization/list')) {
        res.end(JSON.stringify([{ id: 'org_1', name: 'Acme', slug: 'acme' }]));
      } else if (url.startsWith('/api/auth/organization/create')) {
        res.end(JSON.stringify({ id: 'org_2', name: JSON.parse(raw).name, slug: JSON.parse(raw).slug }));
      } else if (url.startsWith('/api/auth/organization/set-active')) {
        res.end(JSON.stringify({ id: JSON.parse(raw).organizationId }));
      } else {
        res.statusCode = 404;
        res.end('{}');
      }
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const addr = server.address();
  if (!addr || typeof addr === 'string') throw new Error('no addr');
  return { baseUrl: `http://127.0.0.1:${addr.port}`, requests, close: () => new Promise<void>((r) => server.close(() => r())) };
}

function runCli(args: string[], configFile: string): Promise<{ stdout: string; code: number | null }> {
  return new Promise((resolveRun) => {
    const env: NodeJS.ProcessEnv = { ...process.env, OD_CONFIG_FILE: configFile };
    delete env.NODE_OPTIONS;
    const child = spawn(process.execPath, [TSX_CLI, CLI_SRC, ...args], { cwd: DAEMON_ROOT, env, stdio: ['ignore', 'pipe', 'pipe'], timeout: 20_000 });
    let stdout = '';
    child.stdout.on('data', (c) => (stdout += c));
    child.on('close', (code) => resolveRun({ stdout, code }));
  });
}

describe('od workspace', () => {
  let stub: Awaited<ReturnType<typeof startStub>>;
  let dir: string;
  let configFile: string;
  beforeAll(async () => { stub = await startStub(); dir = mkdtempSync(join(tmpdir(), 'od-ws-')); });
  afterAll(async () => { await stub.close(); rmSync(dir, { recursive: true, force: true }); });
  afterEach(() => { stub.requests.length = 0; });

  function configWithToken() {
    const f = join(dir, `cfg-${Math.random().toString(36).slice(2)}.json`);
    writeFileSync(f, JSON.stringify({ token: 'tok-xyz' }));
    return f;
  }

  it('list sends the bearer token and prints workspaces', async () => {
    configFile = configWithToken();
    const r = await runCli(['workspace', 'list', '--daemon-url', stub.baseUrl, '--json'], configFile);
    expect(r.code).toBe(0);
    expect(JSON.parse(r.stdout)[0]).toMatchObject({ id: 'org_1', slug: 'acme' });
    const req = stub.requests.find((x) => x.url.startsWith('/api/auth/organization/list'));
    expect(req?.auth).toBe('Bearer tok-xyz');
  });

  it('create posts name + derived slug', async () => {
    configFile = configWithToken();
    const r = await runCli(['workspace', 'create', '--name', 'My Team', '--daemon-url', stub.baseUrl, '--json'], configFile);
    expect(r.code).toBe(0);
    const req = stub.requests.find((x) => x.url.startsWith('/api/auth/organization/create'));
    expect(JSON.parse(req!.body)).toEqual({ name: 'My Team', slug: 'my-team' });
  });

  it('switch sets the active organization', async () => {
    configFile = configWithToken();
    const r = await runCli(['workspace', 'switch', 'org_9', '--daemon-url', stub.baseUrl], configFile);
    expect(r.code).toBe(0);
    const req = stub.requests.find((x) => x.url.startsWith('/api/auth/organization/set-active'));
    expect(JSON.parse(req!.body)).toEqual({ organizationId: 'org_9' });
  });

  it('--token flag overrides the stored token', async () => {
    configFile = configWithToken();
    await runCli(['workspace', 'list', '--token', 'flagtok', '--daemon-url', stub.baseUrl], configFile);
    const req = stub.requests.find((x) => x.url.startsWith('/api/auth/organization/list'));
    expect(req?.auth).toBe('Bearer flagtok');
  });
});
