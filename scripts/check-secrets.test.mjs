import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const scanner = fileURLToPath(new URL('./check-secrets.mjs', import.meta.url));

test('scanner accepts placeholders, masks new leaks, and checks history', () => {
  const root = mkdtempSync(join(tmpdir(), 'validator-secret-scan-'));
  const safeRoot = resolve(root);
  assert.ok(safeRoot.startsWith(resolve(tmpdir()) + sep));
  const git = (...args) => execFileSync('git', args, { cwd: root, encoding: 'utf8' });
  const scan = (...args) => execFileSync(process.execPath, [scanner, ...args], { cwd: root, encoding: 'utf8' });
  try {
    git('init', '-b', 'main');
    git('config', 'user.name', 'Scanner Test');
    git('config', 'user.email', 'scanner@example.invalid');
    writeFileSync(join(root, 'README.md'), 'OIDC_CLIENT_SECRET=REPLACE_WITH_SECRET\n');
    git('add', 'README.md');
    git('commit', '-m', 'safe placeholder');
    assert.match(scan('--tracked', '--history'), /0 finding/);

    const synthetic = 'ghp_' + 'A'.repeat(36);
    writeFileSync(join(root, 'leak.txt'), `token=${synthetic}\n`);
    git('add', 'leak.txt');
    assert.throws(() => scan('--tracked'), error => {
      assert.equal(error.status, 1);
      assert.match(error.stderr, /github_token/);
      assert.ok(!error.stderr.includes(synthetic));
      return true;
    });
    git('commit', '-m', 'synthetic leak');
    git('rm', 'leak.txt');
    git('commit', '-m', 'remove leak');
    assert.throws(() => scan('--history'), error => error.status === 1);

    writeFileSync(join(root, '.env'), 'APP_MASTER_KEY=REPLACE_WITH_KEY\n');
    git('add', '-f', '.env');
    assert.throws(() => scan('--tracked'), error => error.status === 1 && error.stderr.includes('blocked_file'));
  } finally {
    rmSync(safeRoot, { recursive: true, force: true });
  }
});
