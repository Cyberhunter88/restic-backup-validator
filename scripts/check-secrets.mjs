#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const args = new Set(process.argv.slice(2));
const git = (...argv) => execFileSync('git', argv, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
const patterns = [
  ['private_key', /-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----/g],
  ['github_token', /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{30,}\b/g],
  ['github_fine_grained_token', /\bgithub_pat_[A-Za-z0-9_]{40,}\b/g],
  ['aws_access_key', /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g],
  ['discord_webhook', /https:\/\/(?:discord\.com|discordapp\.com)\/api\/webhooks\/\d{15,}\/[A-Za-z0-9_-]{30,}/g],
  ['credential_assignment', /(?:PASSWORD|SECRET|TOKEN|API_KEY|ACCESS_KEY)\s*[:=]\s*["']?([A-Za-z0-9+/=_-]{24,})["']?/gi],
];

function blockedPath(path) {
  const normalized = path.replaceAll('\\', '/');
  const base = normalized.split('/').at(-1).toLowerCase();
  return (base === '.env' || (base.startsWith('.env.') && base !== '.env.example') ||
    /\.(?:pem|key|p12|pfx|db|sqlite|sqlite3)$/i.test(base) ||
    normalized.includes('/data/') || normalized.includes('/test-repos/'));
}

function inspect(path, content, source) {
  if (blockedPath(path)) {
    findings.push(`${source}: ${path}: blocked_file`);
    return;
  }
  if (content.length > 50 * 1024 * 1024) {
    findings.push(`${source}: ${path}: unscanned_large_file`);
    return;
  }
  if (content.includes(0)) return;
  const lines = content.toString('utf8').split(/\r?\n/);
  lines.forEach((line, index) => {
    for (const [rule, expression] of patterns) {
      expression.lastIndex = 0;
      let match;
      while ((match = expression.exec(line)) !== null) {
        const value = match[1] ?? match[0];
        if (/^(?:REPLACE_|EXAMPLE_|YOUR_|PLACEHOLDER|CHANGEME)/i.test(value)) continue;
        findings.push(`${source}: ${path}:${index + 1}: ${rule}: [REDACTED]`);
      }
    }
  });
}

function objects(revisionArgs, source) {
  const rows = git('rev-list', '--objects', ...revisionArgs).trim().split('\n').filter(Boolean);
  for (const row of rows) {
    const [oid, ...name] = row.split(' ');
    if (git('cat-file', '-t', oid).trim() !== 'blob') continue;
    const path = name.join(' ') || oid;
    inspect(path, execFileSync('git', ['cat-file', 'blob', oid], { maxBuffer: 64 * 1024 * 1024 }), source);
  }
}

const findings = [];
try {
  if (args.has('--tracked') || args.size === 0) {
    const paths = git('ls-files', '-z').split('\0').filter(Boolean);
    for (const path of paths) inspect(path, readFileSync(path), 'tracked');
  }
  if (args.has('--history')) objects(['--all'], 'history');
  if (args.has('--outgoing')) {
    const input = readFileSync(0, 'utf8').trim();
    const refs = input ? input.split('\n') : [];
    if (refs.length === 0) {
      const head = git('rev-parse', 'HEAD').trim();
      objects([head, '--not', '--remotes'], 'outgoing');
    } else {
      for (const row of refs) {
        const [, localOID, , remoteOID] = row.trim().split(/\s+/);
        if (!localOID || /^0+$/.test(localOID)) continue;
        const revisionArgs = [localOID];
        if (remoteOID && !/^0+$/.test(remoteOID)) revisionArgs.push('^' + remoteOID);
        objects(revisionArgs, 'outgoing');
      }
    }
  }
} catch (error) {
  console.error(`Secret scan could not finish: ${error.message}`);
  process.exit(2);
}

for (const finding of [...new Set(findings)]) console.error(finding);
console.log(`Secret scan: ${findings.length} finding(s)`);
process.exit(findings.length ? 1 : 0);
