// Verify the installed release plugins can analyze commits and render our preset.
// Usage: node tests/test_release_notes.mjs "$(npm root -g)"
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const modules = resolve(process.argv[2]);
const require = createRequire(resolve(modules, 'semantic-release/package.json'));
const { analyzeCommits } = await import(pathToFileURL(require.resolve('@semantic-release/commit-analyzer')));
const { generateNotes } = await import(pathToFileURL(require.resolve('@semantic-release/release-notes-generator')));
const config = JSON.parse(await readFile(new URL('../.releaserc.json', import.meta.url)));
const options = name => config.plugins.find(plugin => Array.isArray(plugin) && plugin[0] === name)[1];
const context = {
  cwd: resolve(modules, '..'),
  logger: { log() {} },
  options: { repositoryUrl: 'https://github.com/maxgfr/package-checker.sh' },
  commits: [{ hash: '1234567890abcdef', message: 'fix: restore automatic releases' }],
  lastRelease: { version: '1.11.54', gitTag: 'v1.11.54' },
  nextRelease: { version: '1.11.55', gitTag: 'v1.11.55' },
};
assert.equal(await analyzeCommits(options('@semantic-release/commit-analyzer'), context), 'patch');
const notes = await generateNotes(options('@semantic-release/release-notes-generator'), context);
assert.match(notes, /1\.11\.55/);
assert.match(notes, /Bug Fixes/);
assert.match(notes, /restore automatic releases/);
console.log('Release plugins: patch analysis and changelog rendering passed');
