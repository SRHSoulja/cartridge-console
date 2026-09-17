/**
 * Automated Repository Boundary Audit
 *
 * Verifies that cartridge-console (PUBLIC) maintains strict isolation from
 * private application repos (MARKS/TARGETS).
 *
 * Checks:
 * 1. No unreleased MARKS/TARGETS mechanics or secrets in source code or docs
 * 2. Host core, runtime, and protocol contracts contain zero application couplings
 * 3. Repository visibility configuration matches disclosure policy
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const ROOT_DIR = path.resolve(__dirname, '..');

// Directories to scan
const SCAN_DIRS = [
  'src',
  'host',
  'runtime',
  'docs',
  'cartridge-template'
];

// Terms that are forbidden in public platform files
// (Unreleased MARKS / TARGETS proprietary mechanics, secrets, or internal lineage terms)
const FORBIDDEN_APPLICATION_TERMS = [
  'shoot',
  'poach',
  'debond',
  'heist',
  'goldenarrow',
  'targetlineup',
  'splitdynamics'
];

function scanDirectory(dirPath, fileList = []) {
  if (!fs.existsSync(dirPath)) return fileList;
  const entries = fs.readdirSync(dirPath, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dirPath, entry.name);
    if (entry.isDirectory()) {
      if (entry.name !== 'node_modules' && entry.name !== '.git' && entry.name !== 'lib') {
        scanDirectory(fullPath, fileList);
      }
    } else if (entry.isFile()) {
      // Check code, json, and markdown files
      if (/\.(js|sol|json|md|html)$/.test(entry.name)) {
        fileList.push(fullPath);
      }
    }
  }
  return fileList;
}

function runAudit() {
  console.log('🔒 Starting Repository Boundary & Privacy Isolation Audit...\n');

  let filesChecked = 0;
  let violations = [];

  for (const subDir of SCAN_DIRS) {
    const targetDir = path.join(ROOT_DIR, subDir);
    const files = scanDirectory(targetDir);

    for (const filePath of files) {
      filesChecked++;
      const relativePath = path.relative(ROOT_DIR, filePath);
      const content = fs.readFileSync(filePath, 'utf8');

      // Check for forbidden terms (case-insensitive word boundary)
      for (const term of FORBIDDEN_APPLICATION_TERMS) {
        const regex = new RegExp(`\\b${term}\\b`, 'i');
        if (regex.test(content)) {
          violations.push({
            file: relativePath,
            term,
            message: `Forbidden application mechanic term "${term}" found in public file: ${relativePath}`
          });
        }
      }

      // Check for any private filesystem paths
      if (content.includes('marks-targets/src') || content.includes('rhgoldenarrows/src')) {
        violations.push({
          file: relativePath,
          message: `Private repository internal path reference found in: ${relativePath}`
        });
      }
    }
  }

  console.log(`  Scanned ${filesChecked} files across ${SCAN_DIRS.join(', ')}`);

  if (violations.length > 0) {
    console.error(`\n❌ VIOLATIONS DETECTED (${violations.length}):`);
    violations.forEach(v => {
      console.error(`  - [${v.file}] ${v.message}`);
    });
    console.error('\nAudit failed: Please remove private/proprietary application terms or paths.\n');
    process.exit(1);
  } else {
    console.log('  ✅ PASS: Zero private mechanics, secrets, or internal paths detected in public platform files.\n');
  }

  // Verify AGENTS.md boundaries
  const agentsPath = path.join(ROOT_DIR, 'AGENTS.md');
  assert.ok(fs.existsSync(agentsPath), 'AGENTS.md boundary specification must exist');
  const agentsContent = fs.readFileSync(agentsPath, 'utf8');
  assert.ok(agentsContent.includes('PUBLIC'), 'AGENTS.md must declare public visibility status');
  assert.ok(agentsContent.includes('marks-targets'), 'AGENTS.md must explicitly boundary marks-targets');
  console.log('  ✅ PASS: AGENTS.md repository boundary specification verified.');

  // Verify Zero HoodQuest application coupling in production code & default fixtures
  assert.strictEqual(fs.existsSync(path.join(ROOT_DIR, 'cartridges/hoodquest')), false, 'cartridges/hoodquest must not exist in Console repository HEAD');
  const resolverSource = fs.readFileSync(path.join(ROOT_DIR, 'host/resolver.js'), 'utf8');
  assert.strictEqual(resolverSource.includes("'hoodquest'"), false, 'createDefaultResolver must not contain hoodquest registration');
  assert.strictEqual(resolverSource.includes('"hoodquest"'), false, 'createDefaultResolver must not contain hoodquest registration');

  const prodDirs = ['src', 'host', 'runtime', 'cartridge-template', 'cartridges/reference-cartridge-v1'];
  for (const dir of prodDirs) {
    const fullDir = path.join(ROOT_DIR, dir);
    const prodFiles = scanDirectory(fullDir);
    for (const f of prodFiles) {
      const code = fs.readFileSync(f, 'utf8');
      assert.ok(!code.includes('0xF75323518df7Ce90637e2b93cFd7f7d0627cc205'), `Production file ${f} must not contain HoodQuest Outlaws contract address`);
      assert.ok(!code.includes('0x0676129B2bF4B06f04AfC7301617b6cE3BB2405c'), `Production file ${f} must not contain HoodQuest Loot contract address`);
      assert.ok(!code.includes('0xC115C51a1bf9DdE7B1eD0861E18CaA27f24C3Be9'), `Production file ${f} must not contain HoodQuest Raids contract address`);
    }
  }
  console.log('  ✅ PASS: Production code and default fixtures verified to contain zero HoodQuest coupling.');

  console.log('\n=============================================================');
  console.log('Repository Boundary Audit: ALL CHECKS PASSED');
  console.log('=============================================================\n');
}

runAudit();
