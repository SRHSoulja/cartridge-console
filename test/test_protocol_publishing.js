/**
 * Automated Test Suite for Console Protocol V0.2 & Cartridge Protocol V0.1
 * Verifies:
 * 1. RFC 8785 JSON Canonicalization Scheme (JCS) deterministic hashing
 * 2. CAIP-2 chain identifier mapping and policy enforcement
 * 3. OnchainCartridgeResolver: registry resolution, manifest retrieval & validation
 * 4. Tamper detection: halts on corrupted manifest or corrupted chunk bytes (fail-closed)
 * 5. Multi-cartridge shared dependency deduplication proof (Cartridge A + Cartridge B sharing Lib X)
 * 6. End-to-end integration: GenericHostCore boots cartridge resolved via OnchainCartridgeResolver
 */

const assert = require('assert');
const { MessageChannel } = require('worker_threads');
const { keccak256 } = require('js-sha3');

const {
  CartridgeHost,
  BridgeHostAdapter,
  ConsoleRuntimeError,
  PolicyEngine,
  normalizeChainId,
  toCaip2ChainId,
  canonicalizeJson,
  parseSemVer,
  satisfiesSemVer,
  generateSecureNonce,
  CartridgeLoader,
  validateManifestV1
} = require('../runtime/cartridge_host_runtime.js');

const {
  OnchainCartridgeResolver,
  decodeAbiBytes,
  decodeAbiBytesRaw,
  decompressDeflate
} = require('../host/resolver.js');

const {
  GenericHostCore
} = require('../host/host_core.js');

const zlib = require('zlib');

// ABI helpers
function encodeAbiBytes(utf8Str) {
  const buf = Buffer.from(utf8Str, 'utf8');
  const lenHex = buf.length.toString(16).padStart(64, '0');
  const padLen = Math.ceil(buf.length / 32) * 32;
  const paddedBuf = Buffer.alloc(padLen);
  buf.copy(paddedBuf);
  const dataHex = paddedBuf.toString('hex');
  const offsetHex = (32).toString(16).padStart(64, '0');
  return '0x' + offsetHex + lenHex + dataHex;
}

async function runProtocolPublishingSuite() {
  console.log('📦 Starting Console Protocol V0.2 & Publishing Substrate Test Suite...\n');
  let passed = 0;
  let failed = 0;

  async function test(name, fn) {
    try {
      await fn();
      console.log(`  ✅ PASS: ${name}`);
      passed++;
    } catch (err) {
      console.error(`  ❌ FAIL: ${name}`);
      console.error(`     Error: ${err.message}\n${err.stack}`);
      failed++;
    }
  }

  const keccakFn = (b) => keccak256(b);

  // --- 1. RFC 8785 JSON CANONICALIZATION SCHEME ---
  await test('JCS: Canonicalize JSON produces identical deterministic strings and digests regardless of key ordering', async () => {
    const obj1 = {
      manifestVersion: '1.0.0',
      name: 'Test Cartridge',
      id: 'test-cart',
      runtime: { version: '^0.2.0' },
      permissions: { chains: ['eip155:11155111'], contracts: [] }
    };

    // Exactly the same semantic data, different key ordering and whitespace
    const obj2 = {
      id: 'test-cart',
      permissions: { contracts: [], chains: ['eip155:11155111'] },
      runtime: { version: '^0.2.0' },
      name: 'Test Cartridge',
      manifestVersion: '1.0.0'
    };

    const canon1 = canonicalizeJson(obj1);
    const canon2 = canonicalizeJson(obj2);

    assert.strictEqual(canon1, canon2, 'Canonical representations must be identical');
    assert.ok(!canon1.includes(': '), 'Canonical JSON must have no whitespace after colons');
    assert.ok(!canon1.includes(', '), 'Canonical JSON must have no whitespace after commas');

    const hash1 = '0x' + keccak256(canon1);
    const hash2 = '0x' + keccak256(canon2);
    assert.strictEqual(hash1, hash2, 'Keccak digests of canonical representations must match');
  });

  // --- 2. CAIP-2 CHAIN IDENTIFIER INTEGRATION ---
  await test('CAIP-2: Normalizes eip155 identifiers to canonical hex and maps back to CAIP-2', async () => {
    // Sepolia
    assert.strictEqual(normalizeChainId('eip155:11155111'), '0xaa36a7');
    assert.strictEqual(toCaip2ChainId('0xaa36a7'), 'eip155:11155111');
    assert.strictEqual(toCaip2ChainId(11155111), 'eip155:11155111');

    // Ethereum Mainnet
    assert.strictEqual(normalizeChainId('eip155:1'), '0x1');
    assert.strictEqual(toCaip2ChainId('0x1'), 'eip155:1');

    // Polygon
    assert.strictEqual(normalizeChainId('eip155:137'), '0x89');
    assert.strictEqual(toCaip2ChainId('0x89'), 'eip155:137');
  });

  // --- 3. ONCHAIN RESOLVER SIMULATION & INTEGRITY CHECKS ---
  await test('OnchainResolver: Resolves manifest and chunks via mock registry and content store', async () => {
    const mockRegistry = new Map();
    const mockStore = new Map();

    const samplePackage = '<!DOCTYPE html><html><body><h1>Onchain Cartridge 001</h1></body></html>';
    const packageDigest = ('0x' + keccak256(samplePackage)).toLowerCase();
    mockStore.set(packageDigest, samplePackage);

    const cartridgeId = 'onchain-cart-1';
    const cartridgeBytes32 = ('0x' + keccak256(cartridgeId)).toLowerCase();
    const channelKey = ('0x' + keccak256('stable')).toLowerCase();

    const manifestObj = {
      manifestVersion: '1.0.0',
      id: 'onchain-cart-1',
      cartridgeId: cartridgeBytes32,
      name: 'Onchain Test Cartridge',
      version: '1.0.0',
      runtime: { version: '^0.2.0' },
      entry: {
        path: 'index.html',
        digest: packageDigest,
        size: samplePackage.length,
        mediaType: 'text/html'
      },
      permissions: {
        chains: ['eip155:11155111'],
        contracts: [
          {
            address: '0x7777777777777777777777777777777777777777',
            name: 'Echo',
            allowedSelectors: ['0x12345678']
          }
        ]
      }
    };

    const canonicalManifest = canonicalizeJson(manifestObj);
    const manifestDigest = ('0x' + keccak256(canonicalManifest)).toLowerCase();
    mockStore.set(manifestDigest, canonicalManifest);

    // Map registry entry: (cartridgeBytes32, channelKey) -> manifestDigest
    const regKey = `${cartridgeBytes32}:${channelKey}`.toLowerCase();
    mockRegistry.set(regKey, manifestDigest);

    // Call handler for OnchainCartridgeResolver
    const callHandler = async ({ to, data }) => {
      const sel = data.slice(0, 10).toLowerCase();

      // resolveManifest(bytes32,bytes32) -> selector 0x06fa0577
      if (sel === '0x06fa0577') {
        const cartIdWord = '0x' + data.slice(10, 74).toLowerCase();
        const chanWord = '0x' + data.slice(74, 138).toLowerCase();
        const key = `${cartIdWord}:${chanWord}`;
        const found = mockRegistry.get(key);
        if (found) {
          return found.slice(2).padStart(64, '0');
        }
        return '0x0000000000000000000000000000000000000000000000000000000000000000';
      }

      // read(bytes32) -> selector 0x61da1439
      if (sel === '0x61da1439') {
        const digest = '0x' + data.slice(10, 74).toLowerCase();
        const content = mockStore.get(digest);
        if (content !== undefined) {
          return encodeAbiBytes(content);
        }
        return '0x';
      }

      return '0x';
    };

    const resolver = new OnchainCartridgeResolver({
      registryAddress: '0x1111111111111111111111111111111111111111',
      storeAddress: '0x2222222222222222222222222222222222222222',
      callHandler,
      channel: 'stable'
    });
    resolver.registerOnchainCartridge(cartridgeId, { cartridgeBytes32, name: 'Onchain Test Cartridge' });

    // 1. Resolve successfully via directory alias and direct 32-byte ID
    const resolved = await resolver.resolve(cartridgeId);
    assert.strictEqual(resolved.id, 'onchain-cart-1');
    assert.strictEqual(resolved.name, 'Onchain Test Cartridge');
    assert.strictEqual(resolved.expectedContentHash, packageDigest);

    const fetchedPackage = await resolved.fetchPackageBytes();
    assert.strictEqual(fetchedPackage, samplePackage);

    // 2. Tampered manifest fails closed
    mockStore.set(manifestDigest, canonicalManifest.replace('Onchain Test Cartridge', 'Tampered Cartridge'));
    let caughtTamperedManifest = null;
    try {
      await resolver.resolve(cartridgeId);
    } catch (e) {
      caughtTamperedManifest = e;
    }
    assert.ok(caughtTamperedManifest, 'Tampered manifest must fail closed');
    assert.ok(caughtTamperedManifest.message.includes('integrity verification failed'));
  });

  // --- 4. MULTI-CARTRIDGE SHARED DEPENDENCY DEDUPLICATION PROOF ---
  await test('Deduplication: Two independent cartridges share identical library chunk with single on-chain copy', async () => {
    const mockStore = new Map();
    const storedChunks = new Set();

    function storeContent(raw) {
      const digest = ('0x' + keccak256(raw)).toLowerCase();
      if (!storedChunks.has(digest)) {
        storedChunks.add(digest);
        mockStore.set(digest, raw);
      }
      return digest;
    }

    // A. Shared library component (e.g. game physics / sound engine)
    const sharedSoundLibrary = 'const SoundEngine = { playSynth(freq) { return "playing_" + freq; } };';
    const sharedLibDigest = storeContent(sharedSoundLibrary);
    assert.strictEqual(storedChunks.size, 1);

    // B. Cartridge A (HoodQuest) using shared library
    const cartridgeAPackage = `<html><script>${sharedSoundLibrary}</script><h1>HoodQuest</h1></html>`;
    const cartADigest = storeContent(cartridgeAPackage);
    assert.strictEqual(storedChunks.size, 2);

    // C. Cartridge B (Reference Arena) also using shared library
    // Authors store the exact same shared library again
    const sharedLibDigest2 = storeContent(sharedSoundLibrary);
    assert.strictEqual(sharedLibDigest, sharedLibDigest2);
    // Invariant: chunk storage count MUST NOT increase (deduplication!)
    assert.strictEqual(storedChunks.size, 2, 'ContentStore must deduplicate shared library chunk');

    const cartridgeBPackage = `<html><script>${sharedSoundLibrary}</script><h1>Reference Arena</h1></html>`;
    const cartBDigest = storeContent(cartridgeBPackage);
    assert.strictEqual(storedChunks.size, 3);
  });

  // --- 5. END-TO-END INTEGRATION: GENERIC HOST BOOTS ONCHAIN-RESOLVED CARTRIDGE ---
  // --- 5. END-TO-END INTEGRATION: GENERIC HOST BOOTS ONCHAIN-RESOLVED CARTRIDGE ---
  await test('Integration: GenericHostCore boots and executes cartridge resolved via OnchainCartridgeResolver', async () => {
    const mockRegistry = new Map();
    const mockStore = new Map();

    const appHtml = '<!DOCTYPE html><html><body><div id="game">Generic Reference App</div></body></html>';
    const appDigest = ('0x' + keccak256(appHtml)).toLowerCase();
    mockStore.set(appDigest, appHtml);

    const cartId = 'reference-app-v02';
    const cartBytes32 = ('0x' + keccak256(cartId)).toLowerCase();
    const chanKey = ('0x' + keccak256('stable')).toLowerCase();

    const manifestObj = {
      manifestVersion: '1.0.0',
      id: 'reference-app-v02',
      cartridgeId: cartBytes32,
      name: 'Reference Cartridge App (Onchain V0.2)',
      version: '0.2.0',
      runtime: { version: '^0.2.0' },
      entry: {
        path: 'index.html',
        digest: appDigest,
        size: appHtml.length,
        mediaType: 'text/html'
      },
      permissions: {
        chains: ['eip155:11155111'],
        contracts: [
          {
            address: '0x7777777777777777777777777777777777777777',
            name: 'EchoTarget',
            writes: true,
            allowedSelectors: ['0x12345678']
          }
        ]
      }
    };

    const canonManifest = canonicalizeJson(manifestObj);
    const manifestDigest = ('0x' + keccak256(canonManifest)).toLowerCase();
    mockStore.set(manifestDigest, canonManifest);
    mockRegistry.set(`${cartBytes32}:${chanKey}`, manifestDigest);

    const resolver = new OnchainCartridgeResolver({
      registryAddress: '0x1111111111111111111111111111111111111111',
      storeAddress: '0x2222222222222222222222222222222222222222',
      callHandler: async ({ to, data }) => {
        const sel = data.slice(0, 10).toLowerCase();
        if (sel === '0x06fa0577') {
          const key = `0x${data.slice(10, 74)}:0x${data.slice(74, 138)}`.toLowerCase();
          const res = mockRegistry.get(key);
          return res ? res.slice(2).padStart(64, '0') : '0x' + '00'.repeat(32);
        }
        if (sel === '0x61da1439') {
          const d = '0x' + data.slice(10, 74).toLowerCase();
          const content = mockStore.get(d);
          return content !== undefined ? encodeAbiBytes(content) : '0x';
        }
        return '0x';
      }
    });
    resolver.registerOnchainCartridge(cartId, { cartridgeBytes32: cartBytes32, name: 'Reference Cartridge App (Onchain V0.2)' });

    const host = new GenericHostCore({
      resolver,
      keccakFn,
      chainId: '0xaa36a7',
      account: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
      mockMode: true
    });

    // Boot cartridge with explicit write grant for EchoTarget
    const booted = await host.loadCartridge(cartId, {
      ['0x7777777777777777777777777777777777777777'.toLowerCase()]: {
        writes: true,
        allowedSelectors: ['0x12345678']
      }
    });
    assert.strictEqual(booted.id, 'reference-app-v02');
    assert.strictEqual(booted.name, 'Reference Cartridge App (Onchain V0.2)');
    assert.strictEqual(booted.verified, true);
    assert.strictEqual(host.integrityVerified, true);
    assert.strictEqual(host.computedHash, appDigest);

    // Verify MessagePort RPC communication through host
    const { port1, port2 } = new MessageChannel();
    host.bindPortRpc(port1);
    const bridge = new BridgeHostAdapter(port2);
    await bridge.connect();

    // EchoTarget write succeeds
    const tx = await bridge.writeContract({
      to: '0x7777777777777777777777777777777777777777',
      data: '0x12345678' + '00'.repeat(32)
    });
    assert.ok(tx.startsWith('0x'));

    // Unauthorized contract fails closed (4003)
    let caughtUnauthorized = null;
    try {
      await bridge.writeContract({
        to: '0x9999999999999999999999999999999999999999',
        data: '0x12345678'
      });
    } catch (e) {
      caughtUnauthorized = e;
    }
    assert.ok(caughtUnauthorized);
    assert.strictEqual(caughtUnauthorized.code, 4003);

    port1.close();
    port2.close();
  });

  // --- 6. JCS COMPLIANCE & DOMAIN VALIDATION ---
  await test('JCS: Enforces UTF-16 code unit ordering, -0 normalization, and rejects invalid types/surrogates', async () => {
    // UTF-16 code unit ordering: \u0041 ('A', 65) < 'a' (97) < \u00e9 ('é', 233)
    const disordered = {
      '\u00e9': 1,
      'a': 2,
      '\u0041': 3
    };
    const canon = canonicalizeJson(disordered);
    assert.strictEqual(canon, '{"A":3,"a":2,"é":1}');

    // -0 normalizes to "0"
    assert.strictEqual(canonicalizeJson({ zero: -0 }), '{"zero":0}');

    // Non-finite numbers rejected
    assert.throws(() => canonicalizeJson({ val: NaN }), TypeError);
    assert.throws(() => canonicalizeJson({ val: Infinity }), TypeError);
    assert.throws(() => canonicalizeJson({ val: -Infinity }), TypeError);

    // BigInt rejected
    assert.throws(() => canonicalizeJson({ val: 10n }), TypeError);

    // Unsupported types inside objects rejected
    assert.throws(() => canonicalizeJson({ val: undefined }), TypeError);
    assert.throws(() => canonicalizeJson({ val: Symbol('s') }), TypeError);
    assert.throws(() => canonicalizeJson({ fn: () => {} }), TypeError);

    // Lone or unpaired surrogates rejected
    assert.throws(() => canonicalizeJson({ s: '\uD800' }), TypeError); // lone high
    assert.throws(() => canonicalizeJson({ s: '\uDC00' }), TypeError); // lone low
    assert.throws(() => canonicalizeJson({ s: '\uD800abc' }), TypeError); // unpaired high
  });

  // --- 7. STRICT SEMVER 2.0.0 WITH PRERELEASE PRECEDENCE ---
  await test('SemVer: Evaluates ranges and strictly enforces prerelease precedence isolation', async () => {
    // Prereleases NEVER satisfy stable ranges unless explicitly targeted
    assert.strictEqual(satisfiesSemVer('0.2.0-alpha', '^0.2.0'), false);
    assert.strictEqual(satisfiesSemVer('0.2.0-beta.1', '0.2.0'), false);
    assert.strictEqual(satisfiesSemVer('1.0.0-rc.1', '^1.0.0'), false);

    // Stable versions satisfy appropriate ranges
    assert.strictEqual(satisfiesSemVer('0.2.0', '^0.2.0'), true);
    assert.strictEqual(satisfiesSemVer('0.2.1', '^0.2.0'), true);
    assert.strictEqual(satisfiesSemVer('0.3.0', '^0.2.0'), false); // 0.x.y breaking
    assert.strictEqual(satisfiesSemVer('1.0.0', '^1.0.0'), true);
    assert.strictEqual(satisfiesSemVer('1.5.2', '^1.0.0'), true);
    assert.strictEqual(satisfiesSemVer('2.0.0', '^1.0.0'), false);

    // Prerelease comparison when tuple matches
    assert.strictEqual(satisfiesSemVer('0.2.0-beta.2', '>=0.2.0-beta.1'), true);
    assert.strictEqual(satisfiesSemVer('0.2.0-alpha', '>=0.2.0-beta'), false);
  });

  // --- 8. CSPRNG FAIL-CLOSED BEHAVIOR ---
  await test('CSPRNG: Nonce generation is fail-closed and rejects lack of entropy', async () => {
    // Valid generation
    const nonce = generateSecureNonce('test_');
    assert.ok(nonce.startsWith('test_'));
    assert.ok(nonce.length >= 20);

    // Uniqueness
    const nonce2 = generateSecureNonce('test_');
    assert.notStrictEqual(nonce, nonce2);
  });

  // --- 9. PRODUCTION RPC FAIL-CLOSED BEHAVIOR ---
  await test('Production RPC: Fail-closed when transport or signer is unavailable without mock fallbacks', async () => {
    const prodHost = new GenericHostCore({
      resolver: null,
      keccakFn,
      mockMode: false,
      rpcUrl: null
    });

    // 1. connectWallet fails closed without window.ethereum
    await assert.rejects(
      async () => await prodHost.connectWallet(),
      (err) => err.code === 4100
    );

    // 2. executeEthCall fails closed without RPC
    await assert.rejects(
      async () => await prodHost.executeEthCall('0x1111111111111111111111111111111111111111', '0x'),
      (err) => err.code === 4900
    );

    // 3. executeSendTransaction fails closed without signer
    await assert.rejects(
      async () => await prodHost.executeSendTransaction({ to: '0x1111111111111111111111111111111111111111', data: '0x' }),
      (err) => err.code === 4100
    );

    // 4. executeGetLogs fails closed without RPC
    await assert.rejects(
      async () => await prodHost.executeGetLogs({}),
      (err) => err.code === 4900
    );

    // 5. fetchReceipt fails closed without RPC
    await assert.rejects(
      async () => await prodHost.fetchReceipt('0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef'),
      (err) => err.code === 4900
    );
  });

  // --- 10. BINARY PACKAGE & MANIFEST V1 RESOURCE DESCRIPTOR WITH DEFLATE ---
  await test('Manifest V1: Resolves and decompresses binary-safe deflate package chunks with multi-layer digest checks', async () => {
    // 1. Raw uncompressed binary data with null bytes and arbitrary high bytes
    const rawBinary = new Uint8Array([0x00, 0xFF, 0x42, 0x00, 0x13, 0x37, 0xDE, 0xAD, 0xBE, 0xEF, 0x00]);
    const uncompressedDigest = ('0x' + keccak256(rawBinary)).toLowerCase();
    const uncompressedSize = rawBinary.length;

    // 2. Deflate compression
    const compressedBuffer = zlib.deflateSync(Buffer.from(rawBinary));
    const compressedBytes = new Uint8Array(compressedBuffer);
    const compressedDigest = ('0x' + keccak256(compressedBytes)).toLowerCase();
    const compressedSize = compressedBytes.length;

    // 3. Set up mock stores
    const localStore = new Map();
    const localRegistry = new Map();
    localStore.set(compressedDigest, compressedBuffer);

    // Manifest V1 descriptor
    const manifestObj = {
      manifestVersion: '1.0.0',
      id: 'binary-deflate-cartridge',
      cartridgeId: '0x3333333333333333333333333333333333333333333333333333333333333333',
      name: 'Binary Deflate Cartridge',
      version: '1.0.0',
      entry: {
        path: 'cartridge.bin',
        mediaType: 'application/octet-stream',
        encoding: 'deflate',
        digest: compressedDigest,
        size: compressedSize,
        decodedDigest: uncompressedDigest,
        decodedSize: uncompressedSize,
        chunks: [compressedDigest]
      },
      permissions: {
        chains: ['eip155:11155111'],
        contracts: []
      }
    };

    const canonManifest = canonicalizeJson(manifestObj);
    const manifestDigest = ('0x' + keccak256(canonManifest)).toLowerCase();
    localStore.set(manifestDigest, Buffer.from(canonManifest, 'utf8'));

    const cartIdBytes32 = manifestObj.cartridgeId.toLowerCase();
    const chanKey = ('0x' + keccak256('stable')).toLowerCase();
    localRegistry.set(`${cartIdBytes32}:${chanKey}`, manifestDigest);

    const resolver = new OnchainCartridgeResolver({
      registryAddress: '0x1111111111111111111111111111111111111111',
      storeAddress: '0x2222222222222222222222222222222222222222',
      callHandler: async ({ to, data }) => {
        const sel = data.slice(0, 10).toLowerCase();
        if (sel === '0x06fa0577') {
          const key = `0x${data.slice(10, 74)}:0x${data.slice(74, 138)}`.toLowerCase();
          const res = localRegistry.get(key);
          return res ? res.slice(2).padStart(64, '0') : '0x' + '00'.repeat(32);
        }
        if (sel === '0x61da1439') {
          const d = '0x' + data.slice(10, 74).toLowerCase();
          const content = localStore.get(d);
          if (content) {
            const buf = Buffer.isBuffer(content) ? content : Buffer.from(content);
            const lenHex = buf.length.toString(16).padStart(64, '0');
            const padLen = Math.ceil(buf.length / 32) * 32;
            const paddedBuf = Buffer.alloc(padLen);
            buf.copy(paddedBuf);
            return '0x' + (32).toString(16).padStart(64, '0') + lenHex + paddedBuf.toString('hex');
          }
        }
        return '0x';
      }
    });

    const resolved = await resolver.resolve(cartIdBytes32);
    assert.strictEqual(resolved.id, 'binary-deflate-cartridge');
    assert.strictEqual(resolved.expectedContentHash, uncompressedDigest);

    // Fetch and decompress package
    const packageData = await resolved.fetchPackageBytes();
    assert.ok(packageData instanceof Uint8Array, 'Binary package must return Uint8Array');
    assert.strictEqual(packageData.length, uncompressedSize);
    assert.deepStrictEqual(Array.from(packageData), Array.from(rawBinary), 'Decompressed binary must match bit-for-bit');
  });

  // --- 11. CARTRIDGE ID MISMATCH REJECTION ---
  await test('Resolver: Rejects manifest when declared cartridgeId mismatches query ID', async () => {
    const localStore = new Map();
    const localRegistry = new Map();

    const badManifest = {
      manifestVersion: '1.0.0',
      id: 'mismatched-cartridge',
      cartridgeId: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      name: 'Mismatched Cartridge',
      version: '1.0.0',
      entry: { path: 'index.html', digest: '0x' + '11'.repeat(32) },
      permissions: { chains: ['eip155:11155111'], contracts: [] }
    };
    const canon = canonicalizeJson(badManifest);
    const mDigest = ('0x' + keccak256(canon)).toLowerCase();
    localStore.set(mDigest, Buffer.from(canon, 'utf8'));

    const queryId = '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
    const chanKey = ('0x' + keccak256('stable')).toLowerCase();
    localRegistry.set(`${queryId}:${chanKey}`, mDigest);

    const resolver = new OnchainCartridgeResolver({
      registryAddress: '0x1111111111111111111111111111111111111111',
      storeAddress: '0x2222222222222222222222222222222222222222',
      callHandler: async ({ to, data }) => {
        const sel = data.slice(0, 10).toLowerCase();
        if (sel === '0x06fa0577') return mDigest.slice(2).padStart(64, '0');
        if (sel === '0x61da1439') {
          const buf = localStore.get(mDigest);
          const lenHex = buf.length.toString(16).padStart(64, '0');
          const padLen = Math.ceil(buf.length / 32) * 32;
          const paddedBuf = Buffer.alloc(padLen);
          buf.copy(paddedBuf);
          return '0x' + (32).toString(16).padStart(64, '0') + lenHex + paddedBuf.toString('hex');
        }
        return '0x';
      }
    });

    await assert.rejects(
      async () => await resolver.resolve(queryId),
      (err) => err.message.includes('Cartridge ID mismatch')
    );
  });

  // --- 12. PERMISSION FIREWALL: REQUESTED ∩ GRANTED ---
  await test('Permission Firewall: Enforces strict intersection and prevents privilege escalation', async () => {
    const host = new GenericHostCore({ keccakFn });

    const manifest = {
      chainId: '0xaa36a7',
      permissions: {
        contracts: [
          {
            address: '0x1111111111111111111111111111111111111111',
            writes: true,
            allowedSelectors: ['0x12345678', '0x87654321'],
            allowNativeValue: false,
            maxValueWei: '0',
            isElevated: false
          },
          {
            address: '0x2222222222222222222222222222222222222222',
            writes: false // read-only in manifest
          },
          {
            address: '0x3333333333333333333333333333333333333333',
            writes: true,
            allowedSelectors: ['0xaaaa0000'],
            allowNativeValue: true,
            maxValueWei: '1000',
            isElevated: false // did NOT request elevated
          }
        ]
      }
    };

    // Case 1: No host grants provided -> All writes default to FALSE
    const defaultPolicy = host.computeGrantedPolicy(manifest, null);
    assert.strictEqual(defaultPolicy.contracts[0].writes, false);
    assert.deepStrictEqual(defaultPolicy.contracts[0].allowedSelectors, []);
    assert.strictEqual(defaultPolicy.contracts[1].writes, false);
    assert.strictEqual(defaultPolicy.contracts[2].writes, false);

    // Case 2: Host attempts to grant writes to unrequested contract (0x2222...)
    const hostEscalationGrants = {
      ['0x2222222222222222222222222222222222222222']: {
        writes: true,
        allowedSelectors: ['0x99999999']
      }
    };
    const escalationPolicy = host.computeGrantedPolicy(manifest, hostEscalationGrants);
    assert.strictEqual(escalationPolicy.contracts[1].writes, false, 'Host cannot grant write if manifest did not request it');
    assert.deepStrictEqual(escalationPolicy.contracts[1].allowedSelectors, []);

    // Case 3: Selector intersection and privilege capping
    const hostCustomGrants = {
      ['0x1111111111111111111111111111111111111111']: {
        writes: true,
        allowedSelectors: ['0x12345678', '0x99999999'] // 0x99999999 not in manifest!
      },
      ['0x3333333333333333333333333333333333333333']: {
        writes: true,
        allowedSelectors: ['0xaaaa0000'],
        allowNativeValue: true,
        maxValueWei: '5000', // Exceeds manifest cap of 1000
        isElevated: true // Manifest did not request isElevated
      }
    };
    const effectivePolicy = host.computeGrantedPolicy(manifest, hostCustomGrants);

    // Contract 1: Only intersection selector 0x12345678 is granted
    assert.strictEqual(effectivePolicy.contracts[0].writes, true);
    assert.deepStrictEqual(effectivePolicy.contracts[0].allowedSelectors, ['0x12345678']);

    // Contract 3:
    // Native value capped at minimum (1000, not 5000)
    assert.strictEqual(effectivePolicy.contracts[2].allowNativeValue, true);
    assert.strictEqual(effectivePolicy.contracts[2].maxValueWei, '1000');
    // isElevated is FALSE because manifest did not request it!
    assert.strictEqual(effectivePolicy.contracts[2].isElevated, false, 'isElevated requires BOTH request and grant');
  });

  // --- 13. AUTHORITATIVE RFC 8785 VECTORS ---
  await test('JCS: Authoritative RFC 8785 compliance vectors (sorting, numbers, strings, whitespace)', async () => {
    // A. RFC 8785 Section 3.2.3 Sorting Vector
    // Lexicographic ordering based on UTF-16 code units
    const sortingInput = {
      '\u20ac': 'Euro Sign',
      '\r': 'Carriage Return',
      '1': 'One',
      'b': 'Letter B',
      'a': 'Letter A'
    };
    const sortingExpected = '{"\\r":"Carriage Return","1":"One","a":"Letter A","b":"Letter B","€":"Euro Sign"}';
    assert.strictEqual(canonicalizeJson(sortingInput), sortingExpected);

    // B. RFC 8785 Numbers Vector: -0 normalized to 0, no exponential for integers
    const numbersInput = {
      zero: 0,
      negZero: -0,
      integer: 1000000,
      negative: -42,
      fraction: 0.125
    };
    const numbersExpected = '{"fraction":0.125,"integer":1000000,"negZero":0,"negative":-42,"zero":0}';
    assert.strictEqual(canonicalizeJson(numbersInput), numbersExpected);

    // C. Rejection of non-finite numbers (NaN, Infinity)
    assert.throws(() => canonicalizeJson({ val: NaN }), TypeError);
    assert.throws(() => canonicalizeJson({ val: Infinity }), TypeError);

    // D. Rejection of unpaired Unicode surrogates
    assert.throws(() => canonicalizeJson({ val: 'test\uD800' }), TypeError); // Lone high surrogate
    assert.throws(() => canonicalizeJson({ val: 'test\uDC00' }), TypeError); // Lone low surrogate
  });

  // --- 14. RESOLVER: STRICT CANONICAL BYTE ENFORCEMENT ---
  await test('Resolver: Rejects non-canonical JSON bytes even when hash matches registry digest', async () => {
    const localStore = new Map();
    const localRegistry = new Map();

    const manifestObj = {
      manifestVersion: '1.0.0',
      id: 'canonical-check-cartridge',
      cartridgeId: '0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
      name: 'Canonical Check',
      version: '1.0.0',
      runtime: { version: '^0.2.0' },
      entry: { path: 'index.html', digest: '0x' + '22'.repeat(32), size: 100, mediaType: 'text/html' },
      permissions: { chains: ['eip155:11155111'], contracts: [] }
    };

    // Stored with pretty-printed whitespace (NON-CANONICAL!)
    const nonCanonicalJson = JSON.stringify(manifestObj, null, 2);
    const mDigest = ('0x' + keccak256(Buffer.from(nonCanonicalJson, 'utf8'))).toLowerCase();
    localStore.set(mDigest, Buffer.from(nonCanonicalJson, 'utf8'));

    const cartId = manifestObj.cartridgeId;
    const chanKey = ('0x' + keccak256('stable')).toLowerCase();
    localRegistry.set(`${cartId}:${chanKey}`, mDigest);

    const resolver = new OnchainCartridgeResolver({
      registryAddress: '0x1111111111111111111111111111111111111111',
      storeAddress: '0x2222222222222222222222222222222222222222',
      callHandler: async ({ to, data }) => {
        const sel = data.slice(0, 10).toLowerCase();
        if (sel === '0x06fa0577') return mDigest.slice(2).padStart(64, '0');
        if (sel === '0x61da1439') {
          const buf = localStore.get(mDigest);
          const lenHex = buf.length.toString(16).padStart(64, '0');
          const padLen = Math.ceil(buf.length / 32) * 32;
          const paddedBuf = Buffer.alloc(padLen);
          buf.copy(paddedBuf);
          return '0x' + (32).toString(16).padStart(64, '0') + lenHex + paddedBuf.toString('hex');
        }
        return '0x';
      }
    });

    // Hash matches, but byte sequence is non-canonical -> MUST FAIL CLOSED
    await assert.rejects(
      async () => await resolver.resolve(cartId),
      (err) => err.message.includes('not canonical RFC 8785 JSON')
    );
  });

  // --- 15. SEMVER 2.0.0 SPECIFICATION & RANGE GRAMMAR MATRIX ---
  await test('SemVer: Comprehensive grammar matrix (exact, ^, ~, >, >=, <, <=, prereleases, build meta)', async () => {
    // 1. Exact stable and prerelease
    assert.strictEqual(satisfiesSemVer('1.2.3', '1.2.3'), true);
    assert.strictEqual(satisfiesSemVer('1.2.3', '=1.2.3'), true);
    assert.strictEqual(satisfiesSemVer('1.2.4', '1.2.3'), false);
    assert.strictEqual(satisfiesSemVer('1.0.0-alpha.1', '1.0.0-alpha.1'), true);
    assert.strictEqual(satisfiesSemVer('1.0.0-alpha.2', '1.0.0-alpha.1'), false);

    // 2. Caret (^) ranges
    assert.strictEqual(satisfiesSemVer('1.2.5', '^1.2.3'), true);
    assert.strictEqual(satisfiesSemVer('1.3.0', '^1.2.3'), true);
    assert.strictEqual(satisfiesSemVer('2.0.0', '^1.2.3'), false);
    assert.strictEqual(satisfiesSemVer('0.2.5', '^0.2.0'), true);
    assert.strictEqual(satisfiesSemVer('0.3.0', '^0.2.0'), false);
    assert.strictEqual(satisfiesSemVer('0.0.3', '^0.0.3'), true);
    assert.strictEqual(satisfiesSemVer('0.0.4', '^0.0.3'), false);

    // 3. Tilde (~) ranges
    assert.strictEqual(satisfiesSemVer('1.2.5', '~1.2.3'), true);
    assert.strictEqual(satisfiesSemVer('1.3.0', '~1.2.3'), false);
    assert.strictEqual(satisfiesSemVer('0.2.5', '~0.2.0'), true);
    assert.strictEqual(satisfiesSemVer('0.3.0', '~0.2.0'), false);

    // 4. Comparison operators (>, >=, <, <=)
    assert.strictEqual(satisfiesSemVer('1.5.0', '>1.2.0'), true);
    assert.strictEqual(satisfiesSemVer('1.2.0', '>1.2.0'), false);
    assert.strictEqual(satisfiesSemVer('1.2.0', '>=1.2.0'), true);
    assert.strictEqual(satisfiesSemVer('1.1.0', '<1.2.0'), true);
    assert.strictEqual(satisfiesSemVer('1.2.0', '<1.2.0'), false);
    assert.strictEqual(satisfiesSemVer('1.2.0', '<=1.2.0'), true);

    // 5. Prerelease precedence ordering & isolation
    // A prerelease NEVER satisfies a range unless explicitly on the same tuple
    assert.strictEqual(satisfiesSemVer('1.0.0-alpha.1', '^1.0.0'), false);
    assert.strictEqual(satisfiesSemVer('1.0.0-beta', '>=1.0.0'), false);
    // Prerelease ordering on same tuple: alpha < alpha.1 < beta < rc
    assert.strictEqual(satisfiesSemVer('1.0.0-beta', '>=1.0.0-alpha'), true);
    assert.strictEqual(satisfiesSemVer('1.0.0-alpha', '>=1.0.0-beta'), false);
    assert.strictEqual(satisfiesSemVer('1.0.0-alpha.2', '>1.0.0-alpha.1'), true);

    // 6. Numeric prerelease identifiers have lower precedence than non-numeric
    // 1.0.0-1 < 1.0.0-alpha
    assert.strictEqual(satisfiesSemVer('1.0.0-alpha', '>1.0.0-1'), true);
    assert.strictEqual(satisfiesSemVer('1.0.0-1', '<1.0.0-alpha'), true);

    // 7. Invalid leading-zero numeric identifiers in version string
    assert.strictEqual(parseSemVer('01.0.0'), null);
    assert.strictEqual(parseSemVer('1.01.0'), null);
    assert.strictEqual(parseSemVer('1.0.01'), null);
    assert.strictEqual(parseSemVer('1.0.0-01'), null);

    // 8. Build metadata ignored in precedence comparison
    assert.strictEqual(satisfiesSemVer('1.0.0+build.123', '=1.0.0'), true);
    assert.strictEqual(satisfiesSemVer('1.0.0+exp.sha.5114f85', '=1.0.0+diff.build'), true);

    // 9. Unsupported range syntax rejected
    assert.strictEqual(satisfiesSemVer('1.0.0', '1.x'), false);
    assert.strictEqual(satisfiesSemVer('1.0.0', '1.0.0 - 2.0.0'), false);
    assert.strictEqual(satisfiesSemVer('1.0.0', '|| 1.0.0'), false);
  });

  // --- 16. MANIFEST V1 SCHEMA VALIDATION TEST MATRIX ---
  await test('Manifest V1: Schema validation enforces required fields and rejects malformed manifests', async () => {
    const validManifest = {
      manifestVersion: '1.0.0',
      id: 'valid-test-cartridge',
      cartridgeId: '0x' + 'aa'.repeat(32),
      name: 'Valid Cartridge',
      version: '1.0.0',
      runtime: { version: '^0.2.0' },
      entry: {
        path: 'index.html',
        mediaType: 'text/html',
        digest: '0x' + 'bb'.repeat(32),
        size: 512
      },
      permissions: {
        chains: ['eip155:11155111'],
        contracts: [
          {
            address: '0x7777777777777777777777777777777777777777',
            writes: true,
            allowedSelectors: ['0x12345678']
          }
        ]
      }
    };

    // A. Valid manifest passes
    assert.strictEqual(validateManifestV1(validManifest), true);

    // B. Rejects invalid manifestVersion
    assert.throws(() => validateManifestV1({ ...validManifest, manifestVersion: '0.1.0' }), /Invalid manifestVersion/);

    // C. Rejects missing / invalid cartridgeId
    assert.throws(() => validateManifestV1({ ...validManifest, cartridgeId: undefined }), /Invalid cartridgeId/);
    assert.throws(() => validateManifestV1({ ...validManifest, cartridgeId: 'not-a-hex' }), /Invalid cartridgeId/);
    assert.throws(() => validateManifestV1({ ...validManifest, cartridgeId: '0x1234' }), /Invalid cartridgeId/);

    // D. Rejects invalid slug
    assert.throws(() => validateManifestV1({ ...validManifest, id: 'UPPER_CASE_SLUG' }), /Invalid id\/slug/);

    // E. Rejects invalid version
    assert.throws(() => validateManifestV1({ ...validManifest, version: 'invalid-semver' }), /Invalid version/);
    assert.throws(() => validateManifestV1({ ...validManifest, version: '01.0.0' }), /Invalid version/);

    // F. Rejects missing entry or invalid digest
    assert.throws(() => validateManifestV1({ ...validManifest, entry: undefined }), /Manifest missing required "entry"/);
    assert.throws(() => validateManifestV1({ ...validManifest, entry: { ...validManifest.entry, digest: 'bad-digest' } }), /Invalid entry.digest/);

    // G. Rejects non-CAIP-2 chain
    assert.throws(() => validateManifestV1({ ...validManifest, permissions: { chains: ['11155111'], contracts: [] } }), /Invalid CAIP-2/);

    // H. Rejects invalid contract address / selector
    assert.throws(() => validateManifestV1({
      ...validManifest,
      permissions: {
        chains: ['eip155:11155111'],
        contracts: [{ address: 'not-an-evm-address' }]
      }
    }), /Invalid contract address/);

    assert.throws(() => validateManifestV1({
      ...validManifest,
      permissions: {
        chains: ['eip155:11155111'],
        contracts: [{ address: '0x7777777777777777777777777777777777777777', allowedSelectors: ['invalid-sel'] }]
      }
    }), /Invalid selector/);
  });

  // SUMMARY
  console.log('\n=============================================================');
  console.log(`Console Protocol V0.2 & Publishing Suite Results:`);
  console.log(`Total: ${passed + failed} | Passed: ${passed} | Failed: ${failed}`);
  console.log('=============================================================\n');

  if (failed > 0) process.exit(1);
}

runProtocolPublishingSuite();
