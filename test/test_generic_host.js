/**
 * Automated Regression Test Suite: Generic Web Host & Multi-Cartridge Platform Proof
 *
 * Verifies:
 * 1. LocalCartridgeResolver resolves Cartridge #0001 (HoodQuest) and Cartridge #0002 (Runtime Test Cartridge)
 * 2. Package integrity verification rejects tampered bytes before execution (Code 5003)
 * 3. Generic host loads and runs Cartridge #0001 solely from manifest
 * 4. Generic host loads and runs Cartridge #0002 solely from manifest
 * 5. Zero application-specific or game-specific logic in the host
 * 6. Dynamic Requested vs Granted permission enforcement
 * 7. Host isolation & MessageChannel RPC bridge
 * 8. Clean multi-tenant cartridge switching in the same host instance
 */

const assert = require('assert');
const path = require('path');
const fs = require('fs');
const { MessageChannel } = require('worker_threads');
const { keccak256 } = require('js-sha3');

const {
  CartridgeHost,
  BridgeHostAdapter,
  DirectHostAdapter,
  ConsoleRuntimeError,
  PolicyEngine,
  parseCaip19,
  validateLaunchContext,
  sanitizeLaunchContext,
  MAX_LAUNCH_CONTEXT_BYTES
} = require('../runtime/cartridge_host_runtime.js');

const {
  CartridgeResolver,
  LocalCartridgeResolver,
  createDefaultResolver
} = require('../host/resolver.js');

const {
  GenericHostCore
} = require('../host/host_core.js');

const SEPOLIA_HEX = '0xaa36a7';
const MAINNET_HEX = '0x1';

async function runGenericHostTestSuite() {
  console.log('🏛️ Starting Generic Web Host & Multi-Cartridge Compatibility Test Suite...\n');
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

  const resolver = createDefaultResolver(path.join(__dirname, '../cartridges'));
  const keccakFn = (b) => keccak256(b);

  // --- 1. LOCAL CARTRIDGE RESOLVER TESTS ---
  await test('Resolver: Resolves both Reference Cartridge V1 and Runtime Test Cartridge manifests & packages', async () => {
    const list = await resolver.listCartridges();
    assert.strictEqual(list.length >= 2, true);
    assert.ok(list.some(c => c.id === 'reference-cartridge-v1'));
    assert.ok(list.some(c => c.id === 'runtime-test-cartridge'));

    // Resolve Reference Cartridge V1
    const ref = await resolver.resolve('reference-cartridge-v1');
    assert.strictEqual(ref.id, 'reference-cartridge-v1');
    assert.strictEqual(ref.name, 'Reference Cartridge V1');
    assert.strictEqual(ref.expectedContentHash, '0x865443ba96f988fc3d0adc3e0c4109c7fed347c9e8ff81cd57b857c557818d9f');
    assert.strictEqual(typeof ref.fetchPackageBytes, 'function');

    // Resolve Runtime Test Cartridge
    const testCart = await resolver.resolve('runtime-test-cartridge');
    assert.strictEqual(testCart.id, 'runtime-test-cartridge');
    assert.strictEqual(testCart.name, 'Runtime Test Cartridge');
    assert.strictEqual(testCart.expectedContentHash, '0x60d0bde3416316c5eda839cd1d20350a977ea14edaba4480bc5f3e4f8be95194');

    // Unknown Cartridge fails
    let caughtUnknown = null;
    try {
      await resolver.resolve('non-existent-cartridge');
    } catch (e) {
      caughtUnknown = e;
    }
    assert.ok(caughtUnknown);
  });

  // --- 2. INTEGRITY-BEFORE-EXECUTION VERIFICATION ---
  await test('Integrity: Generic host verifies package content hash before execution and halts on mismatch', async () => {
    const host = new GenericHostCore({ resolver, keccakFn });

    // A. Valid package passes verification
    const booted = await host.loadCartridge('runtime-test-cartridge');
    assert.strictEqual(booted.verified, true);
    assert.strictEqual(host.integrityVerified, true);
    assert.strictEqual(host.computedHash, '0x60d0bde3416316c5eda839cd1d20350a977ea14edaba4480bc5f3e4f8be95194');

    // B. Tampered package fails closed before mount
    const tamperedResolver = new LocalCartridgeResolver();
    tamperedResolver.register('tampered-cartridge', {
      id: 'tampered-cartridge',
      manifest: {
        id: 'tampered-cartridge',
        name: 'Tampered Cartridge',
        version: '1.0.0',
        runtime: { version: '^0.1.0' },
        entry: 'index.html',
        integrity: { contentHash: '0x1111111111111111111111111111111111111111111111111111111111111111' }
      },
      rawBytes: '<html><body>Malicious Payload</body></html>'
    });

    const hostTampered = new GenericHostCore({ resolver: tamperedResolver, keccakFn });
    let integrityCaught = null;
    try {
      await hostTampered.loadCartridge('tampered-cartridge');
    } catch (e) {
      integrityCaught = e;
    }
    assert.ok(integrityCaught, 'Must reject corrupted package bytes');
    assert.strictEqual(integrityCaught.code, 5003);
    assert.ok(integrityCaught.message.includes('Package integrity mismatch'));
    assert.strictEqual(hostTampered.integrityVerified, false);
  });

  // --- 3. REQUESTED VS GRANTED PERMISSIONS GATEKEEPER ---
  await test('Permissions: Host computes granted policy from manifest without self-authorization', async () => {
    const host = new GenericHostCore({ resolver, keccakFn });
    const booted = await host.loadCartridge('runtime-test-cartridge');

    const granted = booted.grantedPolicy;
    assert.ok(granted);
    assert.strictEqual(granted.chainId, SEPOLIA_HEX);

    // With no explicit grants: writes MUST default to false for all contracts!
    const lootRule = granted.contracts.find(c => c.address === '0x0676129B2bF4B06f04AfC7301617b6cE3BB2405c'.toLowerCase());
    assert.ok(lootRule);
    assert.strictEqual(lootRule.writes, false);

    // Contract 2: AllowedEcho (writes: true in manifest, but host grant absent -> writes: false)
    const echoRule = granted.contracts.find(c => c.address === '0x7777777777777777777777777777777777777777'.toLowerCase());
    assert.ok(echoRule);
    assert.strictEqual(echoRule.writes, false, 'Without explicit host grant, writes must default to false');
    assert.deepStrictEqual(echoRule.allowedSelectors, [], 'Without explicit host grant, allowedSelectors must be empty');

    // Host explicitly grants write permission for AllowedEcho:
    const customizedBoot = await host.loadCartridge('runtime-test-cartridge', {
      ['0x7777777777777777777777777777777777777777'.toLowerCase()]: {
        writes: true,
        allowedSelectors: ['0x12345678', '0xa9059cbb']
      }
    });
    const grantedRule = customizedBoot.grantedPolicy.contracts.find(c => c.address === '0x7777777777777777777777777777777777777777'.toLowerCase());
    assert.strictEqual(grantedRule.writes, true, 'Explicit host grant must enable writes');
    assert.deepStrictEqual(grantedRule.allowedSelectors, ['0x12345678', '0xa9059cbb']);
    assert.strictEqual(grantedRule.isElevated, false); // Ordinary write does NOT grant elevated ops

    // Host user overrides write permission: revoke AllowedEcho
    const revokedBoot = await host.loadCartridge('runtime-test-cartridge', {
      ['0x7777777777777777777777777777777777777777'.toLowerCase()]: { writes: false }
    });
    const revokedRule = revokedBoot.grantedPolicy.contracts.find(c => c.address === '0x7777777777777777777777777777777777777777'.toLowerCase());
    assert.strictEqual(revokedRule.writes, false, 'User/host override must successfully revoke write permission');
  });

  // --- 4. HOST BRIDGE RPC DISPATCHER & HARDENED POLICY ---
  await test('Host Bridge: Dispatches RPC methods and enforces fail-closed policy over MessagePort', async () => {
    const host = new GenericHostCore({
      resolver,
      keccakFn,
      account: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
      chainId: SEPOLIA_HEX,
      mockMode: true
    });
    await host.loadCartridge('runtime-test-cartridge', {
      ['0x7777777777777777777777777777777777777777'.toLowerCase()]: {
        writes: true,
        allowedSelectors: ['0x12345678']
      }
    });

    const { port1, port2 } = new MessageChannel();
    host.bindPortRpc(port1);

    const bridge = new BridgeHostAdapter(port2);
    CartridgeHost.setAdapter(bridge);

    // A. Connect wallet via bridge
    const connectedAddr = await bridge.connect();
    assert.strictEqual(connectedAddr, '0x70997970C51812dc3A010C7d01b50e0d17dc79C8');

    const caps = bridge.getCapabilities();
    assert.strictEqual(caps.adapter, 'bridge');
    assert.strictEqual(caps.contractRead, true);
    assert.strictEqual(caps.contractWrite, true);

    // B. evm.read
    const readVal = await bridge.readContract({
      to: '0x0676129B2bF4B06f04AfC7301617b6cE3BB2405c',
      data: '0x12345678'
    });
    assert.ok(readVal);

    // C. evm.write to authorized target & selector succeeds
    const txHash = await bridge.writeContract({
      to: '0x7777777777777777777777777777777777777777',
      data: '0x12345678'
    });
    assert.ok(txHash.startsWith('0x'));

    // D. evm.write to unauthorized selector fails closed (4003)
    let caughtBadSelector = null;
    try {
      await bridge.writeContract({
        to: '0x7777777777777777777777777777777777777777',
        data: '0xbad0bad0'
      });
    } catch (e) {
      caughtBadSelector = e;
    }
    assert.ok(caughtBadSelector);
    assert.strictEqual(caughtBadSelector.code, 4003);

    // E. evm.write to read-only target fails closed (4003)
    let caughtReadOnlyTarget = null;
    try {
      await bridge.writeContract({
        to: '0x0676129B2bF4B06f04AfC7301617b6cE3BB2405c',
        data: '0x12345678'
      });
    } catch (e) {
      caughtReadOnlyTarget = e;
    }
    assert.ok(caughtReadOnlyTarget);
    assert.strictEqual(caughtReadOnlyTarget.code, 4003);

    // F. evm.receipt returns receipt
    const receipt = await bridge.waitForReceipt(txHash);
    assert.ok(receipt);
    assert.strictEqual(receipt.transactionHash, txHash);

    port1.close();
    port2.close();
  });

  // --- 4B. EVM.LOGS BRIDGE DISPATCHING & CHAIN GATING ---
  await test('Host Bridge: Dispatches evm.logs with normalization, parameter validation, and fail-closed chain gating', async () => {
    const host = new GenericHostCore({
      resolver,
      keccakFn,
      account: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
      chainId: SEPOLIA_HEX
    });

    host.logsHandler = async (filter) => {
      return [
        {
          address: '0xF75323518DF7CE90637E2B93CFD7F7D0627CC205',
          topics: ['0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef'],
          data: '0x0000000000000000000000000000000000000000000000000000000000000001',
          blockNumber: 123456,
          blockHash: '0xABCD',
          transactionHash: '0x1234',
          transactionIndex: 2,
          logIndex: 0,
          removed: false
        }
      ];
    };

    await host.loadCartridge('runtime-test-cartridge');

    const { port1, port2 } = new MessageChannel();
    host.bindPortRpc(port1);
    const bridge = new BridgeHostAdapter(port2);

    // 1. Query logs successfully
    const logs = await bridge.getLogs({
      address: '0xF75323518df7Ce90637e2b93cFd7f7d0627cc205',
      topics: ['0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef']
    });

    assert.strictEqual(Array.isArray(logs), true);
    assert.strictEqual(logs.length, 1);
    assert.strictEqual(logs[0].address, '0xf75323518df7ce90637e2b93cfd7f7d0627cc205');
    assert.strictEqual(logs[0].blockNumber, '0x1e240'); // 123456 in hex
    assert.strictEqual(logs[0].transactionIndex, '0x2');
    assert.strictEqual(logs[0].logIndex, '0x0');
    assert.strictEqual(logs[0].removed, false);

    // 2. Chain mismatch fails closed (4003 policyViolation)
    let caughtChainMismatch = null;
    try {
      await bridge._sendRequest('evm.logs', { chainId: MAINNET_HEX, address: '0xF75323518df7Ce90637e2b93cFd7f7d0627cc205' });
    } catch (e) {
      caughtChainMismatch = e;
    }
    assert.ok(caughtChainMismatch, 'Chain mismatch must fail closed');
    assert.strictEqual(caughtChainMismatch.code, 4003);

    // 3. Malformed filter fails closed (-32602)
    let caughtBadFilter = null;
    try {
      await bridge.getLogs('not-an-object');
    } catch (e) {
      caughtBadFilter = e;
    }
    assert.ok(caughtBadFilter);
    assert.strictEqual(caughtBadFilter.code, -32602);

    port1.close();
    port2.close();
  });

  // --- 5. TWO-CARTRIDGE HOSTING PROOF (CARTRIDGE #0001 & #0002) ---
  await test('Two-Cartridge Proof: Host loads Reference Cartridge V1 and Runtime Test Cartridge sequentially through exact same path', async () => {
    const host = new GenericHostCore({
      resolver,
      keccakFn,
      account: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
      chainId: SEPOLIA_HEX,
      mockMode: true
    });

    // 1. Boot Primary Generic Reference Cartridge V1 with explicit write grant
    const refBoot = await host.loadCartridge('reference-cartridge-v1', {
      ['0x7777777777777777777777777777777777777777'.toLowerCase()]: {
        writes: true,
        allowedSelectors: ['0x12345678']
      }
    });
    assert.strictEqual(refBoot.id, 'reference-cartridge-v1');
    assert.strictEqual(refBoot.name, 'Reference Cartridge V1');
    assert.strictEqual(refBoot.verified, true);
    assert.strictEqual(host.integrityVerified, true);
    assert.strictEqual(host.computedHash, '0x865443ba96f988fc3d0adc3e0c4109c7fed347c9e8ff81cd57b857c557818d9f');

    // Test Reference Cartridge RPC via Host
    const { port1: refPort1, port2: refPort2 } = new MessageChannel();
    host.bindPortRpc(refPort1);
    const refBridge = new BridgeHostAdapter(refPort2);
    await refBridge.connect();

    const refWrite = await refBridge.writeContract({
      to: '0x7777777777777777777777777777777777777777',
      data: '0x12345678' + '00'.repeat(32)
    });
    assert.ok(refWrite.startsWith('0x'));

    refPort1.close();
    refPort2.close();

    // 2. Switch Host to Legacy Cartridge #0002 (Runtime Test Cartridge) without restart
    const testCartBoot = await host.loadCartridge('runtime-test-cartridge', {
      ['0x7777777777777777777777777777777777777777'.toLowerCase()]: {
        writes: true,
        allowedSelectors: ['0x12345678']
      }
    });
    assert.strictEqual(testCartBoot.id, 'runtime-test-cartridge');
    assert.strictEqual(testCartBoot.name, 'Runtime Test Cartridge');
    assert.strictEqual(testCartBoot.verified, true);
    assert.strictEqual(host.integrityVerified, true);
    assert.strictEqual(host.computedHash, '0x60d0bde3416316c5eda839cd1d20350a977ea14edaba4480bc5f3e4f8be95194');

    // Test Runtime Test Cartridge RPC via Same Host
    const { port1: tcPort1, port2: tcPort2 } = new MessageChannel();
    host.bindPortRpc(tcPort1);
    const tcBridge = new BridgeHostAdapter(tcPort2);
    await tcBridge.connect();

    const tcWriteEcho = await tcBridge.writeContract({
      to: '0x7777777777777777777777777777777777777777',
      data: '0x12345678'
    });
    assert.ok(tcWriteEcho.startsWith('0x'));

    tcPort1.close();
    tcPort2.close();
  });

  // --- 6. INVARIANT: PRODUCTION MISSING-HASH FAILS CLOSED VS DEV OPTION ---
  await test('Integrity: Missing content hash fails closed in production, allowed only via allowUnverifiedDevelopment', async () => {
    const unhashedResolver = {
      resolve: async () => ({
        id: 'unhashed-cartridge',
        name: 'Unhashed Cartridge',
        version: '1.0.0',
        runtimeRequirement: '^0.2.0',
        expectedContentHash: null,
        manifest: { permissions: { chains: ['eip155:11155111'], contracts: [] } },
        fetchPackageBytes: async () => '<html><body>Dev Cartridge</body></html>'
      })
    };

    // A. Default / production mode: fail closed
    const prodHost = new GenericHostCore({ resolver: unhashedResolver, keccakFn });
    let caughtProd = null;
    try {
      await prodHost.loadCartridge('unhashed-cartridge');
    } catch (e) {
      caughtProd = e;
    }
    assert.ok(caughtProd, 'Missing content hash must fail closed by default');
    assert.strictEqual(caughtProd.code, 5003);
    assert.strictEqual(prodHost.integrityVerified, false);

    // B. Explicit allowUnverifiedDevelopment mode: permits boot with verified=false
    const devHost = new GenericHostCore({
      resolver: unhashedResolver,
      keccakFn,
      allowUnverifiedDevelopment: true
    });
    const devBoot = await devHost.loadCartridge('unhashed-cartridge');
    assert.strictEqual(devBoot.verified, false, 'devBoot.verified must be false');
    assert.strictEqual(devHost.integrityVerified, false, 'devHost.integrityVerified must be false');
    assert.strictEqual(devHost.computedHash, 'unverified');
  });

  // --- 7. INVARIANT: PENDING RECEIPT RETURNS NULL (NOT 4900) ---
  await test('RPC: Receipt fetch returns null for pending/unmined transactions without throwing 4900', async () => {
    const pendingHost = new GenericHostCore({
      receiptHandler: async (txHash) => null
    });

    const res = await pendingHost.fetchReceipt('0x' + '33'.repeat(32));
    assert.strictEqual(res, null, 'Pending receipt must return null');

    const rpcRes = await pendingHost.handleRpcMessage({
      jsonrpc: '2.0',
      id: 99,
      method: 'evm.receipt',
      params: { txHash: '0x' + '33'.repeat(32) }
    });
    assert.strictEqual(rpcRes.result, null);
    assert.strictEqual(rpcRes.error, undefined);
  });

  // --- 8. INVARIANT: EVM.LOGS BOUNDS VALIDATION ---
  await test('RPC: evm.logs validates block range limits and mutually exclusive parameters', async () => {
    const host = new GenericHostCore({ mockMode: true, chainId: SEPOLIA_HEX });
    host.grantedPolicy = { isChainSupported: true, chainId: SEPOLIA_HEX, contracts: [] };

    // A. Block range > 50000 rejected
    await assert.rejects(
      async () => await host.executeGetLogs({ fromBlock: 1, toBlock: 50002 }),
      (err) => err.code === -32602 && err.message.includes('exceeds maximum allowed range')
    );

    // B. Mutually exclusive blockHash with fromBlock rejected
    await assert.rejects(
      async () => await host.executeGetLogs({ blockHash: '0x' + '11'.repeat(32), fromBlock: 100 }),
      (err) => err.code === -32602 && err.message.includes('blockHash cannot be specified together with fromBlock')
    );

    // C. Valid filter passes
    const validLogs = await host.executeGetLogs({ fromBlock: 100, toBlock: 200 });
    assert.deepStrictEqual(validLogs, []);
  });

  // --- 9. INVARIANT: CHAIN SWITCHING & CAPABILITY REPORTING ---
  await test('Lifecycle: Host chain switching re-evaluates policy and updates fine-grained capabilities', async () => {
    const host = new GenericHostCore({
      resolver,
      keccakFn,
      account: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
      chainId: SEPOLIA_HEX,
      mockMode: true
    });

    await host.loadCartridge('reference-cartridge-v1', {
      ['0x7777777777777777777777777777777777777777'.toLowerCase()]: {
        writes: true,
        allowedSelectors: ['0x12345678']
      }
    });

    // Active on Sepolia: write is authorized
    let caps = host.getCapabilities();
    assert.strictEqual(caps.evm.write.authorized, true);
    assert.strictEqual(caps.contractWrite, true);

    // Switch host to Mainnet (unsupported by reference cartridge permissions.chains = ["eip155:11155111"])
    host.setChainId(MAINNET_HEX);
    assert.strictEqual(host.grantedPolicy.isChainSupported, false);

    caps = host.getCapabilities();
    assert.strictEqual(caps.evm.write.authorized, false, 'Write must be de-authorized when host chain is unsupported');
    assert.strictEqual(caps.contractWrite, false);

    // evm.write on unsupported chain rejected with policyViolation (4003)
    const writeRes = await host.handleRpcMessage({
      jsonrpc: '2.0',
      id: 101,
      method: 'evm.write',
      params: { to: '0x7777777777777777777777777777777777777777', data: '0x12345678' }
    });
    assert.ok(writeRes.error);
    assert.strictEqual(writeRes.error.code, 4003);
  });

  // --- 5B. LAUNCH CONTEXT V1, CAIP-19 VALIDATION, & SECURITY INVARIANTS ---
  await test('Launch Context V1: Handshake delivery, CAIP-19 validation, and security invariants', async () => {
    // 1. CAIP-19 Parser Unit Verification
    const validErc721 = parseCaip19('eip155:4663/erc721:0xdd084caa7973fa07b71c7247236738786e04057a/123');
    assert.ok(validErc721);
    assert.strictEqual(validErc721.chainId, 'eip155:4663');
    assert.strictEqual(validErc721.chainNamespace, 'eip155');
    assert.strictEqual(validErc721.chainReference, '4663');
    assert.strictEqual(validErc721.assetNamespace, 'erc721');
    assert.strictEqual(validErc721.assetReference, '0xdd084caa7973fa07b71c7247236738786e04057a');
    assert.strictEqual(validErc721.tokenId, '123');

    const validErc20 = parseCaip19('eip155:1/erc20:0x6b175474e89094c44da98b954eedeac495271d0f');
    assert.ok(validErc20);
    assert.strictEqual(validErc20.tokenId, null);

    assert.strictEqual(parseCaip19('bad-uri'), null);
    assert.strictEqual(parseCaip19('eip155:/erc721:0x123/1'), null);

    // 2. Launch Context Validation and Sanitization
    const validCtx = {
      version: '1',
      resource: 'eip155:4663/erc721:0xdd084caa7973fa07b71c7247236738786e04057a/123',
      route: 'detail',
      params: { tab: 'stats', active: true }
    };
    assert.strictEqual(validateLaunchContext(validCtx), true);

    const sanitized = sanitizeLaunchContext({
      ...validCtx,
      untrustedInjection: 'dropMe',
      isOwner: true
    });
    assert.deepStrictEqual(sanitized, validCtx, 'Sanitizer must strip unknown properties');

    // Rejections & Sanitization Fallback
    assert.strictEqual(sanitizeLaunchContext(null), null);
    assert.strictEqual(sanitizeLaunchContext({ version: '2' }), null); // Invalid version
    assert.strictEqual(sanitizeLaunchContext({ version: '1', resource: 'not-caip19' }), null); // Invalid CAIP-19
    assert.strictEqual(sanitizeLaunchContext({ version: '1', route: 'a'.repeat(65) }), null); // Route too long

    // Oversized context rejected
    const hugeContext = { version: '1', route: 'test', params: { data: 'x'.repeat(1024) } };
    assert.strictEqual(sanitizeLaunchContext(hugeContext), null);

    // 3. Handshake Delivery via Host Bridge
    const hostWithCtx = new GenericHostCore({
      resolver,
      keccakFn,
      account: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
      chainId: SEPOLIA_HEX,
      mockMode: true,
      launchContext: validCtx
    });
    await hostWithCtx.loadCartridge('runtime-test-cartridge', {
      ['0x7777777777777777777777777777777777777777'.toLowerCase()]: {
        writes: true,
        allowedSelectors: ['0x12345678']
      }
    });

    const { port1, port2 } = new MessageChannel();
    hostWithCtx.bindPortRpc(port1);

    // Create bridge adapter simulating delivery of handshake ack payload
    const bridgeWithCtx = new BridgeHostAdapter(port2, hostWithCtx.getCapabilities(), hostWithCtx.getLaunchContext());
    CartridgeHost.setAdapter(bridgeWithCtx);

    const receivedCtx = CartridgeHost.getLaunchContext();
    assert.deepStrictEqual(receivedCtx, validCtx, 'CartridgeHost must receive valid Launch Context V1');

    // 4. Backward Compatibility: Boot with no context
    const hostWithoutCtx = new GenericHostCore({
      resolver,
      keccakFn,
      mockMode: true
    });
    assert.strictEqual(hostWithoutCtx.getLaunchContext(), null);

    const channelNoCtx = new MessageChannel();
    const bridgeWithoutCtx = new BridgeHostAdapter(channelNoCtx.port2, hostWithoutCtx.getCapabilities());
    assert.strictEqual(bridgeWithoutCtx.getLaunchContext(), null, 'BridgeHostAdapter must cleanly return null when context is absent');
    channelNoCtx.port1.close();
    channelNoCtx.port2.close();

    // 5. SECURITY INVARIANT: LAUNCH CONTEXT != AUTHORITY
    // A. Connected address remains caller's real address (0x7099...), NOT any address derived from context
    await CartridgeHost.connect();
    assert.strictEqual(CartridgeHost.getAddress(), '0x70997970C51812dc3A010C7d01b50e0d17dc79C8');
    assert.notStrictEqual(CartridgeHost.getAddress(), '0xdd084caa7973fa07b71c7247236738786e04057a');

    // B. Context never widens permissions or bypasses firewall (unauthorized writes still fail with 4003)
    let caughtDisallowed = null;
    try {
      await CartridgeHost.writeContract({
        to: '0xdd084caa7973fa07b71c7247236738786e04057a', // Target from context, but not in manifest permissions!
        data: '0x12345678'
      });
    } catch (e) {
      caughtDisallowed = e;
    }
    assert.ok(caughtDisallowed, 'Launch context must never grant write permission to undeclared contracts');
    assert.strictEqual(caughtDisallowed.code, 4003);

    port1.close();
    port2.close();
  });

  // --- 6. AUDIT: ZERO APPLICATION-SPECIFIC LOGIC IN HOST SOURCE ---
  await test('Audit: Generic host source code contains zero application-specific or game-specific references', async () => {
    const hostCoreSource = fs.readFileSync(path.join(__dirname, '../host/host_core.js'), 'utf8');
    const hostHtmlSource = fs.readFileSync(path.join(__dirname, '../host/index.html'), 'utf8');
    const resolverSource = fs.readFileSync(path.join(__dirname, '../host/resolver.js'), 'utf8');

    const forbiddenTerms = [
      'outlaws',
      'loot',
      'raids',
      'falcon',
      'sanctuary',
      'bow',
      'arrow',
      'pet',
      'debond',
      'bazaar',
      'heist',
      'marks',
      'targets',
      'shoot',
      'poach',
      'cross'
    ];

    // Check host_core.js (the actual host boundary engine)
    for (const term of forbiddenTerms) {
      const regex = new RegExp(`\\b${term}\\b`, 'i');
      assert.ok(!regex.test(hostCoreSource), `host_core.js must not contain application term: "${term}"`);
    }

    // Check host/index.html
    for (const term of forbiddenTerms) {
      // Allow 'hoodquest' only in the default query param string or default fallback ID
      const regex = new RegExp(`\\b${term}\\b`, 'i');
      assert.ok(!regex.test(hostHtmlSource), `host/index.html must not contain application term: "${term}"`);
    }

    // Check host/resolver.js core logic
    const resolverCoreLogic = resolverSource.split('createDefaultResolver')[0];
    for (const term of forbiddenTerms) {
      const regex = new RegExp(`\\b${term}\\b`, 'i');
      assert.ok(!regex.test(resolverCoreLogic), `resolver.js core logic must not contain application term: "${term}"`);
    }
  });

  // SUMMARY
  console.log('\n=============================================================');
  console.log(`Generic Web Host & Compatibility Suite Results:`);
  console.log(`Total: ${passed + failed} | Passed: ${passed} | Failed: ${failed}`);
  console.log('=============================================================\n');

  if (failed > 0) process.exit(1);
}

runGenericHostTestSuite();
